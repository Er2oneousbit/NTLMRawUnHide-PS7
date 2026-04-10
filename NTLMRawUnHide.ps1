#Requires -Version 7.0

<#
.SYNOPSIS
    Parse network packet capture files and extract NTLMv2 hashes in crackable format.

.DESCRIPTION
    NTLMRawUnHide.ps1 is a PowerShell 7 port of NTLMRawUnHide.py by Mike Gualtieri.
    Searches binary packet captures (.pcap, .pcapng, .cap, .etl) for NTLMSSP
    authentication exchanges and outputs NTLMv2 hashes ready for Hashcat or John.

    Capture methods:
      netsh.exe trace start persistent=yes capture=yes TCP.AnyPort=445 tracefile=C:\capture.etl
      netsh.exe trace stop

      pktmon.exe filter add SMB -p 445
      pktmon.exe start --etw -p 0 -c <AdapterID>
      pktmon.exe stop
      pktmon.exe filter remove

.PARAMETER InputFile
    Binary packet capture file (.pcap, .pcapng, .cap, .etl). Alias: -i

.PARAMETER OutputFile
    Optional file to append recovered hashes (one per line). Alias: -o

.PARAMETER Follow
    Continuously poll the input file for new data (like tail -f). Alias: -f

.PARAMETER VerboseOutput
    Show field-level detail: offsets, lengths, raw parsed values. Alias: -v

.PARAMETER Quiet
    Output found hashes only. Suppresses banner and all status messages.
    Overrides -VerboseOutput if both are specified. Alias: -q

.EXAMPLE
    .\NTLMRawUnHide.ps1 -i capture.etl
    .\NTLMRawUnHide.ps1 -i capture.pcap -o hashes.txt -v
    .\NTLMRawUnHide.ps1 -i capture.etl -f -q

.NOTES
    Original Python tool: https://github.com/mlgualtieri/NTLMRawUnhide
    Original Author: Mike Gualtieri (@mlgualtieri)
    PowerShell port assisted by Claude Sonnet 4.6

    Made with ❤️ from your friendly hacker - er2oneousbit
#>

[CmdletBinding()]
param(
    [Alias('i')]
    [string]$InputFile = '',

    [Alias('o')]
    [string]$OutputFile = '',

    [Alias('f')]
    [switch]$Follow,

    [Alias('v')]
    [switch]$VerboseOutput,

    [Alias('q')]
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'


# --------------------------------------------------
# Decode a byte array as UTF-8 and strip null bytes.
# Mirrors Python's decode_string(): UTF-8 decode + replace('\x00', '')
# This works for UTF-16LE ASCII text because the null bytes between
# ASCII chars are simply stripped, recovering the original string.
# --------------------------------------------------
function Decode-NTLMString {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    return [System.Text.Encoding]::UTF8.GetString($Bytes) -replace "`0", ''
}

# --------------------------------------------------
# Convert a byte array to a lowercase hex string.
# --------------------------------------------------
function ConvertTo-HexString {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    return ($Bytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

# --------------------------------------------------
# Decode a little-endian uint16 from 2 bytes.
# --------------------------------------------------
function Decode-Int16LE {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 2) { return 0 }
    return [System.BitConverter]::ToUInt16($Bytes, 0)
}

# --------------------------------------------------
# Decode a little-endian uint32 from 4 bytes.
# --------------------------------------------------
function Decode-Int32LE {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 4) { return 0 }
    return [System.BitConverter]::ToUInt32($Bytes, 0)
}

# --------------------------------------------------
# Return a slice of a byte array. Returns an empty array when
# Start is out of bounds or Length is zero/negative.
# --------------------------------------------------
function Get-Slice {
    param(
        [byte[]]$Data,
        [int]$Start,
        [int]$Length
    )
    if ($Length -le 0 -or $Start -lt 0 -or $Start -ge $Data.Length) {
        return [byte[]]@()
    }
    $end = [Math]::Min($Start + $Length - 1, $Data.Length - 1)
    return $Data[$Start..$end]
}

# --------------------------------------------------
# Search a byte array for a byte pattern.
# Mirrors Python's bytes.find(sub, start, end):
#   - StartOffset: where to begin searching
#   - EndOffset: upper bound of the search window (exclusive); -1 = search to end
#     The pattern must fit entirely within Data[StartOffset:EndOffset].
# Returns the index of the first match, or -1 if not found.
# --------------------------------------------------
function Find-BytePattern {
    param(
        [byte[]]$Data,
        [byte[]]$Pattern,
        [int]$StartOffset = 0,
        [int]$EndOffset = -1
    )

    $dataLen = $Data.Length
    $patLen  = $Pattern.Length
    if ($patLen -eq 0 -or $StartOffset -ge $dataLen) { return -1 }

    # Pattern must fit entirely in the array
    $globalMax = $dataLen - $patLen

    # If EndOffset given, pattern can start at most at (EndOffset - patLen)
    # This matches Python's semantics for bytes.find(sub, start, end)
    $maxStart = if ($EndOffset -ge 0) {
        [Math]::Min($globalMax, $EndOffset - $patLen)
    } else {
        $globalMax
    }

    for ($i = $StartOffset; $i -le $maxStart; $i++) {
        $match = $true
        for ($j = 0; $j -lt $patLen; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) { return $i }
    }
    return -1
}

# --------------------------------------------------
# Append a hash line to the output file.
# --------------------------------------------------
function Write-HashToFile {
    param([string]$Path, [string]$HashLine)
    Add-Content -LiteralPath $Path -Value $HashLine -Encoding UTF8
}

# --------------------------------------------------
# Core scan loop. Walks the binary buffer looking for all NTLMSSP
# message exchanges and assembles crackable NTLMv2 hashes.
#
# Returns: the length of the file when it was read.
# In Follow mode the caller passes this back as the next StartOffset
# so we only scan newly appended data on subsequent reads.
# --------------------------------------------------
function Search-CaptureFile {
    param(
        [string]$InFile,
        [string]$OutFile,
        [bool]$ShowVerbose,
        [bool]$IsQuiet,
        [int]$StartOffset = 0
    )

    # NTLMSSP message byte signatures
    [byte[]]$ntlmsspSig   = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00
    [byte[]]$ntlmsspType1 = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x01,0x00,0x00,0x00
    [byte[]]$ntlmsspType2 = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00
    [byte[]]$ntlmsspType3 = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x03,0x00,0x00,0x00

    [byte[]]$readbuff = [System.IO.File]::ReadAllBytes($InFile)
    [int]$lastByte    = $readbuff.Length
    [int]$offset      = $StartOffset
    $serverChallenge  = $null

    while ($offset -ne -1) {
        # Advance past the previous signature before searching for the next one
        if ($offset -ne 0) {
            $offset += $ntlmsspSig.Length
        }

        $offset = Find-BytePattern -Data $readbuff -Pattern $ntlmsspSig -StartOffset $offset
        if ($offset -eq -1) { break }

        # ---- Type 1: Negotiation ----
        $checkType = Find-BytePattern -Data $readbuff -Pattern $ntlmsspType1 `
            -StartOffset $offset -EndOffset ($offset + $ntlmsspType1.Length)

        if ($checkType -gt -1) {
            if (-not $IsQuiet) {
                if ($ShowVerbose) {
                    Write-Host "`e[1;37mFound NTLMSSP Message Type 1 :`e[1;32m Negotiation`e[0;37m    `e[1;30m>`e[0;37m Offset $offset`e[0;37m"
                } else {
                    Write-Host "`e[1;37mFound NTLMSSP Message Type 1 :`e[1;32m Negotiation`e[0;37m"
                }
                Write-Host ''
            }
        }

        # ---- Type 2: Challenge ----
        # Server challenge is at offset+24, 8 bytes (per CHALLENGE_MESSAGE spec)
        $checkType = Find-BytePattern -Data $readbuff -Pattern $ntlmsspType2 `
            -StartOffset $offset -EndOffset ($offset + $ntlmsspType2.Length)

        if ($checkType -gt -1) {
            $serverChallenge = Get-Slice -Data $readbuff -Start ($offset + 24) -Length 8

            if (-not $IsQuiet) {
                if ($ShowVerbose) {
                    Write-Host "`e[1;37mFound NTLMSSP Message Type 2 :`e[1;32m Challenge      `e[1;30m>`e[0;37m Offset $offset`e[0;37m"
                } else {
                    Write-Host "`e[1;37mFound NTLMSSP Message Type 2 :`e[1;32m Challenge`e[0;37m"
                }
                Write-Host "    `e[1;34m>`e[1;37m Server Challenge       :`e[0;97m $(ConvertTo-HexString $serverChallenge)`e[0;37m"
                Write-Host ''
            }
        }

        # ---- Type 3: Authentication ----
        # AUTHENTICATE_MESSAGE field layout (all offsets relative to NTLMSSP signature):
        #   +12  LmResponse security buffer    (len:2, alloc:2, offset:4)
        #   +20  NtResponse security buffer    (len:2, alloc:2, offset:4)
        #   +28  DomainName security buffer    (len:2, alloc:2, offset:4)
        #   +36  UserName security buffer      (len:2, alloc:2, offset:4)
        #   +44  Workstation security buffer   (len:2, alloc:2, offset:4)
        # Data offsets in the security buffers are relative to the NTLMSSP signature.
        $checkType = Find-BytePattern -Data $readbuff -Pattern $ntlmsspType3 `
            -StartOffset $offset -EndOffset ($offset + $ntlmsspType3.Length)

        if ($checkType -gt -1) {
            if (-not $IsQuiet) {
                if ($ShowVerbose) {
                    Write-Host "`e[1;37mFound NTLMSSP Message Type 3 :`e[1;32m Authentication `e[1;30m>`e[0;37m Offset $offset`e[0;37m"
                } else {
                    Write-Host "`e[1;37mFound NTLMSSP Message Type 3 :`e[1;32m Authentication`e[0;37m"
                }
            }

            # Domain
            [int]$domainLen = Decode-Int16LE -Bytes (Get-Slice -Data $readbuff -Start ($offset + 28) -Length 2)
            [int]$domainOff = Decode-Int32LE -Bytes (Get-Slice -Data $readbuff -Start ($offset + 32) -Length 4)
            [byte[]]$domain = Get-Slice -Data $readbuff -Start ($offset + $domainOff) -Length $domainLen

            if (-not $IsQuiet) {
                Write-Host "    `e[1;34m>`e[1;37m Domain                 :`e[0;97m $(Decode-NTLMString $domain)`e[0;37m"
                if ($ShowVerbose) {
                    Write-Host "      Domain length          : $domainLen"
                    Write-Host "      Domain offset          : $domainOff"
                    Write-Host ''
                }
            }

            # Username
            [int]$usernameLen = Decode-Int16LE -Bytes (Get-Slice -Data $readbuff -Start ($offset + 36) -Length 2)
            [int]$usernameOff = Decode-Int32LE -Bytes (Get-Slice -Data $readbuff -Start ($offset + 40) -Length 4)
            [byte[]]$username = Get-Slice -Data $readbuff -Start ($offset + $usernameOff) -Length $usernameLen

            if (-not $IsQuiet) {
                Write-Host "    `e[1;34m>`e[1;37m Username               :`e[0;97m $(Decode-NTLMString $username)`e[0;37m"
                if ($ShowVerbose) {
                    Write-Host "      Username length        : $usernameLen"
                    Write-Host "      Username offset        : $usernameOff"
                    Write-Host ''
                }
            }

            # Workstation
            [int]$workstationLen = Decode-Int16LE -Bytes (Get-Slice -Data $readbuff -Start ($offset + 44) -Length 2)
            [int]$workstationOff = Decode-Int32LE -Bytes (Get-Slice -Data $readbuff -Start ($offset + 48) -Length 4)
            [byte[]]$workstation = Get-Slice -Data $readbuff -Start ($offset + $workstationOff) -Length $workstationLen

            if (-not $IsQuiet) {
                Write-Host "    `e[1;34m>`e[1;37m Workstation            :`e[0;97m $(Decode-NTLMString $workstation)`e[0;37m"
                if ($ShowVerbose) {
                    Write-Host "      Workstation length     : $workstationLen"
                    Write-Host "      Workstation offset     : $workstationOff"
                    Write-Host ''
                }
            }

            # NtChallengeResponse - first 16 bytes are NTProofStr, the rest is the blob
            [int]$ntlmLen = Decode-Int16LE -Bytes (Get-Slice -Data $readbuff -Start ($offset + 20) -Length 2)
            [int]$ntlmOff = Decode-Int32LE -Bytes (Get-Slice -Data $readbuff -Start ($offset + 24) -Length 4)
            [byte[]]$ntproofstr     = Get-Slice -Data $readbuff -Start ($offset + $ntlmOff)      -Length 16
            [byte[]]$ntlmv2Response = Get-Slice -Data $readbuff -Start ($offset + $ntlmOff + 16) -Length ($ntlmLen - 16)

            if (-not $IsQuiet -and $ShowVerbose) {
                Write-Host "      NTLM length            : $ntlmLen"
                Write-Host "      NTLM offset            : $ntlmOff"
                Write-Host "    `e[1;34m>`e[1;37m NTProofStr             :`e[0;37m $(ConvertTo-HexString $ntproofstr)"
                Write-Host "    `e[1;34m>`e[1;37m NTLMv2 Response        :`e[0;37m $(ConvertTo-HexString $ntlmv2Response)"
            }

            if (-not $IsQuiet) { Write-Host '' }

            # Assemble the crackable hash if we captured a server challenge
            if ($null -ne $serverChallenge) {
                if (-not $IsQuiet) {
                    Write-Host "`e[1;37mNTLMv2 Hash recovered:`e[0;97m"
                }

                if ($ntlmLen -eq 0) {
                    if (-not $IsQuiet) {
                        Write-Host "`e[0;37mNTLM NULL session found... no hash to generate`e[0;37m"
                    }
                } elseif ($domainLen -eq 0) {
                    # No domain: use workstation instead (matches original behavior)
                    $hashOut = "$(Decode-NTLMString $username)::$(Decode-NTLMString $workstation):$(ConvertTo-HexString $serverChallenge):$(ConvertTo-HexString $ntproofstr):$(ConvertTo-HexString $ntlmv2Response)"
                    Write-Host $hashOut
                    if ($OutFile -ne '') { Write-HashToFile -Path $OutFile -HashLine $hashOut }
                } else {
                    $hashOut = "$(Decode-NTLMString $username)::$(Decode-NTLMString $domain):$(ConvertTo-HexString $serverChallenge):$(ConvertTo-HexString $ntproofstr):$(ConvertTo-HexString $ntlmv2Response)"
                    Write-Host $hashOut
                    if ($OutFile -ne '') { Write-HashToFile -Path $OutFile -HashLine $hashOut }
                }

                Write-Host ''
                $serverChallenge = $null
            } else {
                if (-not $IsQuiet) {
                    Write-Host "`e[1;31mServer Challenge not found... can't create crackable hash :-/`e[0;37m"
                    Write-Host ''
                }
            }
        }
    }

    return $lastByte
}

# --------------------------------------------------
# ASCII banner (yellow)
# --------------------------------------------------
function Show-Banner {
    Write-Host @"
`e[0;93m                                                              /%(
                               -= Find NTLMv2 =-          ,@@@@@@@@&
           /%&@@@@&,            -= hashes w/ =-          %@@@@@@@@@@@*
         (@@@@@@@@@@@(       -= NTLMRawUnHide.ps1 =-   *@@@@@@@@@@@@@@@.
        &@@@@@@@@@@@@@@&.                             @@@@@@@@@@@@@@@@@@(
      ,@@@@@@@@@@@@@@@@@@@/                        .%@@@@@@@@@@@@@@@@@@@@@
     /@@@@@@@#&@&*.,/@@@@(.                            ,%@@@@&##(%@@@@@@@@@.
    (@@@@@@@(##(.         .#&@%%(                .&&@@&(            ,/@@@@@@#
   %@@@@@@&*/((.         #(                           ,(@&            ,%@@@@@@*
  @@@@@@@&,/(*                                           ,             .,&@@@@@#
 @@@@@@@/*//,                                                            .,,,**
   .,,  ...
                                    .#@@@@@@@(.
                                   /@@@@@@@@@@@&
                                   .@@@@@@@@@@@*
                                     .(&@@@%/.  ..
                               (@@&     %@@.   .@@@,
                          /@@#          @@@,         %@&
                               &@@&.    @@@/    @@@#
                          .    %@@@(   ,@@@#    @@@(     ,
                         *@@/         .@@@@@(          #@%
                          *@@%.      &@@@@@@@@,      /@@@.
                           .@@@@@@@@@@@&. .*@@@@@@@@@@@/.
                              .%@@@@%,        /%@@@&(.

`e[0;97m
"@
}

# --------------------------------------------------
# Brief usage hint
# --------------------------------------------------
function Show-Usage {
    Write-Host "`e[1;37m"
    Write-Host 'usage: NTLMRawUnHide.ps1 -i <inputfile> [-o <outputfile>] [-f] [-q] [-v]'
    Write-Host "`e[0;97m"
}


# ==========================================
# Main execution
# ==========================================

$showVerbose = $VerboseOutput.IsPresent -and (-not $Quiet.IsPresent)
$isQuiet     = $Quiet.IsPresent

# Show banner + usage when run with no arguments
if ($PSBoundParameters.Count -eq 0) {
    Show-Banner
    Show-Usage
    exit 0
}

if (-not $isQuiet) { Show-Banner }

if ($InputFile -eq '') {
    Write-Host "`e[1;31m[!]`e[0;97m Error: Input file not specified. Use -InputFile / -i"
    Show-Usage
    exit 1
}

if (-not (Test-Path -LiteralPath $InputFile)) {
    Write-Host "`e[1;31m[!]`e[0;97m Error: Input file not found: $InputFile"
    exit 1
}

if (-not $isQuiet) {
    Write-Host "`e[1;37mSearching $InputFile for NTLMv2 hashes..."
    if ($OutputFile -ne '') {
        Write-Host "Writing output to: $OutputFile"
    }
    Write-Host "`e[0;97m"
}

$scanOffset = 0

do {
    try {
        $scanOffset = Search-CaptureFile `
            -InFile      $InputFile `
            -OutFile     $OutputFile `
            -ShowVerbose $showVerbose `
            -IsQuiet     $isQuiet `
            -StartOffset $scanOffset
    } catch {
        Write-Host "`e[1;31m[!]`e[0;97m Error reading file: $_"
        exit 1
    }

    if ($Follow) {
        Start-Sleep -Seconds 1
    }
} while ($Follow)
