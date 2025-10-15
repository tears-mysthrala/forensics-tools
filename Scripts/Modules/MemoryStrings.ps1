function Get-MemoryStrings {
    <#
    .SYNOPSIS
        Extracts strings from memory dump for analysis.
    .DESCRIPTION
        Uses strings-like functionality to extract readable strings from memory dumps.
    .PARAMETER MemoryDump
        Path to the memory dump file.
    .PARAMETER MinLength
        Minimum string length to extract.
    .PARAMETER OutputPath
        Directory to save the strings file.
    .EXAMPLE
        Get-MemoryStrings -MemoryDump C:\Evidence\memory.dmp -MinLength 8
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$MemoryDump,
        [int]$MinLength = 4,
        [string]$OutputPath = "."
    )

    if (-not (Test-Path $MemoryDump)) {
        Write-Error "Memory dump file not found: $MemoryDump"
        return
    }

    Write-Host "Extracting strings from memory dump (min length: $MinLength)..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $stringsFile = Join-Path $OutputPath "memory_strings_$timestamp.txt"

    try {
        # Use PowerShell to extract strings (basic implementation)
        $bytes = [System.IO.File]::ReadAllBytes($MemoryDump)
        $strings = New-Object System.Collections.Generic.List[string]

        $currentString = ""
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $byte = $bytes[$i]
            if ($byte -ge 32 -and $byte -le 126) {
                # Printable ASCII character
                $currentString += [char]$byte
            }
            else {
                # Non-printable character
                if ($currentString.Length -ge $MinLength) {
                    $strings.Add($currentString)
                }
                $currentString = ""
            }
        }

        # Write strings to file
        $strings | Out-File $stringsFile

        Write-Host "Memory strings extracted: $stringsFile" -ForegroundColor Green
        Write-Host "Total strings found: $($strings.Count)" -ForegroundColor Cyan

        return $stringsFile

    }
    catch {
        Write-Error "Failed to extract memory strings: $($_.Exception.Message)"
    }

    return $null
}