# StaticAnalysis.ps1
# Static file analysis functions for malware detection

<#
.SYNOPSIS
    Static Analysis Functions

.DESCRIPTION
    This module provides static file analysis capabilities for malware detection:
    - Get-FileStaticAnalysis: Performs static analysis on files for malware indicators

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function Get-FileStaticAnalysis {
    <#
    .SYNOPSIS
        Performs static analysis on files for malware indicators.
    .DESCRIPTION
        Analyzes file properties, strings, imports, and other static characteristics for malware detection.
    .PARAMETER Path
        File or directory path to analyze.
    .PARAMETER OutputPath
        Directory to save analysis results.
    .PARAMETER DeepAnalysis
        Whether to perform deep string analysis (slower but more thorough).
    .EXAMPLE
        Get-FileStaticAnalysis -Path C:\Suspicious\malware.exe -OutputPath C:\Analysis
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$OutputPath = ".",
        [bool]$DeepAnalysis = $false
    )

    Write-Host "Performing static malware analysis..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "StaticAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $analysisResults = @{
        Timestamp = Get-Date
        Path      = $Path
        Results   = @()
    }

    # Get files to analyze
    $files = if (Test-Path $Path -PathType Leaf) {
        Get-Item $Path
    }
    else {
        Get-ChildItem -Path $Path -File -Recurse
    }

    Write-Host "Analyzing $($files.Count) files..." -ForegroundColor Yellow

    foreach ($file in $files) {
        try {
            $fileAnalysis = @{
                FileName             = $file.Name
                FullPath             = $file.FullName
                Size                 = $file.Length
                Extension            = $file.Extension
                CreationTime         = $file.CreationTime
                LastWriteTime        = $file.LastWriteTime
                Attributes           = $file.Attributes
                SuspiciousIndicators = @()
                RiskScore            = 0
            }

            # Basic file properties analysis
            if ($file.Extension -match "\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js)$") {
                $fileAnalysis.SuspiciousIndicators += "Executable file type"
                $fileAnalysis.RiskScore += 20
            }

            # Check file size (very small executables are suspicious)
            if ($file.Length -lt 1024 -and $file.Extension -match "\.(exe|dll)$") {
                $fileAnalysis.SuspiciousIndicators += "Unusually small executable"
                $fileAnalysis.RiskScore += 30
            }

            # Check for hidden files
            if ($file.Attributes -band [System.IO.FileAttributes]::Hidden) {
                $fileAnalysis.SuspiciousIndicators += "Hidden file"
                $fileAnalysis.RiskScore += 10
            }

            # Extract strings from file
            try {
                $strings = & strings.exe $file.FullName 2>$null
                if (-not $strings) {
                    # Fallback to PowerShell string extraction
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    $stringBuilder = New-Object System.Text.StringBuilder
                    $currentString = ""

                    for ($i = 0; $i -lt $bytes.Length; $i++) {
                        $byte = $bytes[$i]
                        if ($byte -ge 32 -and $byte -le 126) {
                            $currentString += [char]$byte
                        }
                        else {
                            if ($currentString.Length -ge 4) {
                                $stringBuilder.AppendLine($currentString) | Out-Null
                            }
                            $currentString = ""
                        }
                    }

                    $strings = $stringBuilder.ToString()
                }

                # Analyze strings for suspicious patterns
                $stringLines = $strings -split "`n"
                $suspiciousStrings = @()

                $malwarePatterns = @(
                    "CreateRemoteThread",
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "LoadLibrary",
                    "GetProcAddress",
                    "cmd\.exe",
                    "powershell",
                    "net user",
                    "reg add",
                    "schtasks",
                    "bitsadmin",
                    "certutil",
                    "rundll32",
                    "mshta",
                    "cscript",
                    "wscript",
                    "http://",
                    "https://",
                    "ftp://",
                    "irc://",
                    "bitcoin",
                    "wallet",
                    "ransomware",
                    "encrypt",
                    "decrypt"
                )

                foreach ($line in $stringLines) {
                    foreach ($pattern in $malwarePatterns) {
                        if ($line -match [regex]::Escape($pattern)) {
                            $suspiciousStrings += $line.Trim()
                            $fileAnalysis.RiskScore += 5
                            break
                        }
                    }
                }

                if ($suspiciousStrings) {
                    $fileAnalysis.SuspiciousIndicators += "Suspicious strings found: $($suspiciousStrings.Count) patterns"
                }

                # Save strings to file if deep analysis requested
                if ($DeepAnalysis) {
                    $stringsFile = Join-Path $analysisDir "$($file.BaseName)_strings.txt"
                    $strings | Out-File $stringsFile
                    $fileAnalysis.StringsFile = $stringsFile
                }

            }
            catch {
                $fileAnalysis.SuspiciousIndicators += "Could not extract strings: $($_.Exception.Message)"
            }

            # Calculate risk level
            if ($fileAnalysis.RiskScore -ge 80) {
                $fileAnalysis.RiskLevel = "High"
            }
            elseif ($fileAnalysis.RiskScore -ge 40) {
                $fileAnalysis.RiskLevel = "Medium"
            }
            else {
                $fileAnalysis.RiskLevel = "Low"
            }

            $analysisResults.Results += $fileAnalysis

            Write-Host "Analyzed $($file.Name) - Risk: $($fileAnalysis.RiskLevel) ($($fileAnalysis.RiskScore) points)" -ForegroundColor $(if ($fileAnalysis.RiskScore -ge 40) { "Red" } else { "Green" })

        }
        catch {
            Write-Warning "Failed to analyze $($file.FullName): $($_.Exception.Message)"
        }
    }

    # Export results
    $resultsFile = Join-Path $analysisDir "static_analysis_results.json"
    $analysisResults | ConvertTo-Json -Depth 4 | Out-File $resultsFile

    # Create summary CSV
    $csvData = $analysisResults.Results | ForEach-Object {
        [PSCustomObject]@{
            FileName             = $_.FileName
            FullPath             = $_.FullPath
            Size                 = $_.Size
            RiskLevel            = $_.RiskLevel
            RiskScore            = $_.RiskScore
            SuspiciousIndicators = ($_.SuspiciousIndicators -join "; ")
        }
    }
    $csvData | Export-Csv (Join-Path $analysisDir "static_analysis_summary.csv") -NoTypeInformation

    $highRisk = ($analysisResults.Results | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumRisk = ($analysisResults.Results | Where-Object { $_.RiskLevel -eq "Medium" }).Count

    Write-Host "Static analysis complete!" -ForegroundColor Green
    Write-Host "Files analyzed: $($analysisResults.Results.Count)" -ForegroundColor Cyan
    Write-Host "High risk files: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium risk files: $mediumRisk" -ForegroundColor $(if ($mediumRisk -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}