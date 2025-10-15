# YaraAnalysis.ps1
# YARA-based malware analysis functions

<#
.SYNOPSIS
    YARA Analysis Functions

.DESCRIPTION
    This module provides YARA-based malware detection and analysis capabilities:
    - Get-YaraRules: Downloads and manages YARA rule sets
    - Invoke-YaraScan: Scans files using YARA rules for malware detection

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function Get-YaraRules {
    <#
    .SYNOPSIS
        Downloads and manages YARA rules for malware detection.
    .DESCRIPTION
        Downloads YARA rules from public repositories and manages rule sets for malware scanning.
    .PARAMETER OutputPath
        Directory to save YARA rules.
    .PARAMETER RuleSet
        Which rule set to download (default: all available).
    .EXAMPLE
        Get-YaraRules -OutputPath C:\YaraRules
    #>
    param(
        [string]$OutputPath = ".",
        [string[]]$RuleSet = @("malware", "crypto", "packers", "capabilities")
    )

    Write-Host "Downloading YARA rules..." -ForegroundColor Cyan

    $rulesDir = Join-Path $OutputPath "YaraRules"
    if (-not (Test-Path $rulesDir)) {
        New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
    }

    $rulesInfo = @{
        Timestamp = Get-Date
        RuleSets  = @{}
    }

    # YARA rule repositories
    $ruleSources = @{
        "malware"      = @{
            Url         = "https://github.com/Yara-Rules/rules/archive/master.zip"
            Description = "Comprehensive malware detection rules"
        }
        "crypto"       = @{
            Url         = "https://github.com/Neo23x0/signature-base/archive/master.zip"
            Description = "Cryptocurrency malware and financial malware rules"
        }
        "packers"      = @{
            Url         = "https://github.com/gdataadvancedanalytics/yar Gen/archive/master.zip"
            Description = "Packer and obfuscation detection rules"
        }
        "capabilities" = @{
            Url         = "https://github.com/100DaysofYARA/2023/archive/main.zip"
            Description = "Advanced malware capability detection"
        }
    }

    foreach ($set in $RuleSet) {
        if ($ruleSources.ContainsKey($set)) {
            $source = $ruleSources[$set]
            Write-Host "Downloading $set rules..." -ForegroundColor Yellow

            try {
                $zipFile = Join-Path $rulesDir "$set-rules.zip"
                $extractPath = Join-Path $rulesDir $set

                # Download the rules
                Invoke-WebRequest -Uri $source.Url -OutFile $zipFile -ErrorAction Stop

                # Extract the rules
                if (Test-Path $extractPath) {
                    Remove-Item $extractPath -Recurse -Force
                }
                Expand-Archive -Path $zipFile -DestinationPath $extractPath -ErrorAction Stop

                # Find .yar files
                $yarFiles = Get-ChildItem -Path $extractPath -Filter "*.yar" -Recurse
                $rulesInfo.RuleSets[$set] = @{
                    Description = $source.Description
                    Files       = $yarFiles.Count
                    Path        = $extractPath
                    Status      = "Downloaded"
                }

                Write-Host "[OK] Downloaded $($yarFiles.Count) $set rules" -ForegroundColor Green

            }
            catch {
                Write-Warning "Failed to download $set rules: $($_.Exception.Message)"
                $rulesInfo.RuleSets[$set] = @{
                    Description = $source.Description
                    Status      = "Failed: $($_.Exception.Message)"
                }
            }
        }
    }

    # Create compiled rules index
    $indexFile = Join-Path $rulesDir "rules_index.txt"
    $indexContent = @()
    foreach ($set in $rulesInfo.RuleSets.Keys) {
        if ($rulesInfo.RuleSets[$set].Status -eq "Downloaded") {
            $setPath = $rulesInfo.RuleSets[$set].Path
            $yarFiles = Get-ChildItem -Path $setPath -Filter "*.yar" -Recurse
            foreach ($file in $yarFiles) {
                $indexContent += "$set|$($file.FullName)"
            }
        }
    }
    $indexContent | Out-File $indexFile

    # Save rules info
    $infoFile = Join-Path $rulesDir "rules_info.json"
    $rulesInfo | ConvertTo-Json -Depth 3 | Out-File $infoFile

    Write-Host "YARA rules download complete!" -ForegroundColor Green
    Write-Host "Rules saved to: $rulesDir" -ForegroundColor Cyan
    Write-Host "Rules index: $indexFile" -ForegroundColor Cyan

    return $rulesDir
}

function Invoke-YaraScan {
    <#
    .SYNOPSIS
        Scans files using YARA rules for malware detection.
    .DESCRIPTION
        Uses YARA to scan files or directories for malware signatures and suspicious patterns.
    .PARAMETER Path
        File or directory path to scan.
    .PARAMETER RulesPath
        Path to YARA rules directory.
    .PARAMETER OutputPath
        Directory to save scan results.
    .PARAMETER Recurse
        Whether to scan subdirectories recursively.
    .EXAMPLE
        Invoke-YaraScan -Path C:\Suspicious -RulesPath C:\YaraRules -OutputPath C:\ScanResults
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$RulesPath,
        [string]$OutputPath = ".",
        [bool]$Recurse = $true
    )

    Write-Host "Starting YARA malware scan..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $scanDir = Join-Path $OutputPath "YaraScan_$timestamp"

    if (-not (Test-Path $scanDir)) {
        New-Item -ItemType Directory -Path $scanDir -Force | Out-Null
    }

    $scanResults = @{
        Timestamp = Get-Date
        Path      = $Path
        RulesPath = $RulesPath
        Results   = @{}
        Summary   = @{}
    }

    # Check if YARA is available
    $yaraPath = Get-Command yara -ErrorAction SilentlyContinue
    if (-not $yaraPath) {
        Write-Warning "YARA not found in PATH. Please install YARA from https://github.com/VirusTotal/yara"
        Write-Host "Attempting to use Python yara module..." -ForegroundColor Yellow

        # Try Python yara module
        try {
            $pythonYara = python -c "import yara; print('YARA Python module available')" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Using Python YARA module" -ForegroundColor Green
                $usePython = $true
            }
            else {
                throw "Python YARA module not available"
            }
        }
        catch {
            Write-Error "Neither YARA executable nor Python YARA module found. Please install YARA."
            return $null
        }
    }

    # Get all YARA rule files
    $ruleFiles = Get-ChildItem -Path $RulesPath -Filter "*.yar" -Recurse
    if (-not $ruleFiles) {
        Write-Warning "No YARA rule files found in $RulesPath"
        return $null
    }

    Write-Host "Found $($ruleFiles.Count) YARA rule files" -ForegroundColor Cyan

    # Get files to scan
    $scanFiles = if (Test-Path $Path -PathType Leaf) {
        Get-Item $Path
    }
    else {
        Get-ChildItem -Path $Path -File -Recurse:$Recurse
    }

    Write-Host "Scanning $($scanFiles.Count) files..." -ForegroundColor Yellow

    $totalMatches = 0
    $scannedFiles = 0

    foreach ($file in $scanFiles) {
        try {
            $fileResults = @{
                FileName = $file.Name
                FullPath = $file.FullName
                Size     = $file.Length
                Matches  = @()
            }

            if ($usePython) {
                # Use Python YARA module
                $pythonScript = @"
import yara
import sys
import os

rules = {}
for rule_file in sys.argv[2:]:
    try:
        rules.update(yara.compile(filepath=rule_file))
    except:
        pass

if rules:
    matches = rules.match(sys.argv[1])
    for match in matches:
        print(f"{match.rule}|{match.namespace}|{','.join(match.strings)}")
"@

                $tempScript = Join-Path $env:TEMP "yara_scan.py"
                $pythonScript | Out-File $tempScript -Encoding UTF8

                $ruleFileList = $ruleFiles | ForEach-Object { $_.FullName }
                $output = python $tempScript $file.FullName @ruleFileList 2>$null

                if ($output) {
                    foreach ($line in $output) {
                        $parts = $line -split '\|'
                        if ($parts.Count -ge 2) {
                            $fileResults.Matches += @{
                                Rule      = $parts[0]
                                Namespace = $parts[1]
                                Strings   = if ($parts.Count -gt 2) { $parts[2] } else { "" }
                            }
                        }
                    }
                }

                Remove-Item $tempScript -ErrorAction SilentlyContinue

            }
            else {
                # Use YARA executable
                $ruleFileList = $ruleFiles | ForEach-Object { "`"$($_.FullName)`"" }
                $ruleString = $ruleFileList -join " "

                $output = & yara -s $ruleString "`"$($file.FullName)`"" 2>$null

                if ($output) {
                    foreach ($line in $output) {
                        if ($line -match "^(\w+)\s+(.+)$") {
                            $fileResults.Matches += @{
                                Rule  = $matches[1]
                                Match = $matches[2]
                            }
                        }
                    }
                }
            }

            if ($fileResults.Matches.Count -gt 0) {
                $totalMatches += $fileResults.Matches.Count
                $scanResults.Results[$file.FullName] = $fileResults
                Write-Host "⚠ Malware signatures found in $($file.Name)" -ForegroundColor Red
            }

            $scannedFiles++

        }
        catch {
            Write-Warning "Failed to scan $($file.FullName): $($_.Exception.Message)"
        }
    }

    # Export results
    $resultsFile = Join-Path $scanDir "yara_scan_results.json"
    $scanResults | ConvertTo-Json -Depth 4 | Out-File $resultsFile

    # Create summary CSV
    $summaryData = @()
    foreach ($result in $scanResults.Results.Values) {
        foreach ($match in $result.Matches) {
            $summaryData += [PSCustomObject]@{
                FileName  = $result.FileName
                FullPath  = $result.FullPath
                Size      = $result.Size
                Rule      = $match.Rule
                Namespace = $match.Namespace
                Strings   = $match.Strings
            }
        }
    }

    if ($summaryData) {
        $summaryData | Export-Csv (Join-Path $scanDir "malware_detections.csv") -NoTypeInformation
    }

    $scanResults.Summary = @{
        TotalFilesScanned = $scannedFiles
        TotalMatches      = $totalMatches
        SuspiciousFiles   = $scanResults.Results.Count
    }

    Write-Host "YARA scan complete!" -ForegroundColor Green
    Write-Host "Files scanned: $scannedFiles" -ForegroundColor Cyan
    Write-Host "Malware matches: $totalMatches" -ForegroundColor $(if ($totalMatches -gt 0) { "Red" } else { "Green" })
    Write-Host "Results saved to: $scanDir" -ForegroundColor Cyan

    return $scanDir
}