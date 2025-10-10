# FileAnomalyFunctions.ps1 - File system anomaly detection and analysis

function Get-FileAnomalyDetection {
    <#
    .SYNOPSIS
        Detects file system anomalies and suspicious file activity.
    .DESCRIPTION
        Identifies unusual file patterns, suspicious locations, and potential security issues.
    .PARAMETER Path
        Directory path to analyze.
    .PARAMETER OutputPath
        Directory to save anomaly analysis results.
    .EXAMPLE
        Get-FileAnomalyDetection -Path C:\ -OutputPath C:\Analysis
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$OutputPath = "."
    )

    Write-Host "Detecting file system anomalies..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "FileAnomalies_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $anomalies = @{
        Timestamp = Get-Date
        Path = $Path
        Anomalies = @{}
    }

    # Suspicious file locations
    Write-Host "Checking for suspicious file locations..." -ForegroundColor Yellow
    try {
        $suspiciousLocations = @(
            "$Path\Windows\System32\*.exe",
            "$Path\Windows\System32\*.dll",
            "$Path\Windows\SysWOW64\*.exe",
            "$Path\Windows\SysWOW64\*.dll"
        )

        $suspiciousFiles = @()
        foreach ($location in $suspiciousLocations) {
            if (Test-Path $location) {
                $files = Get-ChildItem -Path $location -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.CreationTime -gt (Get-Date).AddDays(-7) -or
                        $_.LastWriteTime -gt (Get-Date).AddDays(-7)
                    } |
                    Select-Object FullName, Name, Length, CreationTime, LastWriteTime

                $suspiciousFiles += $files
            }
        }

        if ($suspiciousFiles) {
            $suspiciousFiles | Export-Csv (Join-Path $analysisDir "suspicious_locations.csv") -NoTypeInformation
            $anomalies.Anomalies.SuspiciousLocations = $suspiciousFiles.Count
            Write-Host "⚠ Found $($suspiciousFiles.Count) recently modified system files" -ForegroundColor Red
        } else {
            $anomalies.Anomalies.SuspiciousLocations = 0
            Write-Host "[OK] No suspicious file locations found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check suspicious locations: $($_.Exception.Message)"
        $anomalies.Anomalies.SuspiciousLocations = "Error: $($_.Exception.Message)"
    }

    # Hidden files analysis
    Write-Host "Analyzing hidden files..." -ForegroundColor Yellow
    try {
        $hiddenFiles = Get-ChildItem -Path $Path -Hidden -Recurse -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            Select-Object FullName, Name, Length, LastWriteTime |
            Sort-Object LastWriteTime -Descending

        if ($hiddenFiles) {
            $hiddenFiles | Export-Csv (Join-Path $analysisDir "hidden_files.csv") -NoTypeInformation
            $anomalies.Anomalies.HiddenFiles = $hiddenFiles.Count
            Write-Host "[OK] Found $($hiddenFiles.Count) hidden files" -ForegroundColor Green
        } else {
            $anomalies.Anomalies.HiddenFiles = 0
            Write-Host "[OK] No hidden files found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to analyze hidden files: $($_.Exception.Message)"
        $anomalies.Anomalies.HiddenFiles = "Error: $($_.Exception.Message)"
    }

    # Large files in unusual locations
    Write-Host "Checking for large files in unusual locations..." -ForegroundColor Yellow
    try {
        $unusualLargeFiles = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Length -gt 100MB -and
                $_.FullName -notmatch "Windows|Program Files|Users\\.*\\Downloads|Users\\.*\\Desktop"
            } |
            Select-Object FullName, Name, Length, LastWriteTime |
            Sort-Object Length -Descending

        if ($unusualLargeFiles) {
            $unusualLargeFiles | Export-Csv (Join-Path $analysisDir "unusual_large_files.csv") -NoTypeInformation
            $anomalies.Anomalies.UnusualLargeFiles = $unusualLargeFiles.Count
            Write-Host "⚠ Found $($unusualLargeFiles.Count) large files in unusual locations" -ForegroundColor Yellow
        } else {
            $anomalies.Anomalies.UnusualLargeFiles = 0
            Write-Host "[OK] No unusual large files found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check unusual large files: $($_.Exception.Message)"
        $anomalies.Anomalies.UnusualLargeFiles = "Error: $($_.Exception.Message)"
    }

    # Recently created executables
    Write-Host "Checking for recently created executables..." -ForegroundColor Yellow
    try {
        $recentExecutables = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -match "\.(exe|dll|bat|cmd|ps1|vbs|js)" -and
                $_.CreationTime -gt (Get-Date).AddHours(-24)
            } |
            Select-Object FullName, Name, Length, CreationTime, LastWriteTime

        if ($recentExecutables) {
            $recentExecutables | Export-Csv (Join-Path $analysisDir "recent_executables.csv") -NoTypeInformation
            $anomalies.Anomalies.RecentExecutables = $recentExecutables.Count
            Write-Host "⚠ Found $($recentExecutables.Count) recently created executables" -ForegroundColor Red
        } else {
            $anomalies.Anomalies.RecentExecutables = 0
            Write-Host "[OK] No recently created executables found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check recent executables: $($_.Exception.Message)"
        $anomalies.Anomalies.RecentExecutables = "Error: $($_.Exception.Message)"
    }

    # Save anomalies summary
    $summaryFile = Join-Path $analysisDir "file_anomalies_summary.json"
    $anomalies | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "File anomaly detection complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}