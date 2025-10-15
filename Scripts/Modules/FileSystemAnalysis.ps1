# FileSystemAnalysis.ps1
# File system analysis functions

<#
.SYNOPSIS
    File System Analysis Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for performing comprehensive file system analysis.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Invoke-FileSystemAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive file system analysis.
    .DESCRIPTION
        Analyzes file hashes, alternate data streams, recent files, and large files.
    .EXAMPLE
        Invoke-FileSystemAnalysis
    #>
    Write-Host "=== FILE SYSTEM ANALYSIS ===" -ForegroundColor Cyan

    $analysis = @{
        Timestamp            = Get-Date
        RecentFiles          = $null
        LargeFiles           = $null
        AlternateDataStreams = $null
        FileHashes           = $null
        SuspiciousFiles      = $null
    }

    # Recent Files
    Write-Host "Analyzing recent files..." -ForegroundColor Yellow
    try {
        $analysis.RecentFiles = Get-RecentFiles -Days 7
        Write-Host "[OK] Recent files analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze recent files: $($_.Exception.Message)"
    }

    # Large Files
    Write-Host "Analyzing large files..." -ForegroundColor Yellow
    try {
        $analysis.LargeFiles = Get-LargeFiles -SizeMB 500
        Write-Host "[OK] Large files analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze large files: $($_.Exception.Message)"
    }

    # Alternate Data Streams
    Write-Host "Analyzing alternate data streams..." -ForegroundColor Yellow
    try {
        $analysis.AlternateDataStreams = Get-AlternateDataStreams -Path "C:\"
        Write-Host "[OK] Alternate data streams analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze ADS: $($_.Exception.Message)"
    }

    # File Hashes (sample of system files)
    Write-Host "Calculating file hashes..." -ForegroundColor Yellow
    try {
        $systemFiles = @(
            "$env:windir\System32\cmd.exe",
            "$env:windir\System32\powershell.exe",
            "$env:windir\System32\svchost.exe"
        )
        $hashResults = @()
        foreach ($file in $systemFiles) {
            if (Test-Path $file) {
                $hashResults += Get-FileHashes -Path $file
            }
        }
        $analysis.FileHashes = $hashResults
        Write-Host "[OK] File hashes calculated" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to calculate file hashes: $($_.Exception.Message)"
    }

    # Suspicious Files (basic check)
    Write-Host "Checking for suspicious files..." -ForegroundColor Yellow
    try {
        $suspiciousPaths = @(
            "$env:TEMP",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        )
        $suspiciousFiles = @()
        foreach ($path in $suspiciousPaths) {
            if (Test-Path $path) {
                $suspiciousFiles += Get-ChildItem $path -File -ErrorAction SilentlyContinue | Select-Object Name, FullName, Length, LastWriteTime
            }
        }
        $analysis.SuspiciousFiles = $suspiciousFiles
        Write-Host "[OK] Suspicious files checked" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to check suspicious files: $($_.Exception.Message)"
    }

    Write-Host "File system analysis complete!" -ForegroundColor Green
    return $analysis
}