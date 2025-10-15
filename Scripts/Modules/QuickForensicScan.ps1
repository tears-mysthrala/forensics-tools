# QuickForensicScan.ps1
# Quick forensic scan functions

<#
.SYNOPSIS
    Quick Forensic Scan Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for performing quick forensic scans of the system.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Invoke-QuickForensicScan {
    <#
    .SYNOPSIS
        Performs a quick forensic scan of the system.
    .DESCRIPTION
        Runs essential forensic checks without deep analysis or memory dumping.
    .EXAMPLE
        Invoke-QuickForensicScan
    #>
    Write-Host "=== QUICK FORENSIC SCAN ===" -ForegroundColor Cyan

    $scan = @{
        Timestamp           = Get-Date
        SystemStatus        = $null
        SuspiciousProcesses = $null
        NetworkConnections  = $null
        RecentFiles         = $null
        SecurityEvents      = $null
    }

    # System Status
    Write-Host "Checking system status..." -ForegroundColor Yellow
    try {
        $scan.SystemStatus = Invoke-LiveSystemStatus
        Write-Host "[OK] System status checked" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to check system status: $($_.Exception.Message)"
    }

    # Suspicious Processes
    Write-Host "Checking for suspicious processes..." -ForegroundColor Yellow
    try {
        $suspicious = Get-Process | Where-Object {
            $_.ProcessName -match "(?i)(cmd|powershell|net|wmic|reg|sc|tasklist|netstat|whoami|systeminfo)" -and
            $_.StartTime -gt (Get-Date).AddHours(-1)
        } | Select-Object Name, Id, StartTime, CPU, WorkingSet
        $scan.SuspiciousProcesses = $suspicious
        Write-Host "[OK] Suspicious processes checked" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to check suspicious processes: $($_.Exception.Message)"
    }

    # Network Connections
    Write-Host "Checking network connections..." -ForegroundColor Yellow
    try {
        $scan.NetworkConnections = Get-NetworkConnections | Where-Object {
            $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
        } | Select-Object -First 10
        Write-Host "[OK] Network connections checked" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to check network connections: $($_.Exception.Message)"
    }

    # Recent Files
    Write-Host "Checking recent files..." -ForegroundColor Yellow
    try {
        $scan.RecentFiles = Get-RecentFiles -Days 1
        Write-Host "[OK] Recent files checked" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to check recent files: $($_.Exception.Message)"
    }

    # Security Events
    Write-Host "Checking recent security events..." -ForegroundColor Yellow
    try {
        $scan.SecurityEvents = Search-EventLogs -LogName "Security" -Hours 1 | Select-Object -First 5
        Write-Host "[OK] Security events checked" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to check security events: $($_.Exception.Message)"
    }

    Write-Host "Quick forensic scan complete!" -ForegroundColor Green
    return $scan
}