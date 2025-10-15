# LiveSystemStatus.ps1
# Live system status check functions

<#
.SYNOPSIS
    Live System Status Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for performing quick live system status checks.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Invoke-LiveSystemStatus {
    <#
    .SYNOPSIS
        Performs a quick live system status check.
    .DESCRIPTION
        Gathers basic system information, running processes, and network status.
    .EXAMPLE
        Invoke-LiveSystemStatus
    #>
    Write-Host "=== LIVE SYSTEM STATUS ===" -ForegroundColor Cyan

    $status = @{
        Timestamp  = Get-Date
        Hostname   = $env:COMPUTERNAME
        Username   = $env:USERNAME
        SystemInfo = $null
        Processes  = $null
        Network    = $null
        Services   = $null
    }

    # System Information
    Write-Host "Gathering system information..." -ForegroundColor Yellow
    try {
        $status.SystemInfo = Get-SystemInfo
        Write-Host "[OK] System information collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to get system info: $($_.Exception.Message)"
    }

    # Process Information
    Write-Host "Checking running processes..." -ForegroundColor Yellow
    try {
        $status.Processes = Get-ProcessDetails | Where-Object { $_.ProcessName -notlike "*svchost*" } | Select-Object -First 20
        Write-Host "[OK] Process information collected (showing top 20 non-svchost)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to get process info: $($_.Exception.Message)"
    }

    # Network Status
    Write-Host "Checking network connections..." -ForegroundColor Yellow
    try {
        $status.Network = Get-NetworkConnections | Where-Object { $_.State -eq "Established" } | Select-Object -First 10
        Write-Host "[OK] Network connections collected (showing top 10 established)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to get network info: $($_.Exception.Message)"
    }

    # Service Status
    Write-Host "Checking critical services..." -ForegroundColor Yellow
    try {
        $status.Services = Get-ServicesStatus | Where-Object { $_.Status -ne "Running" }
        Write-Host "[OK] Service status collected (showing non-running services)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to get service info: $($_.Exception.Message)"
    }

    Write-Host "Live system status check complete!" -ForegroundColor Green
    return $status
}