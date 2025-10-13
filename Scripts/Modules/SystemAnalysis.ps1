# SystemAnalysis.ps1
# System analysis functions

<#
.SYNOPSIS
    System Analysis Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for performing comprehensive system analysis.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Invoke-SystemAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive system analysis.
    .DESCRIPTION
        Analyzes system configuration, user accounts, scheduled tasks, and system logs.
    .EXAMPLE
        Invoke-SystemAnalysis
    #>
    Write-Host "=== SYSTEM ANALYSIS ===" -ForegroundColor Cyan

    $analysis = @{
        Timestamp           = Get-Date
        SystemConfiguration = $null
        UserAccounts        = $null
        ScheduledTasks      = $null
        SystemLogs          = $null
        RegistryAnalysis    = $null
    }

    # System Configuration
    Write-Host "Analyzing system configuration..." -ForegroundColor Yellow
    try {
        $analysis.SystemConfiguration = Get-SystemInfo
        Write-Host "[OK] System configuration analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze system config: $($_.Exception.Message)"
    }

    # User Accounts
    Write-Host "Analyzing user accounts..." -ForegroundColor Yellow
    try {
        $analysis.UserAccounts = Get-UserAccounts
        Write-Host "[OK] User accounts analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze user accounts: $($_.Exception.Message)"
    }

    # Scheduled Tasks
    Write-Host "Analyzing scheduled tasks..." -ForegroundColor Yellow
    try {
        $analysis.ScheduledTasks = Get-ScheduledTasks
        Write-Host "[OK] Scheduled tasks analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze scheduled tasks: $($_.Exception.Message)"
    }

    # System Logs
    Write-Host "Analyzing system logs..." -ForegroundColor Yellow
    try {
        $analysis.SystemLogs = Get-SystemLogsSummary
        Write-Host "[OK] System logs analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze system logs: $($_.Exception.Message)"
    }

    # Registry Analysis
    Write-Host "Analyzing registry for persistence..." -ForegroundColor Yellow
    try {
        $runKeys = Get-RegistryKeys -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $runOnceKeys = Get-RegistryKeys -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        $analysis.RegistryAnalysis = @{
            RunKeys     = $runKeys
            RunOnceKeys = $runOnceKeys
        }
        Write-Host "[OK] Registry persistence analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze registry: $($_.Exception.Message)"
    }

    Write-Host "System analysis complete!" -ForegroundColor Green
    return $analysis
}