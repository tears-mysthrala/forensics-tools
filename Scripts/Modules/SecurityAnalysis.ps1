# SecurityAnalysis.ps1
# Security analysis functions

<#
.SYNOPSIS
    Security Analysis Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for performing comprehensive security analysis.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Invoke-SecurityAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive security analysis.
    .DESCRIPTION
        Analyzes security events, user privileges, installed software, and potential security issues.
    .EXAMPLE
        Invoke-SecurityAnalysis
    #>
    Write-Host "=== SECURITY ANALYSIS ===" -ForegroundColor Cyan

    $analysis = @{
        Timestamp         = Get-Date
        SecurityEvents    = $null
        UserPrivileges    = $null
        InstalledSoftware = $null
        AntivirusStatus   = $null
        OpenPorts         = $null
    }

    # Security Events
    Write-Host "Analyzing security events..." -ForegroundColor Yellow
    try {
        $analysis.SecurityEvents = Search-EventLogs -LogName "Security" -EventId 4625, 4624, 4634, 4648 -Hours 24
        Write-Host "[OK] Security events analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze security events: $($_.Exception.Message)"
    }

    # User Privileges
    Write-Host "Analyzing user privileges..." -ForegroundColor Yellow
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

        $analysis.UserPrivileges = @{
            CurrentUser = $currentUser.Name
            IsAdmin     = $principal.IsInRole($adminRole)
            Groups      = $currentUser.Groups | ForEach-Object { $_.Translate([Security.Principal.NTAccount]).Value }
        }
        Write-Host "[OK] User privileges analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze user privileges: $($_.Exception.Message)"
    }

    # Installed Software
    Write-Host "Analyzing installed software..." -ForegroundColor Yellow
    try {
        $analysis.InstalledSoftware = Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor | Sort-Object Name
        Write-Host "[OK] Installed software analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze installed software: $($_.Exception.Message)"
    }

    # Antivirus Status
    Write-Host "Checking antivirus status..." -ForegroundColor Yellow
    try {
        $antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
        if ($antivirus) {
            $analysis.AntivirusStatus = $antivirus | Select-Object displayName, productState, timestamp
        }
        else {
            $analysis.AntivirusStatus = "Security Center not available or no antivirus detected"
        }
        Write-Host "[OK] Antivirus status checked" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to check antivirus status: $($_.Exception.Message)"
    }

    # Open Ports
    Write-Host "Analyzing open ports..." -ForegroundColor Yellow
    try {
        $analysis.OpenPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object LocalAddress, LocalPort, OwningProcess
        Write-Host "[OK] Open ports analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze open ports: $($_.Exception.Message)"
    }

    Write-Host "Security analysis complete!" -ForegroundColor Green
    return $analysis
}