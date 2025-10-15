# NetworkAnalysis.ps1
# Network analysis functions

<#
.SYNOPSIS
    Network Analysis Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for performing comprehensive network analysis.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Invoke-NetworkAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive network analysis.
    .DESCRIPTION
        Analyzes network connections, shares, firewall rules, and network configuration.
    .EXAMPLE
        Invoke-NetworkAnalysis
    #>
    Write-Host "=== NETWORK ANALYSIS ===" -ForegroundColor Cyan

    $analysis = @{
        Timestamp          = Get-Date
        NetworkConnections = $null
        NetworkShares      = $null
        FirewallRules      = $null
        USBHistory         = $null
        NetworkConfig      = $null
    }

    # Network Connections
    Write-Host "Analyzing network connections..." -ForegroundColor Yellow
    try {
        $analysis.NetworkConnections = Get-NetworkConnections
        Write-Host "[OK] Network connections analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze network connections: $($_.Exception.Message)"
    }

    # Network Shares
    Write-Host "Analyzing network shares..." -ForegroundColor Yellow
    try {
        $analysis.NetworkShares = Get-NetworkShares
        Write-Host "[OK] Network shares analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze network shares: $($_.Exception.Message)"
    }

    # Firewall Rules
    Write-Host "Analyzing firewall rules..." -ForegroundColor Yellow
    try {
        $analysis.FirewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true } | Select-Object DisplayName, Direction, Action, Profile
        Write-Host "[OK] Firewall rules analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze firewall rules: $($_.Exception.Message)"
    }

    # USB Device History
    Write-Host "Analyzing USB device history..." -ForegroundColor Yellow
    try {
        $analysis.USBHistory = Get-USBDeviceHistory
        Write-Host "[OK] USB device history analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze USB history: $($_.Exception.Message)"
    }

    # Network Configuration
    Write-Host "Analyzing network configuration..." -ForegroundColor Yellow
    try {
        $analysis.NetworkConfig = Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed
        Write-Host "[OK] Network configuration analyzed" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to analyze network config: $($_.Exception.Message)"
    }

    Write-Host "Network analysis complete!" -ForegroundColor Green
    return $analysis
}