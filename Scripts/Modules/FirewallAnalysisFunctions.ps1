# FirewallAnalysisFunctions.ps1 - Firewall log analysis

function Get-FirewallLogAnalysis {
    <#
    .SYNOPSIS
        Analyzes Windows Firewall logs for forensic insights.
    .DESCRIPTION
        Examines firewall logs for blocked connections, suspicious activity, and network patterns.
    .PARAMETER OutputPath
        Directory to save firewall analysis results.
    .PARAMETER Days
        Number of days of logs to analyze (default: 7).
    .EXAMPLE
        Get-FirewallLogAnalysis -OutputPath C:\Evidence -Days 30
    #>
    param(
        [string]$OutputPath = ".",
        [int]$Days = 7
    )

    Write-Host "Analyzing Windows Firewall logs..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "FirewallAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $firewallAnalysis = @{
        Timestamp = Get-Date
        Analysis = @{}
    }

    # Firewall Rules
    Write-Host "Collecting firewall rules..." -ForegroundColor Yellow
    try {
        $firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true } |
            Select-Object Name, DisplayName, Direction, Action, Profile, Enabled
        $firewallRules | Export-Csv (Join-Path $analysisDir "firewall_rules.csv") -NoTypeInformation
        $firewallAnalysis.Analysis.FirewallRules = "Collected $($firewallRules.Count) rules"
        Write-Host "[OK] Firewall rules collected" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect firewall rules: $($_.Exception.Message)"
        $firewallAnalysis.Analysis.FirewallRules = "Error: $($_.Exception.Message)"
    }

    # Firewall Profiles
    Write-Host "Analyzing firewall profiles..." -ForegroundColor Yellow
    try {
        $firewallProfiles = Get-NetFirewallProfile |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked
        $firewallProfiles | Export-Csv (Join-Path $analysisDir "firewall_profiles.csv") -NoTypeInformation
        $firewallAnalysis.Analysis.FirewallProfiles = "Collected profiles"
        Write-Host "[OK] Firewall profiles analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze firewall profiles: $($_.Exception.Message)"
        $firewallAnalysis.Analysis.FirewallProfiles = "Error: $($_.Exception.Message)"
    }

    # Blocked Connections
    Write-Host "Analyzing blocked connections..." -ForegroundColor Yellow
    try {
        $blockedConnections = Get-NetFirewallProfile | ForEach-Object {
            if ($_.LogBlocked) {
                $logPath = $_.LogFileName
                if (Test-Path $logPath) {
                    Get-Content $logPath -Tail 1000 | Where-Object { $_ -match "DROP" } |
                        ForEach-Object {
                            $parts = $_ -split '\s+'
                            if ($parts.Count -ge 8) {
                                [PSCustomObject]@{
                                    Date = $parts[0]
                                    Time = $parts[1]
                                    Action = $parts[2]
                                    Protocol = $parts[3]
                                    SourceIP = $parts[4]
                                    DestIP = $parts[5]
                                    SourcePort = $parts[6]
                                    DestPort = $parts[7]
                                    Size = $parts[8]
                                    TCPFlags = if ($parts.Count -gt 9) { $parts[9] } else { "" }
                                    TCPSeq = if ($parts.Count -gt 10) { $parts[10] } else { "" }
                                    TCPAck = if ($parts.Count -gt 11) { $parts[11] } else { "" }
                                    TCPWin = if ($parts.Count -gt 12) { $parts[12] } else { "" }
                                    ICMPType = if ($parts.Count -gt 13) { $parts[13] } else { "" }
                                    ICMPCode = if ($parts.Count -gt 14) { $parts[14] } else { "" }
                                    Info = if ($parts.Count -gt 15) { $parts[15] } else { "" }
                                    Path = if ($parts.Count -gt 16) { $parts[16] } else { "" }
                                    PID = if ($parts.Count -gt 17) { $parts[17] } else { "" }
                                    ProcessName = if ($parts.Count -gt 18) { $parts[18] } else { "" }
                                }
                            }
                        }
                }
            }
        }

        if ($blockedConnections) {
            $blockedConnections | Export-Csv (Join-Path $analysisDir "blocked_connections.csv") -NoTypeInformation
            $firewallAnalysis.Analysis.BlockedConnections = "Collected $($blockedConnections.Count) blocked connections"
            Write-Host "[OK] Blocked connections analyzed" -ForegroundColor Green
        } else {
            $firewallAnalysis.Analysis.BlockedConnections = "No blocked connections found"
        }
    } catch {
        Write-Warning "Failed to analyze blocked connections: $($_.Exception.Message)"
        $firewallAnalysis.Analysis.BlockedConnections = "Error: $($_.Exception.Message)"
    }

    # Suspicious Activity Analysis
    Write-Host "Analyzing for suspicious firewall activity..." -ForegroundColor Yellow
    try {
        $suspiciousPatterns = @()

        # Check for unusual ports
        $unusualPorts = $blockedConnections | Where-Object {
            $port = [int]$_.DestPort
            $port -lt 1024 -and ($port -notin @(21,22,23,25,53,80,110,143,443,993,995))
        }
        if ($unusualPorts) {
            $suspiciousPatterns += "Unusual privileged ports accessed: $($unusualPorts.Count) instances"
        }

        # Check for rapid connections from same IP
        $rapidConnections = $blockedConnections | Group-Object SourceIP |
            Where-Object { $_.Count -gt 10 } |
            Select-Object Name, Count
        if ($rapidConnections) {
            $suspiciousPatterns += "Rapid connections from IPs: $($rapidConnections | ForEach-Object { "$($_.Name) ($($_.Count) attempts)" } -join '; ')"
        }

        if ($suspiciousPatterns) {
            $suspiciousPatterns | Out-File (Join-Path $analysisDir "suspicious_patterns.txt")
            $firewallAnalysis.Analysis.SuspiciousPatterns = "Found $($suspiciousPatterns.Count) suspicious patterns"
            Write-Host "⚠ Suspicious firewall patterns detected" -ForegroundColor Red
        } else {
            $firewallAnalysis.Analysis.SuspiciousPatterns = "No suspicious patterns found"
            Write-Host "[OK] No suspicious patterns found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to analyze suspicious patterns: $($_.Exception.Message)"
        $firewallAnalysis.Analysis.SuspiciousPatterns = "Error: $($_.Exception.Message)"
    }

    # Save analysis summary
    $summaryFile = Join-Path $analysisDir "firewall_analysis_summary.json"
    $firewallAnalysis | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "Firewall analysis complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}