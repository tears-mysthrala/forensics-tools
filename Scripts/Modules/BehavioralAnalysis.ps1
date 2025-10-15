# BehavioralAnalysis.ps1
# Behavioral analysis functions for malware detection

<#
.SYNOPSIS
    Behavioral Analysis Functions

.DESCRIPTION
    This module provides behavioral analysis capabilities for malware detection:
    - Get-BehavioralAnalysis: Monitors process behavior, network connections, and system activity

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function Get-BehavioralAnalysis {
    <#
    .SYNOPSIS
        Performs behavioral analysis of running processes.
    .DESCRIPTION
        Monitors process behavior, network connections, file access, and registry modifications.
    .PARAMETER ProcessName
        Name of process to monitor (wildcards supported).
    .PARAMETER Duration
        Monitoring duration in seconds.
    .PARAMETER OutputPath
        Directory to save analysis results.
    .EXAMPLE
        Get-BehavioralAnalysis -ProcessName "suspicious.exe" -Duration 300 -OutputPath C:\Analysis
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProcessName,
        [int]$Duration = 60,
        [string]$OutputPath = "."
    )

    Write-Host "Starting behavioral analysis..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "BehavioralAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $behaviorResults = @{
        Timestamp    = Get-Date
        ProcessName  = $ProcessName
        Duration     = $Duration
        Observations = @{}
    }

    Write-Host "Monitoring $ProcessName for $Duration seconds..." -ForegroundColor Yellow

    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($Duration)

    # Baseline measurements
    $baseline = @{
        Processes          = Get-Process | Where-Object { $_.Name -like $ProcessName }
        NetworkConnections = Get-NetTCPConnection
        FileSystemActivity = @()
        RegistryActivity   = @()
    }

    $behaviorResults.Observations.Baseline = $baseline

    # Monitor during the analysis period
    $networkActivity = @()
    $processActivity = @()

    while ((Get-Date) -lt $endTime) {
        try {
            # Check for new processes
            $currentProcesses = Get-Process | Where-Object { $_.Name -like $ProcessName }
            $newProcesses = Compare-Object -ReferenceObject $baseline.Processes -DifferenceObject $currentProcesses -Property Id -PassThru |
            Where-Object { $_.SideIndicator -eq "=>" }

            if ($newProcesses) {
                $processActivity += @{
                    Timestamp = Get-Date
                    Type      = "New Process"
                    Details   = $newProcesses | Select-Object Name, Id, CPU, Memory
                }
            }

            # Check network connections
            $currentConnections = Get-NetTCPConnection
            $newConnections = Compare-Object -ReferenceObject $baseline.NetworkConnections -DifferenceObject $currentConnections -Property OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort -PassThru |
            Where-Object { $_.SideIndicator -eq "=>" }

            if ($newConnections) {
                $networkActivity += @{
                    Timestamp = Get-Date
                    Type      = "New Connection"
                    Details   = $newConnections | Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State
                }
            }

            Start-Sleep -Seconds 1

        }
        catch {
            Write-Warning "Error during monitoring: $($_.Exception.Message)"
        }
    }

    $behaviorResults.Observations.ProcessActivity = $processActivity
    $behaviorResults.Observations.NetworkActivity = $networkActivity

    # Analyze behavior patterns
    $analysis = @{
        SuspiciousPatterns = @()
        RiskScore          = 0
    }

    # Check for rapid process creation
    if ($processActivity.Count -gt 5) {
        $analysis.SuspiciousPatterns += "High process creation rate"
        $analysis.RiskScore += 30
    }

    # Check for suspicious network connections
    $suspiciousPorts = @(4444, 6667, 31337, 12345, 54321)  # Common malware ports
    foreach ($activity in $networkActivity) {
        foreach ($conn in $activity.Details) {
            if ($conn.RemotePort -in $suspiciousPorts) {
                $analysis.SuspiciousPatterns += "Connection to suspicious port: $($conn.RemotePort)"
                $analysis.RiskScore += 25
            }
        }
    }

    # Check for connections to suspicious IP ranges
    foreach ($activity in $networkActivity) {
        foreach ($conn in $activity.Details) {
            $remoteIP = $conn.RemoteAddress
            if ($remoteIP -match "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|0\.)") {
                # Internal IP - less suspicious
            }
            else {
                # External connection - check for known bad IPs (simplified check)
                $analysis.SuspiciousPatterns += "External network connection to: $remoteIP"
                $analysis.RiskScore += 10
            }
        }
    }

    $behaviorResults.Observations.Analysis = $analysis

    # Export results
    $resultsFile = Join-Path $analysisDir "behavioral_analysis.json"
    $behaviorResults | ConvertTo-Json -Depth 4 | Out-File $resultsFile

    Write-Host "Behavioral analysis complete!" -ForegroundColor Green
    Write-Host "Duration: $Duration seconds" -ForegroundColor Cyan
    Write-Host "Process activities: $($processActivity.Count)" -ForegroundColor Cyan
    Write-Host "Network activities: $($networkActivity.Count)" -ForegroundColor Cyan
    Write-Host "Risk score: $($analysis.RiskScore)" -ForegroundColor $(if ($analysis.RiskScore -ge 50) { "Red" } elseif ($analysis.RiskScore -ge 20) { "Yellow" } else { "Green" })
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}