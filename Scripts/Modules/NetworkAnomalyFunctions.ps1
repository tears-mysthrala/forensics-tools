# NetworkAnomalyFunctions.ps1 - Network anomaly detection

function Get-NetworkAnomalies {
    <#
    .SYNOPSIS
        Detects network anomalies and suspicious patterns.
    .DESCRIPTION
        Analyzes network traffic for anomalies, unusual connections, and potential security threats.
    .PARAMETER OutputPath
        Directory to save anomaly analysis results.
    .PARAMETER Threshold
        Threshold for anomaly detection (default: 3 standard deviations).
    .EXAMPLE
        Get-NetworkAnomalies -OutputPath C:\Evidence -Threshold 2.5
    #>
    param(
        [string]$OutputPath = ".",
        [double]$Threshold = 3.0
    )

    Write-Host "Detecting network anomalies..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "NetworkAnomalies_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $anomalyAnalysis = @{
        Timestamp = Get-Date
        Analysis = @{}
        Threshold = $Threshold
    }

    # Network Connections Analysis
    Write-Host "Analyzing network connections..." -ForegroundColor Yellow
    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -ne "Listen" } |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

        $connections | Export-Csv (Join-Path $analysisDir "network_connections.csv") -NoTypeInformation
        $anomalyAnalysis.Analysis.Connections = "Analyzed $($connections.Count) connections"
        Write-Host "[OK] Network connections analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze connections: $($_.Exception.Message)"
        $anomalyAnalysis.Analysis.Connections = "Error: $($_.Exception.Message)"
    }

    # Unusual Port Activity
    Write-Host "Detecting unusual port activity..." -ForegroundColor Yellow
    try {
        $portStats = $connections | Group-Object RemotePort |
            Select-Object Name, Count |
            Sort-Object Count -Descending

        $avgConnections = ($portStats | Measure-Object Count -Average).Average
        $stdDev = [Math]::Sqrt(($portStats | ForEach-Object { [Math]::Pow($_.Count - $avgConnections, 2) } | Measure-Object -Average).Average)

        $unusualPorts = $portStats | Where-Object { $_.Count -gt ($avgConnections + ($Threshold * $stdDev)) }

        if ($unusualPorts) {
            $unusualPorts | Export-Csv (Join-Path $analysisDir "unusual_ports.csv") -NoTypeInformation
            $anomalyAnalysis.Analysis.UnusualPorts = "Found $($unusualPorts.Count) unusual ports"
            Write-Host "⚠ Unusual port activity detected" -ForegroundColor Red
        } else {
            $anomalyAnalysis.Analysis.UnusualPorts = "No unusual port activity"
            Write-Host "[OK] No unusual port activity" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to detect unusual ports: $($_.Exception.Message)"
        $anomalyAnalysis.Analysis.UnusualPorts = "Error: $($_.Exception.Message)"
    }

    # Suspicious IP Analysis
    Write-Host "Analyzing suspicious IP addresses..." -ForegroundColor Yellow
    try {
        $ipStats = $connections | Group-Object RemoteAddress |
            Select-Object Name, Count |
            Sort-Object Count -Descending

        $avgIPConnections = ($ipStats | Measure-Object Count -Average).Average
        $ipStdDev = [Math]::Sqrt(($ipStats | ForEach-Object { [Math]::Pow($_.Count - $avgIPConnections, 2) } | Measure-Object -Average).Average)

        $suspiciousIPs = $ipStats | Where-Object { $_.Count -gt ($avgIPConnections + ($Threshold * $ipStdDev)) }

        # Check for known malicious IPs (simplified check)
        $knownMalicious = @(
            "127.0.0.1",  # Loopback - unusual if many connections
            "0.0.0.0"     # Invalid IP
        )

        $maliciousIPs = $connections | Where-Object { $_.RemoteAddress -in $knownMalicious }

        if ($suspiciousIPs -or $maliciousIPs) {
            $suspiciousIPData = @()
            if ($suspiciousIPs) { $suspiciousIPData += $suspiciousIPs | Select-Object @{Name="IP";Expression={$_.Name}}, @{Name="Type";Expression={"High Frequency"}}, Count }
            if ($maliciousIPs) { $suspiciousIPData += $maliciousIPs | Select-Object @{Name="IP";Expression={$_.RemoteAddress}}, @{Name="Type";Expression={"Known Malicious"}}, @{Name="Count";Expression={1}} }

            $suspiciousIPData | Export-Csv (Join-Path $analysisDir "suspicious_ips.csv") -NoTypeInformation
            $anomalyAnalysis.Analysis.SuspiciousIPs = "Found $($suspiciousIPData.Count) suspicious IPs"
            Write-Host "⚠ Suspicious IP activity detected" -ForegroundColor Red
        } else {
            $anomalyAnalysis.Analysis.SuspiciousIPs = "No suspicious IPs found"
            Write-Host "[OK] No suspicious IPs found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to analyze suspicious IPs: $($_.Exception.Message)"
        $anomalyAnalysis.Analysis.SuspiciousIPs = "Error: $($_.Exception.Message)"
    }

    # Protocol Anomalies
    Write-Host "Detecting protocol anomalies..." -ForegroundColor Yellow
    try {
        $protocolStats = Get-NetTCPConnection | Group-Object State |
            Select-Object Name, Count

        $unusualStates = $protocolStats | Where-Object {
            $_.Name -in @("CloseWait", "TimeWait") -and $_.Count -gt 50  # Too many connections in closing states
        }

        if ($unusualStates) {
            $unusualStates | Export-Csv (Join-Path $analysisDir "protocol_anomalies.csv") -NoTypeInformation
            $anomalyAnalysis.Analysis.ProtocolAnomalies = "Found protocol anomalies"
            Write-Host "⚠ Protocol anomalies detected" -ForegroundColor Red
        } else {
            $anomalyAnalysis.Analysis.ProtocolAnomalies = "No protocol anomalies"
            Write-Host "[OK] No protocol anomalies" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to detect protocol anomalies: $($_.Exception.Message)"
        $anomalyAnalysis.Analysis.ProtocolAnomalies = "Error: $($_.Exception.Message)"
    }

    # Process Network Activity
    Write-Host "Analyzing process network activity..." -ForegroundColor Yellow
    try {
        $processConnections = $connections | Group-Object OwningProcess |
            Select-Object Name, Count |
            Sort-Object Count -Descending

        $avgProcessConnections = ($processConnections | Measure-Object Count -Average).Average
        $processStdDev = [Math]::Sqrt(($processConnections | ForEach-Object { [Math]::Pow($_.Count - $avgProcessConnections, 2) } | Measure-Object -Average).Average)

        $unusualProcesses = $processConnections | Where-Object { $_.Count -gt ($avgProcessConnections + ($Threshold * $processStdDev)) }

        if ($unusualProcesses) {
            $unusualProcesses | Export-Csv (Join-Path $analysisDir "unusual_processes.csv") -NoTypeInformation
            $anomalyAnalysis.Analysis.UnusualProcesses = "Found $($unusualProcesses.Count) unusual processes"
            Write-Host "⚠ Unusual process network activity detected" -ForegroundColor Red
        } else {
            $anomalyAnalysis.Analysis.UnusualProcesses = "No unusual process activity"
            Write-Host "[OK] No unusual process activity" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to analyze process activity: $($_.Exception.Message)"
        $anomalyAnalysis.Analysis.UnusualProcesses = "Error: $($_.Exception.Message)"
    }

    # Save analysis summary
    $summaryFile = Join-Path $analysisDir "network_anomalies_summary.json"
    $anomalyAnalysis | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "Network anomaly detection complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}