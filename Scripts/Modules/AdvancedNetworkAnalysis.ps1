# AdvancedNetworkAnalysisFunctions.ps1 - Advanced network analysis orchestration

function Invoke-AdvancedNetworkAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive network forensic analysis.
    .DESCRIPTION
        Orchestrates multiple network analysis functions for complete forensic investigation.
    .PARAMETER OutputPath
        Directory to save all analysis results.
    .PARAMETER IncludeCapture
        Whether to include network capture (requires elevated privileges).
    .PARAMETER Days
        Number of days for log analysis.
    .EXAMPLE
        Invoke-AdvancedNetworkAnalysis -OutputPath C:\Evidence -IncludeCapture $true
    #>
    param(
        [string]$OutputPath = ".",
        [bool]$IncludeCapture = $false,
        [int]$Days = 7
    )

    Write-Host "Starting comprehensive network forensic analysis..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "AdvancedNetworkAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $comprehensiveAnalysis = @{
        Timestamp = Get-Date
        Analysis = @{}
        Components = @()
    }

    # Network Capture (if requested)
    if ($IncludeCapture) {
        Write-Host "Performing network capture..." -ForegroundColor Yellow
        try {
            $captureResult = Start-NetworkCapture -OutputPath $analysisDir -Duration 60
            $comprehensiveAnalysis.Analysis.NetworkCapture = "Capture completed: $captureResult"
            $comprehensiveAnalysis.Components += "NetworkCapture"
            Write-Host "[OK] Network capture completed" -ForegroundColor Green
        } catch {
            Write-Warning "Network capture failed: $($_.Exception.Message)"
            $comprehensiveAnalysis.Analysis.NetworkCapture = "Error: $($_.Exception.Message)"
        }
    }

    # Network Traffic Analysis
    Write-Host "Analyzing network traffic..." -ForegroundColor Yellow
    try {
        $trafficResult = Get-NetworkTrafficAnalysis -OutputPath $analysisDir
        $comprehensiveAnalysis.Analysis.NetworkTraffic = "Traffic analysis completed: $trafficResult"
        $comprehensiveAnalysis.Components += "NetworkTraffic"
        Write-Host "[OK] Network traffic analysis completed" -ForegroundColor Green
    } catch {
        Write-Warning "Network traffic analysis failed: $($_.Exception.Message)"
        $comprehensiveAnalysis.Analysis.NetworkTraffic = "Error: $($_.Exception.Message)"
    }

    # DNS Analysis
    Write-Host "Performing DNS analysis..." -ForegroundColor Yellow
    try {
        $dnsResult = Get-DNSAnalysis -OutputPath $analysisDir
        $comprehensiveAnalysis.Analysis.DNSAnalysis = "DNS analysis completed: $dnsResult"
        $comprehensiveAnalysis.Components += "DNSAnalysis"
        Write-Host "[OK] DNS analysis completed" -ForegroundColor Green
    } catch {
        Write-Warning "DNS analysis failed: $($_.Exception.Message)"
        $comprehensiveAnalysis.Analysis.DNSAnalysis = "Error: $($_.Exception.Message)"
    }

    # Firewall Analysis
    Write-Host "Analyzing firewall logs..." -ForegroundColor Yellow
    try {
        $firewallResult = Get-FirewallLogAnalysis -OutputPath $analysisDir -Days $Days
        $comprehensiveAnalysis.Analysis.FirewallAnalysis = "Firewall analysis completed: $firewallResult"
        $comprehensiveAnalysis.Components += "FirewallAnalysis"
        Write-Host "[OK] Firewall analysis completed" -ForegroundColor Green
    } catch {
        Write-Warning "Firewall analysis failed: $($_.Exception.Message)"
        $comprehensiveAnalysis.Analysis.FirewallAnalysis = "Error: $($_.Exception.Message)"
    }

    # Network Anomaly Detection
    Write-Host "Detecting network anomalies..." -ForegroundColor Yellow
    try {
        $anomalyResult = Get-NetworkAnomalies -OutputPath $analysisDir
        $comprehensiveAnalysis.Analysis.NetworkAnomalies = "Anomaly detection completed: $anomalyResult"
        $comprehensiveAnalysis.Components += "NetworkAnomalies"
        Write-Host "[OK] Network anomaly detection completed" -ForegroundColor Green
    } catch {
        Write-Warning "Network anomaly detection failed: $($_.Exception.Message)"
        $comprehensiveAnalysis.Analysis.NetworkAnomalies = "Error: $($_.Exception.Message)"
    }

    # Generate Comprehensive Report
    Write-Host "Generating comprehensive report..." -ForegroundColor Yellow
    try {
        $reportData = @{
            Title = "Advanced Network Forensic Analysis Report"
            Generated = Get-Date
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                UserName = $env:USERNAME
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            }
            AnalysisResults = $comprehensiveAnalysis
            Summary = @{
                ComponentsExecuted = $comprehensiveAnalysis.Components.Count
                SuccessfulComponents = ($comprehensiveAnalysis.Analysis.Values | Where-Object { -not $_.StartsWith("Error:") }).Count
                FailedComponents = ($comprehensiveAnalysis.Analysis.Values | Where-Object { $_.StartsWith("Error:") }).Count
            }
        }

        $reportFile = Join-Path $analysisDir "comprehensive_network_report.json"
        $reportData | ConvertTo-Json -Depth 5 | Out-File $reportFile

        # Generate HTML Report
        $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Network Forensic Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Advanced Network Forensic Analysis Report</h1>
        <p>Generated: $($reportData.Generated)</p>
        <p>System: $($reportData.SystemInfo.ComputerName) | User: $($reportData.SystemInfo.UserName)</p>
    </div>

    <div class="section">
        <h2>Analysis Summary</h2>
        <p>Components Executed: $($reportData.Summary.ComponentsExecuted)</p>
        <p class="success">Successful: $($reportData.Summary.SuccessfulComponents)</p>
        <p class="error">Failed: $($reportData.Summary.FailedComponents)</p>
    </div>

    <div class="section">
        <h2>Analysis Results</h2>
        <table>
            <tr><th>Component</th><th>Status</th><th>Details</th></tr>
"@

        foreach ($component in $comprehensiveAnalysis.Analysis.GetEnumerator()) {
            $status = if ($component.Value -match "^Error:") { "Error" } else { "Success" }
            $statusClass = if ($status -eq "Error") { "error" } else { "success" }
            $htmlReport += "<tr><td>$($component.Key)</td><td class='$statusClass'>$status</td><td>$($component.Value)</td></tr>"
        }

        $htmlReport += @"
        </table>
    </div>

    <div class="section">
        <h2>Components Executed</h2>
        <ul>
"@

        foreach ($component in $comprehensiveAnalysis.Components) {
            $htmlReport += "<li>$component</li>"
        }

        $htmlReport += @"
        </ul>
    </div>
</body>
</html>
"@

        $htmlFile = Join-Path $analysisDir "comprehensive_network_report.html"
        $htmlReport | Out-File $htmlFile

        $comprehensiveAnalysis.Analysis.ReportGeneration = "Reports generated successfully"
        Write-Host "[OK] Comprehensive report generated" -ForegroundColor Green
    } catch {
        Write-Warning "Report generation failed: $($_.Exception.Message)"
        $comprehensiveAnalysis.Analysis.ReportGeneration = "Error: $($_.Exception.Message)"
    }

    # Save final analysis summary
    $summaryFile = Join-Path $analysisDir "advanced_network_analysis_summary.json"
    $comprehensiveAnalysis | ConvertTo-Json -Depth 5 | Out-File $summaryFile

    Write-Host "Advanced network analysis complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan
    Write-Host "Components executed: $($comprehensiveAnalysis.Components -join ', ')" -ForegroundColor Cyan

    return $analysisDir
}