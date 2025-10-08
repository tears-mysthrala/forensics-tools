# ExportReportFunctions.ps1 - Report export functions

function Export-ForensicReport {
    <#
    .SYNOPSIS
        Exports a comprehensive forensic report in multiple formats.
    .DESCRIPTION
        Generates forensic reports in JSON, CSV, and HTML formats with evidence correlation.
    .PARAMETER AnalysisResults
        Results from forensic analysis functions.
    .PARAMETER OutputPath
        Directory to save the reports.
    .PARAMETER Formats
        Report formats to generate (JSON, CSV, HTML).
    .EXAMPLE
        Export-ForensicReport -AnalysisResults $results -OutputPath C:\Reports -Formats @("JSON", "HTML")
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisResults,
        [string]$OutputPath = ".",
        [string[]]$Formats = @("JSON", "HTML")
    )

    Write-Host "Exporting comprehensive forensic report..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportDir = Join-Path $OutputPath "ForensicReport_$timestamp"

    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }

    $exportedFiles = @()

    # Export JSON format
    if ($Formats -contains "JSON") {
        Write-Host "Exporting JSON report..." -ForegroundColor Yellow
        $jsonFile = Join-Path $reportDir "forensic_report.json"
        $AnalysisResults | ConvertTo-Json -Depth 4 | Out-File $jsonFile
        $exportedFiles += $jsonFile
        Write-Host "✓ JSON report exported" -ForegroundColor Green
    }

    # Export CSV format
    if ($Formats -contains "CSV") {
        Write-Host "Exporting CSV reports..." -ForegroundColor Yellow

        # Flatten and export different data types
        if ($AnalysisResults.FileAnalysis) {
            $csvFile = Join-Path $reportDir "file_analysis.csv"
            $AnalysisResults.FileAnalysis | Export-Csv $csvFile -NoTypeInformation
            $exportedFiles += $csvFile
        }

        if ($AnalysisResults.NetworkAnalysis) {
            $csvFile = Join-Path $reportDir "network_analysis.csv"
            $AnalysisResults.NetworkAnalysis | Export-Csv $csvFile -NoTypeInformation
            $exportedFiles += $csvFile
        }

        if ($AnalysisResults.ProcessAnalysis) {
            $csvFile = Join-Path $reportDir "process_analysis.csv"
            $AnalysisResults.ProcessAnalysis | Export-Csv $csvFile -NoTypeInformation
            $exportedFiles += $csvFile
        }

        Write-Host "✓ CSV reports exported" -ForegroundColor Green
    }

    # Export HTML format
    if ($Formats -contains "HTML") {
        Write-Host "Creating HTML report..." -ForegroundColor Yellow
        $htmlFile = New-ForensicHTMLReport -AnalysisData $AnalysisResults -OutputPath $reportDir -Title "Comprehensive Forensic Report"
        $exportedFiles += $htmlFile
        Write-Host "✓ HTML report created" -ForegroundColor Green
    }

    # Create report summary
    $summaryFile = Join-Path $reportDir "report_summary.txt"
    $summary = @"
FORENSIC ANALYSIS REPORT SUMMARY
================================

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Report Directory: $reportDir

EXPORTED FILES:
$($exportedFiles | ForEach-Object { "  - " + (Split-Path $_ -Leaf) })

ANALYSIS SUMMARY:
"@

    if ($AnalysisResults.SystemInfo) {
        $summary += "`nSystem Information:`n"
        $summary += "  Hostname: $($AnalysisResults.SystemInfo.Hostname)`n"
        $summary += "  OS: $($AnalysisResults.SystemInfo.OS)`n"
    }

    if ($AnalysisResults.FileAnalysis) {
        $highRisk = ($AnalysisResults.FileAnalysis | Where-Object { $_.RiskLevel -eq "High" }).Count
        $summary += "`nFile Analysis:`n"
        $summary += "  Files analyzed: $($AnalysisResults.FileAnalysis.Count)`n"
        $summary += "  High risk files: $highRisk`n"
    }

    if ($AnalysisResults.NetworkAnalysis) {
        $summary += "`nNetwork Analysis:`n"
        $summary += "  Connections analyzed: $($AnalysisResults.NetworkAnalysis.TotalConnections)`n"
        $summary += "  Suspicious activities: $($AnalysisResults.NetworkAnalysis.SuspiciousConnections)`n"
    }

    $summary | Out-File $summaryFile

    Write-Host "✓ Forensic report export complete!" -ForegroundColor Green
    Write-Host "Reports saved to: $reportDir" -ForegroundColor Cyan
    Write-Host "Summary: $summaryFile" -ForegroundColor Cyan

    return $reportDir
}