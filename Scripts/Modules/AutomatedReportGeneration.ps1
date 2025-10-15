# AutomatedReportGeneration.ps1 - Automated report generation functions

<#
.SYNOPSIS
    Automated Report Generation Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for generating automated forensic reports.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function New-AutomatedReport {
    <#
    .SYNOPSIS
        Creates automated forensic reports on a schedule or on-demand.

    .DESCRIPTION
        Generates comprehensive forensic reports automatically, including system information,
        event logs, network connections, running processes, and more. Can be scheduled
        to run periodically or executed on-demand.

    .PARAMETER Schedule
        Schedule for automated report generation (Daily, Weekly, Monthly, or OnDemand)

    .PARAMETER OutputPath
        Directory where reports will be saved

    .PARAMETER IncludeSystemInfo
        Include system information in the report

    .PARAMETER IncludeEventLogs
        Include event log analysis in the report

    .PARAMETER IncludeNetwork
        Include network connections analysis

    .PARAMETER IncludeProcesses
        Include running processes analysis

    .PARAMETER IncludeFiles
        Include file system analysis

    .PARAMETER RetentionDays
        Number of days to keep old reports (default: 30)

    .PARAMETER EmailReport
        Email address to send reports to (optional)

    .EXAMPLE
        New-AutomatedReport -Schedule Daily -OutputPath "C:\Reports"

    .EXAMPLE
        New-AutomatedReport -Schedule OnDemand -IncludeSystemInfo -IncludeEventLogs -OutputPath "C:\Reports"
    #>

    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("OnDemand", "Hourly", "Daily", "Weekly", "Monthly")]
        [string]$Schedule,

        [string]$OutputPath = ".\Reports",

        [switch]$IncludeSystemInfo,
        [switch]$IncludeEventLogs,
        [switch]$IncludeNetwork,
        [switch]$IncludeProcesses,
        [switch]$IncludeFiles,

        [int]$RetentionDays = 30,

        [string]$EmailReport
    )

    # Set default inclusions if none specified
    if (-not ($IncludeSystemInfo -or $IncludeEventLogs -or $IncludeNetwork -or $IncludeProcesses -or $IncludeFiles)) {
        $IncludeSystemInfo = $true
        $IncludeEventLogs = $true
        $IncludeNetwork = $true
        $IncludeProcesses = $true
    }

    Write-Host "Creating automated forensic report..." -ForegroundColor Cyan

    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Generate timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportBaseName = "Automated_Forensic_Report_$timestamp"

    # Collect forensic data
    $forensicData = @{}

    try {
        # System Information
        if ($IncludeSystemInfo) {
            Write-Host "Collecting system information..." -ForegroundColor Yellow
            $forensicData.SystemInfo = Get-SystemInfo
        }

        # Event Logs
        if ($IncludeEventLogs) {
            Write-Host "Analyzing event logs..." -ForegroundColor Yellow
            $forensicData.EventLogs = Get-EventLogsSummary
        }

        # Network Connections
        if ($IncludeNetwork) {
            Write-Host "Analyzing network connections..." -ForegroundColor Yellow
            $forensicData.Network = Get-NetworkConnections
        }

        # Running Processes
        if ($IncludeProcesses) {
            Write-Host "Analyzing running processes..." -ForegroundColor Yellow
            $forensicData.Processes = Get-ProcessDetails
        }

        # File System Analysis
        if ($IncludeFiles) {
            Write-Host "Analyzing file system..." -ForegroundColor Yellow
            $forensicData.FileSystem = Get-LargeFiles -Path "C:\" -Top 50
        }

        # Generate HTML Report
        Write-Host "Generating HTML report..." -ForegroundColor Yellow
        $htmlReport = New-ForensicHTMLReport -AnalysisData $forensicData -OutputPath $OutputPath -Title "Automated Forensic Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

        # Generate JSON export
        Write-Host "Generating JSON export..." -ForegroundColor Yellow
        $jsonFile = Join-Path $OutputPath "$reportBaseName.json"
        $forensicData | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8

        # Generate CSV summary
        Write-Host "Generating CSV summary..." -ForegroundColor Yellow
        Export-ForensicReport -AnalysisResults $forensicData -OutputPath $OutputPath -Formats @("CSV")

        # Clean up old reports
        Write-Host "Cleaning up old reports..." -ForegroundColor Yellow
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        Get-ChildItem -Path $OutputPath -Filter "Automated_Forensic_Report_*.html" | Where-Object { $_.CreationTime -lt $cutoffDate } | Remove-Item -Force
        Get-ChildItem -Path $OutputPath -Filter "Automated_Forensic_Report_*.json" | Where-Object { $_.CreationTime -lt $cutoffDate } | Remove-Item -Force
        Get-ChildItem -Path $OutputPath -Filter "Automated_Forensic_Report_*.csv" | Where-Object { $_.CreationTime -lt $cutoffDate } | Remove-Item -Force

        # Email report if requested
        if ($EmailReport) {
            Write-Host "Sending email report..." -ForegroundColor Yellow
            Send-AutomatedReportEmail -ReportPath $htmlReport -EmailTo $EmailReport -ReportData $forensicData
        }

        # Schedule next run if not OnDemand
        if ($Schedule -ne "OnDemand") {
            Write-Host "Scheduling next report run..." -ForegroundColor Yellow
            Register-AutomatedReportSchedule -Schedule $Schedule -OutputPath $OutputPath -IncludeSystemInfo:$IncludeSystemInfo -IncludeEventLogs:$IncludeEventLogs -IncludeNetwork:$IncludeNetwork -IncludeProcesses:$IncludeProcesses -IncludeFiles:$IncludeFiles -RetentionDays $RetentionDays -EmailReport $EmailReport
        }

        Write-Host "Automated report completed successfully!" -ForegroundColor Green
        Write-Host "Report saved to: $htmlReport" -ForegroundColor Cyan
        Write-Host "JSON export: $jsonFile" -ForegroundColor Cyan
        Write-Host "CSV summary: $csvFile" -ForegroundColor Cyan

        return @{
            HTMLReport = $htmlReport
            JSONExport = $jsonFile
            CSVSummary = $csvFile
            Data       = $forensicData
        }

    }
    catch {
        Write-Error "Failed to generate automated report: $($_.Exception.Message)"
        throw
    }
}