# AutomatedReportingFunctions.ps1
# Automated report generation functions for PowerShell Forensics Toolkit

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
        [Parameter(Mandatory=$true)]
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
            Data = $forensicData
        }

    } catch {
        Write-Error "Failed to generate automated report: $($_.Exception.Message)"
        throw
    }
}

function Register-AutomatedReportSchedule {
    <#
    .SYNOPSIS
        Registers a scheduled task for automated report generation.

    .DESCRIPTION
        Creates a Windows scheduled task to run automated forensic reports
        at specified intervals.

    .PARAMETER Schedule
        Schedule type (Hourly, Daily, Weekly, Monthly)

    .PARAMETER OutputPath
        Directory where reports will be saved

    .PARAMETER IncludeSystemInfo
        Include system information

    .PARAMETER IncludeEventLogs
        Include event logs

    .PARAMETER IncludeNetwork
        Include network analysis

    .PARAMETER IncludeProcesses
        Include process analysis

    .PARAMETER IncludeFiles
        Include file system analysis

    .PARAMETER RetentionDays
        Days to keep reports

    .PARAMETER EmailReport
        Email address for reports
    #>

    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Hourly", "Daily", "Weekly", "Monthly")]
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

    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Administrator privileges required to create scheduled tasks. Run as administrator to enable scheduling."
        return
    }

    # Build command line arguments
    $arguments = "-Command `"& { Import-Module '$PSScriptRoot\..\ForensicFunctions.ps1'; New-AutomatedReport -Schedule OnDemand -OutputPath '$OutputPath'"

    if ($IncludeSystemInfo) { $arguments += " -IncludeSystemInfo" }
    if ($IncludeEventLogs) { $arguments += " -IncludeEventLogs" }
    if ($IncludeNetwork) { $arguments += " -IncludeNetwork" }
    if ($IncludeProcesses) { $arguments += " -IncludeProcesses" }
    if ($IncludeFiles) { $arguments += " -IncludeFiles" }

    $arguments += " -RetentionDays $RetentionDays"

    if ($EmailReport) { $arguments += " -EmailReport '$EmailReport'" }

    $arguments += " }`""

    # Determine trigger based on schedule
    $trigger = switch ($Schedule) {
        "Hourly" {
            New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 365)
        }
        "Daily" {
            New-ScheduledTaskTrigger -Daily -At "02:00"
        }
        "Weekly" {
            New-ScheduledTaskTrigger -Weekly -At "02:00" -DaysOfWeek Sunday
        }
        "Monthly" {
            New-ScheduledTaskTrigger -Monthly -At "02:00" -DaysOfMonth 1
        }
    }

    # Create scheduled task
    $taskName = "PowerShell Forensics - Automated Report ($Schedule)"
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    try {
        # Remove existing task if it exists
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        # Register new task
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $trigger -Settings $taskSettings -Description "Automated forensic report generation" | Out-Null

        Write-Host "Scheduled task created: $taskName" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to create scheduled task. You can manually schedule the reports using Task Scheduler."
        Write-Host "Command to run: powershell.exe $arguments" -ForegroundColor Yellow
    }
}

function Send-AutomatedReportEmail {
    <#
    .SYNOPSIS
        Sends automated report via email.

    .DESCRIPTION
        Emails the generated forensic report to specified recipients.

    .PARAMETER ReportPath
        Path to the HTML report file

    .PARAMETER EmailTo
        Email address to send to

    .PARAMETER ReportData
        Report data for summary
    #>

    param(
        [Parameter(Mandatory=$true)]
        [string]$ReportPath,

        [Parameter(Mandatory=$true)]
        [string]$EmailTo,

        [hashtable]$ReportData
    )

    try {
        # Create email summary
        $subject = "Automated Forensic Report - $(Get-Date -Format 'yyyy-MM-dd')"
        $body = @"
Automated Forensic Report Generated

Report Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Report File: $ReportPath

Summary:
"@

        if ($ReportData.SystemInfo) {
            $body += "`nSystem: $($ReportData.SystemInfo.ComputerName) ($($ReportData.SystemInfo.OS))"
        }

        if ($ReportData.EventLogs) {
            $totalEvents = ($ReportData.EventLogs | Measure-Object -Property TotalEvents -Sum).Sum
            $body += "`nEvent Logs: $totalEvents total events"
        }

        if ($ReportData.Network) {
            $connections = $ReportData.Network | Where-Object { $_.State -eq "Established" } | Measure-Object | Select-Object -ExpandProperty Count
            $body += "`nNetwork: $connections active connections"
        }

        if ($ReportData.Processes) {
            $processCount = $ReportData.Processes.Count
            $body += "`nProcesses: $processCount running processes"
        }

        $body += "`n`nPlease find the detailed report attached."

        # Note: Email sending requires SMTP configuration
        # This is a placeholder for actual email functionality
        Write-Host "Email functionality requires SMTP configuration." -ForegroundColor Yellow
        Write-Host "Subject: $subject" -ForegroundColor Yellow
        Write-Host "To: $EmailTo" -ForegroundColor Yellow
        Write-Host "Report: $ReportPath" -ForegroundColor Yellow

    } catch {
        Write-Warning "Failed to send email report: $($_.Exception.Message)"
    }
}

# Export functions