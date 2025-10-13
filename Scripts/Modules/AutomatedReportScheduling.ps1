# AutomatedReportScheduling.ps1 - Automated report scheduling functions

<#
.SYNOPSIS
    Automated Report Scheduling Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for scheduling automated forensic reports.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

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
        [Parameter(Mandatory = $true)]
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
    }
    catch {
        Write-Warning "Failed to create scheduled task. You can manually schedule the reports using Task Scheduler."
        Write-Host "Command to run: powershell.exe $arguments" -ForegroundColor Yellow
    }
}