# AutomatedReportEmail.ps1 - Automated report email functions

<#
.SYNOPSIS
    Automated Report Email Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for emailing automated forensic reports.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

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
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,

        [Parameter(Mandatory = $true)]
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

    }
    catch {
        Write-Warning "Failed to send email report: $($_.Exception.Message)"
    }
}