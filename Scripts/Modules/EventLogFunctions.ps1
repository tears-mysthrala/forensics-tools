# EventLogFunctions.ps1 - Event log analysis functions

function Get-EventLogsSummary {
    <#
    .SYNOPSIS
        Summarizes event logs for quick overview.
    .DESCRIPTION
        Counts events by level in System, Security, Application logs.
    .EXAMPLE
        Get-EventLogsSummary
    #>
    $logs = 'System', 'Security', 'Application'
    foreach ($log in $logs) {
        $events = Get-EventLog -LogName $log -Newest 1000 -ErrorAction SilentlyContinue
        if ($events) {
            $summary = $events | Group-Object -Property EntryType | Select-Object Name, Count
            [PSCustomObject]@{
                LogName = $log
                TotalEvents = $events.Count
                Error = ($summary | Where-Object Name -eq 'Error').Count
                Warning = ($summary | Where-Object Name -eq 'Warning').Count
                Information = ($summary | Where-Object Name -eq 'Information').Count
            }
        }
    }
}

function Search-EventLogs {
    <#
    .SYNOPSIS
        Searches event logs for specific keywords.
    .PARAMETER Keyword
        The keyword to search for.
    .PARAMETER LogName
        The log to search (default: Security).
    .EXAMPLE
        Search-EventLogs -Keyword "failed" -LogName Security
    #>
    param(
        [string]$Keyword,
        [string]$LogName = 'Security'
    )
    try {
        Get-EventLog -LogName $LogName -ErrorAction Stop | Where-Object { $_.Message -like "*$Keyword*" } |
        Select-Object TimeGenerated, EntryType, Source, EventID, Message
    } catch {
        Write-Error "Failed to search event logs: $($_.Exception.Message)"
        Write-Host "Try running as Administrator or check if the log '$LogName' exists." -ForegroundColor Yellow
    }
}

function Get-SystemLogsSummary {
    <#
    .SYNOPSIS
        Provides a summary of system logs.
    .PARAMETER Hours
        Hours to look back (default: 24).
    .EXAMPLE
        Get-SystemLogsSummary -Hours 48
    #>
    param([int]$Hours = 24)

    $startTime = (Get-Date).AddHours(-$Hours)

    $logs = @('System', 'Application', 'Security')
    foreach ($log in $logs) {
        $entries = Get-EventLog -LogName $log -After $startTime -ErrorAction SilentlyContinue
        if ($entries) {
            $summary = $entries | Group-Object -Property EntryType |
            Select-Object Name, Count

            [PSCustomObject]@{
                LogName = $log
                TotalEntries = $entries.Count
                Errors = ($summary | Where-Object Name -eq 'Error').Count
                Warnings = ($summary | Where-Object Name -eq 'Warning').Count
                Information = ($summary | Where-Object Name -eq 'Information').Count
                TimeRange = "$Hours hours"
            }
        }
    }
}