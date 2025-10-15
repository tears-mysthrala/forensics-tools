# ScheduledTaskFunctions.ps1 - Scheduled forensic task management functions

# Global variables for automation
$script:ScheduledTasks = @{}

function New-ScheduledForensicTask {
    <#
    .SYNOPSIS
        Creates a scheduled forensic analysis task

    .DESCRIPTION
        Creates Windows scheduled tasks for automated forensic analysis
        and evidence collection

    .PARAMETER TaskName
        Name of the scheduled task

    .PARAMETER WorkflowName
        Name of the workflow to execute

    .PARAMETER Schedule
        Schedule type (Daily, Weekly, Monthly)

    .PARAMETER StartTime
        Time to start the task (HH:mm format)

    .PARAMETER User
        User account to run the task under

    .EXAMPLE
        New-ScheduledForensicTask -TaskName "DailyForensics" -WorkflowName "DailySystemAudit" -Schedule "Daily" -StartTime "02:00"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName,

        [Parameter(Mandatory = $true)]
        [string]$WorkflowName,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Daily", "Weekly", "Monthly")]
        [string]$Schedule = "Daily",

        [Parameter(Mandatory = $false)]
        [string]$StartTime = "02:00",

        [Parameter(Mandatory = $false)]
        [string]$User = "SYSTEM"
    )

    try {
        # Validate workflow exists
        if (-not $script:WorkflowDefinitions.ContainsKey($WorkflowName)) {
            throw "Workflow '$WorkflowName' not found"
        }

        # Create PowerShell script for the task
        $taskScript = @"
# Scheduled Forensic Task: $TaskName
# Generated on $(Get-Date)

try {
    # Import forensic functions
    `$forensicFunctionsPath = "`$PSScriptRoot\Scripts\ForensicFunctions.ps1"
    if (Test-Path `$forensicFunctionsPath) {
        . `$forensicFunctionsPath
    }

    # Execute workflow
    Start-AutomatedEvidenceCollection -WorkflowName "$WorkflowName" -Force

    # Log completion
    `$logPath = "`$env:TEMP\ForensicScheduledTasks.log"
    "`$(Get-Date) - Task '$TaskName' completed successfully" | Out-File -FilePath `$logPath -Append
}
catch {
    # Log error
    `$logPath = "`$env:TEMP\ForensicScheduledTasks.log"
    "`$(Get-Date) - Task '$TaskName' failed: `$_" | Out-File -FilePath `$logPath -Append
}
"@

        # Save task script
        $scriptPath = "$env:TEMP\ScheduledForensicTasks\$TaskName.ps1"
        $scriptDir = Split-Path $scriptPath -Parent
        if (-not (Test-Path $scriptDir)) {
            New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
        }
        $taskScript | Out-File -FilePath $scriptPath -Encoding UTF8

        # Create scheduled task
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = switch ($Schedule) {
            "Daily" { New-ScheduledTaskTrigger -Daily -At $StartTime }
            "Weekly" { New-ScheduledTaskTrigger -Weekly -At $StartTime -DaysOfWeek Monday }
            "Monthly" { New-ScheduledTaskTrigger -Monthly -At $StartTime -DaysOfMonth 1 }
        }

        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType ServiceAccount

        $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal

        Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

        # Store task information
        $script:ScheduledTasks[$TaskName] = @{
            Name = $TaskName
            Workflow = $WorkflowName
            Schedule = $Schedule
            StartTime = $StartTime
            ScriptPath = $scriptPath
            Created = Get-Date
        }

        Write-Host "Created scheduled forensic task: $TaskName" -ForegroundColor Green
        Write-Host "Workflow: $WorkflowName" -ForegroundColor Cyan
        Write-Host "Schedule: $Schedule at $StartTime" -ForegroundColor Cyan

        return $script:ScheduledTasks[$TaskName]
    }
    catch {
        Write-Error "Failed to create scheduled task: $_"
        return $null
    }
}

function Get-ScheduledForensicTasks {
    <#
    .SYNOPSIS
        Gets all scheduled forensic tasks

    .DESCRIPTION
        Retrieves information about all configured scheduled forensic tasks

    .EXAMPLE
        Get-ScheduledForensicTasks
    #>
    [CmdletBinding()]
    param()

    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -in $script:ScheduledTasks.Keys }

        $results = @()
        foreach ($task in $tasks) {
            $customInfo = $script:ScheduledTasks[$task.TaskName]
            $results += [PSCustomObject]@{
                Name = $task.TaskName
                Workflow = $customInfo.Workflow
                Schedule = $customInfo.Schedule
                StartTime = $customInfo.StartTime
                State = $task.State
                LastRunTime = $task.LastRunTime
                NextRunTime = $task.NextRunTime
            }
        }

        return $results
    }
    catch {
        Write-Error "Failed to get scheduled tasks: $_"
        return $null
    }
}