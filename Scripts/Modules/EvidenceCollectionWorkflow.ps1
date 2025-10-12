# EvidenceCollectionWorkflowFunctions.ps1 - Automated evidence collection workflow functions

# Global variables for automation
$script:WorkflowDefinitions = @{}

function New-AutomatedEvidenceCollectionWorkflow {
    <#
    .SYNOPSIS
        Creates an automated evidence collection workflow

    .DESCRIPTION
        Defines and creates automated workflows for systematic evidence collection
        across multiple sources and systems

    .PARAMETER WorkflowName
        Name of the workflow

    .PARAMETER Sources
        Array of evidence sources to collect from

    .PARAMETER Schedule
        Schedule for automated execution (Daily, Hourly, Weekly, etc.)

    .PARAMETER RetentionDays
        Number of days to retain collected evidence

    .PARAMETER OutputPath
        Path to store collected evidence

    .EXAMPLE
        New-AutomatedEvidenceCollectionWorkflow -WorkflowName "DailySystemAudit" -Sources @("Memory", "Network", "Filesystem") -Schedule "Daily" -RetentionDays 30
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkflowName,

        [Parameter(Mandatory = $true)]
        [array]$Sources,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Hourly", "Daily", "Weekly", "Monthly")]
        [string]$Schedule = "Daily",

        [Parameter(Mandatory = $false)]
        [int]$RetentionDays = 30,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "$env:TEMP\ForensicEvidence\$WorkflowName"
    )

    try {
        # Create workflow definition
        $workflow = @{
            Name = $WorkflowName
            Sources = $Sources
            Schedule = $Schedule
            RetentionDays = $RetentionDays
            OutputPath = $OutputPath
            Created = Get-Date
            LastRun = $null
            Status = "Created"
            Tasks = @()
        }

        # Define tasks based on sources
        foreach ($source in $Sources) {
            switch ($source) {
                "Memory" {
                    $workflow.Tasks += @{
                        Name = "MemoryDump"
                        Function = "Get-MemoryDump"
                        Parameters = @{ OutputPath = "$OutputPath\Memory" }
                        Timeout = 300
                    }
                }
                "Network" {
                    $workflow.Tasks += @{
                        Name = "NetworkCapture"
                        Function = "Start-NetworkCapture"
                        Parameters = @{ Duration = 60; OutputPath = "$OutputPath\Network" }
                        Timeout = 120
                    }
                }
                "Filesystem" {
                    $workflow.Tasks += @{
                        Name = "FileSystemSnapshot"
                        Function = "Get-FileSystemSnapshot"
                        Parameters = @{ OutputPath = "$OutputPath\FileSystem" }
                        Timeout = 600
                    }
                }
                "Registry" {
                    $workflow.Tasks += @{
                        Name = "RegistryExport"
                        Function = "Export-RegistryHives"
                        Parameters = @{ OutputPath = "$OutputPath\Registry" }
                        Timeout = 180
                    }
                }
                "EventLogs" {
                    $workflow.Tasks += @{
                        Name = "EventLogExport"
                        Function = "Export-EventLogs"
                        Parameters = @{ OutputPath = "$OutputPath\EventLogs" }
                        Timeout = 120
                    }
                }
                "Cloud" {
                    $workflow.Tasks += @{
                        Name = "CloudInventory"
                        Function = "Get-AzureResourceInventory"
                        Parameters = @{ OutputPath = "$OutputPath\Cloud" }
                        Timeout = 300
                    }
                }
            }
        }

        # Store workflow
        $script:WorkflowDefinitions[$WorkflowName] = $workflow

        Write-Host "Created automated evidence collection workflow: $WorkflowName" -ForegroundColor Green
        Write-Host "Sources: $($Sources -join ', ')" -ForegroundColor Cyan
        Write-Host "Schedule: $Schedule" -ForegroundColor Cyan
        Write-Host "Retention: $RetentionDays days" -ForegroundColor Cyan

        return $workflow
    }
    catch {
        Write-Error "Failed to create automated workflow: $_"
        return $null
    }
}

function Start-AutomatedEvidenceCollection {
    <#
    .SYNOPSIS
        Executes an automated evidence collection workflow

    .DESCRIPTION
        Runs the specified automated evidence collection workflow,
        executing all defined tasks in sequence

    .PARAMETER WorkflowName
        Name of the workflow to execute

    .PARAMETER Force
        Force execution even if recently run

    .EXAMPLE
        Start-AutomatedEvidenceCollection -WorkflowName "DailySystemAudit"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkflowName,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        if (-not $script:WorkflowDefinitions.ContainsKey($WorkflowName)) {
            throw "Workflow '$WorkflowName' not found"
        }

        $workflow = $script:WorkflowDefinitions[$WorkflowName]

        # Check if recently run (unless forced)
        if (-not $Force -and $workflow.LastRun) {
            $timeSinceLastRun = (Get-Date) - $workflow.LastRun
            switch ($workflow.Schedule) {
                "Hourly" { $maxAge = [TimeSpan]::FromHours(1) }
                "Daily" { $maxAge = [TimeSpan]::FromDays(1) }
                "Weekly" { $maxAge = [TimeSpan]::FromDays(7) }
                "Monthly" { $maxAge = [TimeSpan]::FromDays(30) }
            }

            if ($timeSinceLastRun -lt $maxAge) {
                Write-Host "Workflow '$WorkflowName' was last run $($timeSinceLastRun.TotalHours.ToString('F1')) hours ago. Use -Force to run anyway." -ForegroundColor Yellow
                return
            }
        }

        Write-Host "Starting automated evidence collection workflow: $WorkflowName" -ForegroundColor Green
        $workflow.Status = "Running"

        # Create output directory
        if (-not (Test-Path $workflow.OutputPath)) {
            New-Item -ItemType Directory -Path $workflow.OutputPath -Force | Out-Null
        }

        # Execute tasks
        $results = @()
        foreach ($task in $workflow.Tasks) {
            Write-Host "Executing task: $($task.Name)" -ForegroundColor Cyan

            try {
                # Create task output directory
                $taskOutputPath = Join-Path $workflow.OutputPath $task.Name
                if (-not (Test-Path $taskOutputPath)) {
                    New-Item -ItemType Directory -Path $taskOutputPath -Force | Out-Null
                }

                # Execute task with timeout
                $job = Start-Job -ScriptBlock {
                    param($FunctionName, $Parameters, $OutputPath)

                    try {
                        # Update parameters with output path
                        $Parameters.OutputPath = $OutputPath

                        # Execute the function
                        & $FunctionName @Parameters

                        return @{ Success = $true; Result = "Task completed successfully" }
                    }
                    catch {
                        return @{ Success = $false; Result = $_.Exception.Message }
                    }
                } -ArgumentList $task.Function, $task.Parameters, $taskOutputPath

                # Wait for job with timeout
                $completed = Wait-Job $job -Timeout $task.Timeout
                if (-not $completed) {
                    Stop-Job $job -ErrorAction SilentlyContinue
                    throw "Task timed out after $($task.Timeout) seconds"
                }

                $jobResult = Receive-Job $job
                Remove-Job $job

                if ($jobResult.Success) {
                    Write-Host "  Task completed successfully" -ForegroundColor Green
                    $results += @{ Task = $task.Name; Status = "Success"; Result = $jobResult.Result }
                }
                else {
                    Write-Host "  Task failed: $($jobResult.Result)" -ForegroundColor Red
                    $results += @{ Task = $task.Name; Status = "Failed"; Result = $jobResult.Result }
                }
            }
            catch {
                Write-Host "  Task failed: $_" -ForegroundColor Red
                $results += @{ Task = $task.Name; Status = "Failed"; Result = $_.Exception.Message }
            }
        }

        # Update workflow status
        $workflow.LastRun = Get-Date
        $workflow.Status = "Completed"

        # Clean up old evidence
        $cutoffDate = (Get-Date).AddDays(-$workflow.RetentionDays)
        Get-ChildItem $workflow.OutputPath -Directory | Where-Object { $_.CreationTime -lt $cutoffDate } | Remove-Item -Recurse -Force

        Write-Host "Workflow '$WorkflowName' completed. Results:" -ForegroundColor Green
        $results | Format-Table -AutoSize

        return $results
    }
    catch {
        Write-Error "Failed to execute automated workflow: $_"
        if ($workflow) {
            $workflow.Status = "Failed"
        }
        return $null
    }
}