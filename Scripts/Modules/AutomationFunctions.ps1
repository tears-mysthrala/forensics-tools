# AutomationFunctions.ps1
# Comprehensive automation and orchestration functions for forensic analysis
# Includes automated evidence collection, scheduled tasks, and SIEM integration

#Requires -Version 7.0

<#
.SYNOPSIS
    Forensic Automation and Orchestration Functions

.DESCRIPTION
    This module provides comprehensive automation capabilities for forensic analysis including:
    - Automated evidence collection workflows
    - Scheduled analysis tasks
    - SIEM integration and alerting
    - Workflow orchestration and management
    - Automated reporting and notifications

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7.0+, Windows Terminal
#>

# Global variables for automation
$script:AutomationJobs = @{}
$script:ScheduledTasks = @{}
$script:WorkflowDefinitions = @{}
$script:SIEMIntegrations = @{}

# Automated Evidence Collection Functions

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

# Scheduled Task Management Functions

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

# SIEM Integration Functions

function New-SIEMIntegration {
    <#
    .SYNOPSIS
        Creates a SIEM integration configuration

    .DESCRIPTION
        Configures integration with SIEM systems for automated alerting
        and incident response

    .PARAMETER SIEMType
        Type of SIEM system (Splunk, ELK, QRadar, etc.)

    .PARAMETER Server
        SIEM server hostname or IP

    .PARAMETER Port
        SIEM server port

    .PARAMETER APIKey
        API key for authentication

    .PARAMETER AlertThresholds
        Hash table of alert thresholds

    .EXAMPLE
        New-SIEMIntegration -SIEMType "Splunk" -Server "splunk.company.com" -Port 8088 -APIKey "your-api-key"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Splunk", "ELK", "QRadar", "ArcSight", "Custom")]
        [string]$SIEMType,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [int]$Port = 8088,

        [Parameter(Mandatory = $false)]
        [string]$APIKey,

        [Parameter(Mandatory = $false)]
        [hashtable]$AlertThresholds = @{
            HighSeverity = 8
            MediumSeverity = 5
            LowSeverity = 2
        }
    )

    try {
        $integration = @{
            Type = $SIEMType
            Server = $Server
            Port = $Port
            APIKey = $APIKey
            AlertThresholds = $AlertThresholds
            Created = Get-Date
            Status = "Configured"
        }

        $script:SIEMIntegrations[$SIEMType] = $integration

        Write-Host "Configured SIEM integration: $SIEMType" -ForegroundColor Green
        Write-Host "Server: $Server`:$Port" -ForegroundColor Cyan

        return $integration
    }
    catch {
        Write-Error "Failed to configure SIEM integration: $_"
        return $null
    }
}

function Send-SIEMAlert {
    <#
    .SYNOPSIS
        Sends an alert to configured SIEM systems

    .DESCRIPTION
        Sends forensic findings and alerts to integrated SIEM systems

    .PARAMETER SIEMType
        Type of SIEM system to send alert to

    .PARAMETER AlertData
        Alert data including severity, message, and details

    .EXAMPLE
        Send-SIEMAlert -SIEMType "Splunk" -AlertData @{ Severity = "High"; Message = "Malware detected"; Details = $malwareInfo }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SIEMType,

        [Parameter(Mandatory = $true)]
        [hashtable]$AlertData
    )

    try {
        if (-not $script:SIEMIntegrations.ContainsKey($SIEMType)) {
            throw "SIEM integration '$SIEMType' not configured"
        }

        $integration = $script:SIEMIntegrations[$SIEMType]

        # Check if alert meets threshold
        $severity = $AlertData.Severity
        $threshold = switch ($severity) {
            "High" { $integration.AlertThresholds.HighSeverity }
            "Medium" { $integration.AlertThresholds.MediumSeverity }
            "Low" { $integration.AlertThresholds.LowSeverity }
            default { 0 }
        }

        if ($AlertData.Score -lt $threshold) {
            Write-Host "Alert score ($($AlertData.Score)) below threshold ($threshold) for $severity severity. Skipping SIEM alert." -ForegroundColor Yellow
            return
        }

        # Format alert for SIEM
        $alertPayload = @{
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            source = "PowerShell Forensics"
            severity = $severity
            message = $AlertData.Message
            details = $AlertData.Details
            score = $AlertData.Score
        }

        # Send to SIEM based on type
        switch ($SIEMType) {
            "Splunk" {
                $url = "https://$($integration.Server):$($integration.Port)/services/collector/event"
                $headers = @{
                    "Authorization" = "Splunk $($integration.APIKey)"
                    "Content-Type" = "application/json"
                }

                $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($alertPayload | ConvertTo-Json) -SkipCertificateCheck
                Write-Host "Alert sent to Splunk SIEM" -ForegroundColor Green
            }
            "ELK" {
                $url = "http://$($integration.Server):$($integration.Port)/forensics-alerts/_doc"
                $response = Invoke-RestMethod -Uri $url -Method Post -Body ($alertPayload | ConvertTo-Json) -ContentType "application/json"
                Write-Host "Alert sent to ELK SIEM" -ForegroundColor Green
            }
            default {
                Write-Host "SIEM alert formatted for $SIEMType (custom integration required)" -ForegroundColor Yellow
                return $alertPayload
            }
        }

        return $true
    }
    catch {
        Write-Error "Failed to send SIEM alert: $_"
        return $false
    }
}

# Workflow Orchestration Functions

function New-ForensicWorkflowOrchestrator {
    <#
    .SYNOPSIS
        Creates a forensic workflow orchestrator

    .DESCRIPTION
        Sets up an orchestrator to manage complex forensic workflows
        with dependencies and parallel execution

    .PARAMETER OrchestratorName
        Name of the orchestrator

    .PARAMETER Workflows
        Array of workflow names to orchestrate

    .PARAMETER Dependencies
        Hash table defining workflow dependencies

    .EXAMPLE
        New-ForensicWorkflowOrchestrator -OrchestratorName "IncidentResponse" -Workflows @("MemoryAnalysis", "NetworkAnalysis", "FileSystemAnalysis")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrchestratorName,

        [Parameter(Mandatory = $true)]
        [array]$Workflows,

        [Parameter(Mandatory = $false)]
        [hashtable]$Dependencies = @{}
    )

    try {
        $orchestrator = @{
            Name = $OrchestratorName
            Workflows = $Workflows
            Dependencies = $Dependencies
            Created = Get-Date
            Status = "Created"
        }

        # Validate workflows exist
        foreach ($workflow in $Workflows) {
            if (-not $script:WorkflowDefinitions.ContainsKey($workflow)) {
                throw "Workflow '$workflow' not found"
            }
        }

        # Store orchestrator
        $script:AutomationJobs[$OrchestratorName] = $orchestrator

        Write-Host "Created forensic workflow orchestrator: $OrchestratorName" -ForegroundColor Green
        Write-Host "Workflows: $($Workflows -join ', ')" -ForegroundColor Cyan

        return $orchestrator
    }
    catch {
        Write-Error "Failed to create workflow orchestrator: $_"
        return $null
    }
}

function Start-ForensicWorkflowOrchestration {
    <#
    .SYNOPSIS
        Executes a forensic workflow orchestration

    .DESCRIPTION
        Runs orchestrated workflows with proper dependency management
        and parallel execution where possible

    .PARAMETER OrchestratorName
        Name of the orchestrator to execute

    .EXAMPLE
        Start-ForensicWorkflowOrchestration -OrchestratorName "IncidentResponse"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrchestratorName
    )

    try {
        if (-not $script:AutomationJobs.ContainsKey($OrchestratorName)) {
            throw "Orchestrator '$OrchestratorName' not found"
        }

        $orchestrator = $script:AutomationJobs[$OrchestratorName]
        $orchestrator.Status = "Running"

        Write-Host "Starting forensic workflow orchestration: $OrchestratorName" -ForegroundColor Green

        # Simple dependency resolution (can be enhanced)
        $completedWorkflows = @()
        $pendingWorkflows = $orchestrator.Workflows.Clone()

        while ($pendingWorkflows.Count -gt 0) {
            $executableWorkflows = @()

            # Find workflows with satisfied dependencies
            foreach ($workflow in $pendingWorkflows) {
                $dependencies = $orchestrator.Dependencies[$workflow]
                if (-not $dependencies -or ($dependencies | Where-Object { $_ -notin $completedWorkflows }).Count -eq 0) {
                    $executableWorkflows += $workflow
                }
            }

            if ($executableWorkflows.Count -eq 0) {
                throw "Circular dependency detected or unsatisfied dependencies"
            }

            # Execute workflows in parallel
            $jobs = @()
            foreach ($workflow in $executableWorkflows) {
                Write-Host "Starting workflow: $workflow" -ForegroundColor Cyan
                $job = Start-Job -ScriptBlock {
                    param($WorkflowName)
                    try {
                        Start-AutomatedEvidenceCollection -WorkflowName $WorkflowName -Force
                        return @{ Workflow = $WorkflowName; Success = $true }
                    }
                    catch {
                        return @{ Workflow = $WorkflowName; Success = $false; Error = $_.Exception.Message }
                    }
                } -ArgumentList $workflow

                $jobs += @{ Job = $job; Workflow = $workflow }
            }

            # Wait for all jobs to complete
            $jobs | ForEach-Object {
                $result = Receive-Job $_.Job -Wait
                Remove-Job $_.Job

                if ($result.Success) {
                    Write-Host "Workflow '$($result.Workflow)' completed successfully" -ForegroundColor Green
                    $completedWorkflows += $result.Workflow
                }
                else {
                    Write-Host "Workflow '$($result.Workflow)' failed: $($result.Error)" -ForegroundColor Red
                }
            }

            # Remove completed workflows from pending
            $pendingWorkflows = $pendingWorkflows | Where-Object { $_ -notin $completedWorkflows }
        }

        $orchestrator.Status = "Completed"
        Write-Host "Workflow orchestration '$OrchestratorName' completed" -ForegroundColor Green

        return @{ Completed = $completedWorkflows; Status = "Success" }
    }
    catch {
        Write-Error "Failed to execute workflow orchestration: $_"
        $orchestrator.Status = "Failed"
        return @{ Status = "Failed"; Error = $_.Exception.Message }
    }
}

# Automation Monitoring and Management

function Get-AutomationStatus {
    <#
    .SYNOPSIS
        Gets the status of all automation components

    .DESCRIPTION
        Provides comprehensive status information for workflows,
        scheduled tasks, and SIEM integrations

    .EXAMPLE
        Get-AutomationStatus
    #>
    [CmdletBinding()]
    param()

    try {
        $status = @{
            Workflows = $script:WorkflowDefinitions.Values | Select-Object Name, Status, LastRun, Schedule
            ScheduledTasks = Get-ScheduledForensicTasks
            SIEMIntegrations = $script:SIEMIntegrations.Values | Select-Object Type, Server, Status
            Orchestrators = $script:AutomationJobs.Values | Select-Object Name, Status, Workflows
        }

        return $status
    }
    catch {
        Write-Error "Failed to get automation status: $_"
        return $null
    }
}

function Export-AutomationConfiguration {
    <#
    .SYNOPSIS
        Exports automation configuration for backup or migration

    .DESCRIPTION
        Exports all automation configurations to a JSON file

    .PARAMETER OutputPath
        Path to export the configuration

    .EXAMPLE
        Export-AutomationConfiguration -OutputPath "C:\Backup\ForensicAutomation.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "$env:TEMP\ForensicAutomation_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    )

    try {
        $config = @{
            Workflows = $script:WorkflowDefinitions
            ScheduledTasks = $script:ScheduledTasks
            SIEMIntegrations = $script:SIEMIntegrations
            Orchestrators = $script:AutomationJobs
            Exported = Get-Date
        }

        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8

        Write-Host "Automation configuration exported to: $OutputPath" -ForegroundColor Green

        return $OutputPath
    }
    catch {
        Write-Error "Failed to export automation configuration: $_"
        return $null
    }
}

function Import-AutomationConfiguration {
    <#
    .SYNOPSIS
        Imports automation configuration from a backup file

    .DESCRIPTION
        Imports automation configurations from a JSON file

    .PARAMETER InputPath
        Path to the configuration file to import

    .EXAMPLE
        Import-AutomationConfiguration -InputPath "C:\Backup\ForensicAutomation.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )

    try {
        if (-not (Test-Path $InputPath)) {
            throw "Configuration file not found: $InputPath"
        }

        $config = Get-Content -Path $InputPath -Raw | ConvertFrom-Json

        # Import configurations
        if ($config.Workflows) {
            $script:WorkflowDefinitions = @{}
            foreach ($workflow in $config.Workflows.PSObject.Properties) {
                $script:WorkflowDefinitions[$workflow.Name] = $workflow.Value
            }
        }

        if ($config.ScheduledTasks) {
            $script:ScheduledTasks = @{}
            foreach ($task in $config.ScheduledTasks.PSObject.Properties) {
                $script:ScheduledTasks[$task.Name] = $task.Value
            }
        }

        if ($config.SIEMIntegrations) {
            $script:SIEMIntegrations = @{}
            foreach ($integration in $config.SIEMIntegrations.PSObject.Properties) {
                $script:SIEMIntegrations[$integration.Name] = $integration.Value
            }
        }

        if ($config.Orchestrators) {
            $script:AutomationJobs = @{}
            foreach ($orchestrator in $config.Orchestrators.PSObject.Properties) {
                $script:AutomationJobs[$orchestrator.Name] = $orchestrator.Value
            }
        }

        Write-Host "Automation configuration imported from: $InputPath" -ForegroundColor Green
        Write-Host "Imported $($script:WorkflowDefinitions.Count) workflows, $($script:ScheduledTasks.Count) scheduled tasks, $($script:SIEMIntegrations.Count) SIEM integrations, $($script:AutomationJobs.Count) orchestrators" -ForegroundColor Cyan

        return $true
    }
    catch {
        Write-Error "Failed to import automation configuration: $_"
        return $false
    }
}