# AutomationManagementFunctions.ps1 - Automation monitoring and management functions

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