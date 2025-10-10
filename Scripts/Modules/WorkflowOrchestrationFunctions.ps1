# WorkflowOrchestrationFunctions.ps1 - Forensic workflow orchestration functions

# Global variables for automation
$script:AutomationJobs = @{}

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