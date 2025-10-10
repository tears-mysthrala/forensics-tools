# Automation.psm1 - Forensic Automation and Orchestration Module

# Import all automation functions
. "$PSScriptRoot\EvidenceCollectionWorkflowFunctions.ps1"
. "$PSScriptRoot\ScheduledTaskFunctions.ps1"
. "$PSScriptRoot\SIEMIntegrationFunctions.ps1"
. "$PSScriptRoot\WorkflowOrchestrationFunctions.ps1"
. "$PSScriptRoot\AutomationManagementFunctions.ps1"

# Export functions
Export-ModuleMember -Function @(
    'New-AutomatedEvidenceCollectionWorkflow',
    'Start-AutomatedEvidenceCollection',
    'New-ScheduledForensicTask',
    'Get-ScheduledForensicTasks',
    'New-SIEMIntegration',
    'Send-SIEMAlert',
    'New-ForensicWorkflowOrchestrator',
    'Start-ForensicWorkflowOrchestration',
    'Get-AutomationStatus',
    'Export-AutomationConfiguration',
    'Import-AutomationConfiguration'
)