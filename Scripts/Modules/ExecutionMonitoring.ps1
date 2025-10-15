# ExecutionMonitoring.ps1
# Incident response execution and monitoring functions

<#
.SYNOPSIS
    Execution and Monitoring Functions for Incident Response

.DESCRIPTION
    This module provides functions for executing incident response playbooks,
    monitoring for incidents, and generating comprehensive reports.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

# Import split modules
. "$PSScriptRoot\ResponseClasses.ps1"
. "$PSScriptRoot\PlaybookExecution.ps1"
. "$PSScriptRoot\StandardPlaybooks.ps1"
. "$PSScriptRoot\IncidentMonitoring.ps1"
. "$PSScriptRoot\ResponseReporting.ps1"