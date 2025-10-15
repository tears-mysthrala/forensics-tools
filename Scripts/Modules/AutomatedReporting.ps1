# AutomatedReporting.ps1 - Automated report generation functions

<#
.SYNOPSIS
    Automated Reporting Functions for Forensic Analysis

.DESCRIPTION
    This module provides automated report generation, scheduling, and email functions.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

# Import split modules
. "$PSScriptRoot\AutomatedReportGeneration.ps1"
. "$PSScriptRoot\AutomatedReportScheduling.ps1"
. "$PSScriptRoot\AutomatedReportEmail.ps1"