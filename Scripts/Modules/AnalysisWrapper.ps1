# AnalysisWrapper.ps1 - Single-command analysis wrapper functions

<#
.SYNOPSIS
    Analysis Wrapper Functions for Forensic Analysis

.DESCRIPTION
    This module provides single-command analysis wrapper functions for forensic investigations.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

# Import split modules
. "$PSScriptRoot\LiveSystemStatus.ps1"
. "$PSScriptRoot\SystemAnalysis.ps1"
. "$PSScriptRoot\NetworkAnalysis.ps1"
. "$PSScriptRoot\FileSystemAnalysis.ps1"
. "$PSScriptRoot\SecurityAnalysis.ps1"
. "$PSScriptRoot\QuickForensicScan.ps1"
. "$PSScriptRoot\ForensicWorkflow.ps1"