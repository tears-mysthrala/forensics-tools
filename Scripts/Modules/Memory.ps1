# Memory.ps1 - Memory analysis functions

<#
.SYNOPSIS
    Memory Analysis Functions for Forensic Analysis

.DESCRIPTION
    This module provides memory analysis, dumping, and forensic tool setup functions.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

# Import split modules
. "$PSScriptRoot\SystemMemoryDump.ps1"
. "$PSScriptRoot\SystemVolatilityAnalysis.ps1"
. "$PSScriptRoot\ForensicToolsInstallation.ps1"
. "$PSScriptRoot\PythonForensicsTools.ps1"