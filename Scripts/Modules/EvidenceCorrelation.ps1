# EvidenceCorrelation.ps1 - Evidence correlation dashboard

<#
.SYNOPSIS
    Evidence Correlation Functions

.DESCRIPTION
    This module provides functions for creating evidence correlation dashboards.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

# Import split modules
. "$PSScriptRoot\EvidenceCorrelationTemplate.ps1"
. "$PSScriptRoot\EvidenceCorrelationDashboard.ps1"

# Note: This file has been split into smaller modules for better maintainability:
# - EvidenceCorrelationTemplate.ps1: Get-EvidenceCorrelationHTMLTemplate
# - EvidenceCorrelationDashboard.ps1: New-EvidenceCorrelationDashboard
