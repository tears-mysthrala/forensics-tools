# EvidenceCorrelationDashboard.ps1
# Main dashboard creation function for evidence correlation

<#
.SYNOPSIS
    Evidence Correlation Dashboard Functions

.DESCRIPTION
    This module provides the main function for creating evidence correlation dashboards.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function New-EvidenceCorrelationDashboard {
    <#
    .SYNOPSIS
        Creates an evidence correlation dashboard.
    .DESCRIPTION
        Generates an interactive dashboard showing correlations between different types of evidence.
    .PARAMETER EvidenceData
        Collection of evidence data from various sources.
    .PARAMETER OutputPath
        Directory to save the correlation dashboard.
    .PARAMETER Title
        Title of the dashboard.
    .EXAMPLE
        New-EvidenceCorrelationDashboard -EvidenceData $evidence -OutputPath C:\Reports -Title "Evidence Correlation"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$EvidenceData,
        [string]$OutputPath = ".",
        [string]$Title = "Evidence Correlation Dashboard"
    )

    Write-Host "Creating evidence correlation dashboard..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $dashboardFile = Join-Path $OutputPath "CorrelationDashboard_$timestamp.html"

    # Get HTML template
    $htmlContent = Get-EvidenceCorrelationHTMLTemplate -Title $Title -EvidenceData $EvidenceData

    # Write the correlation dashboard
    $htmlContent | Out-File $dashboardFile -Encoding UTF8

    Write-Host "[OK] Evidence correlation dashboard created: $dashboardFile" -ForegroundColor Green

    # Try to open the dashboard in default browser
    try {
        Start-Process $dashboardFile
        Write-Host "[OK] Dashboard opened in default browser" -ForegroundColor Green
    }
    catch {
        Write-Host "Note: Could not automatically open dashboard. Please open manually: $dashboardFile" -ForegroundColor Yellow
    }

    return $dashboardFile
}