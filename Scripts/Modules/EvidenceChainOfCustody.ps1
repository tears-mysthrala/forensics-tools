# EvidenceChainOfCustody.ps1
# Functions for managing evidence chain of custody

<#
.SYNOPSIS
    Evidence Chain of Custody Functions

.DESCRIPTION
    This file contains functions for managing chain of custody including:
    - Add-EvidenceToChainOfCustody: Adds entries to track evidence actions

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
    Depends on: EvidenceClasses.ps1
#>

function Add-EvidenceToChainOfCustody {
    <#
    .SYNOPSIS
        Adds an entry to the evidence chain of custody

    .DESCRIPTION
        Documents any action performed on evidence including transfers, analysis, or access

    .PARAMETER Evidence
        The evidence item object

    .PARAMETER Action
        Action performed (Transferred, Analyzed, Accessed, Copied, etc.)

    .PARAMETER PerformedBy
        Person performing the action

    .PARAMETER FromLocation
        Source location (if applicable)

    .PARAMETER ToLocation
        Destination location (if applicable)

    .PARAMETER Reason
        Reason for the action

    .PARAMETER AuthorizedBy
        Person authorizing the action

    .EXAMPLE
        Add-EvidenceToChainOfCustody -Evidence $evidence -Action "Analyzed" -PerformedBy "Analyst" -Reason "Malware analysis"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [EvidenceItem]$Evidence,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Collected", "Transferred", "Analyzed", "Accessed", "Copied", "Archived", "Destroyed", "Returned", "Custom")]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$PerformedBy,

        [Parameter(Mandatory = $false)]
        [string]$FromLocation,

        [Parameter(Mandatory = $false)]
        [string]$ToLocation,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [Parameter(Mandatory = $false)]
        [string]$AuthorizedBy = $PerformedBy
    )

    try {
        $cocEntry = [ChainOfCustodyEntry]::new()
        $cocEntry.Action = $Action
        $cocEntry.PerformedBy = $PerformedBy
        $cocEntry.FromLocation = $FromLocation
        $cocEntry.ToLocation = $ToLocation
        $cocEntry.Reason = $Reason
        $cocEntry.AuthorizedBy = $AuthorizedBy

        $Evidence.ChainOfCustody += $cocEntry
        $Evidence.LastVerified = Get-Date

        Write-Host "Added chain of custody entry: $Action by $PerformedBy" -ForegroundColor Green
        return $cocEntry
    }
    catch {
        Write-Error "Failed to add chain of custody entry: $($_.Exception.Message)"
        return $null
    }
}