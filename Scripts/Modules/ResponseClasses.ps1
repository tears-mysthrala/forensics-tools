# ResponseClasses.ps1
# Incident response action classes

<#
.SYNOPSIS
    Response Action Classes for Incident Response

.DESCRIPTION
    This module provides classes for defining and managing incident response actions.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

# Incident Response Classes

class ResponseAction {
    [string]$ActionId
    [string]$Name
    [string]$Description
    [string]$Type
    [hashtable]$Parameters
    [string]$Status
    [DateTime]$Executed
    [string]$Result
    [string]$ErrorMessage
    [array]$Dependencies

    ResponseAction() {
        $this.ActionId = "ACTION-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff")
        $this.Status = "Pending"
        $this.Parameters = @{}
        $this.Dependencies = @()
    }
}