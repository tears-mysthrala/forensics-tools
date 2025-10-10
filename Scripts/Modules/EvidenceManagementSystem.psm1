# EvidenceManagementSystem.psm1
# Evidence Management System Module

<#
.SYNOPSIS
    Evidence Management System Module

.DESCRIPTION
    This module provides comprehensive evidence management capabilities including:
    - Secure evidence collection and storage
    - Chain of custody tracking and documentation
    - Integrity verification with cryptographic hashing
    - Evidence metadata management and tagging
    - Secure evidence transfer and sharing
    - Audit logging and compliance reporting
    - Evidence lifecycle management

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

# Import required modules and classes
. $PSScriptRoot\EvidenceClasses.ps1
. $PSScriptRoot\EvidenceCollection.ps1
. $PSScriptRoot\EvidenceChainOfCustody.ps1
. $PSScriptRoot\EvidenceVerification.ps1
. $PSScriptRoot\EvidenceRepository.ps1
. $PSScriptRoot\EvidenceReporting.ps1
. $PSScriptRoot\EvidenceAudit.ps1

# Export functions
Export-ModuleMember -Function New-EvidenceItem, Add-EvidenceToChainOfCustody, Verify-EvidenceIntegrity, New-EvidenceRepository, Add-EvidenceToRepository, Get-EvidenceFromRepository, Export-EvidenceReport, Invoke-EvidenceAudit