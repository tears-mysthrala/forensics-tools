# EvidenceClasses.ps1
# Evidence management system classes for secure handling, chain of custody tracking, and integrity verification

<#
.SYNOPSIS
    Evidence Management System Classes

.DESCRIPTION
    This file contains the class definitions for evidence management including:
    - EvidenceItem: Represents individual evidence items
    - ChainOfCustodyEntry: Tracks chain of custody entries
    - EvidenceRepository: Manages evidence repositories

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

# Evidence Management Classes

class EvidenceItem {
    [string]$EvidenceId
    [string]$CaseId
    [string]$Name
    [string]$Description
    [string]$Type
    [string]$Source
    [string]$Path
    [string]$OriginalPath
    [long]$Size
    [string]$HashSHA256
    [string]$HashSHA1
    [string]$HashMD5
    [DateTime]$Collected
    [string]$CollectedBy
    [string]$CollectionMethod
    [array]$ChainOfCustody
    [hashtable]$Metadata
    [array]$Tags
    [string]$Status
    [DateTime]$LastVerified
    [bool]$IsVerified
    [string]$StorageLocation
    [string]$AccessLevel

    EvidenceItem() {
        $this.EvidenceId = "EVID-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff")
        $this.Collected = Get-Date
        $this.LastVerified = Get-Date
        $this.ChainOfCustody = @()
        $this.Metadata = @{}
        $this.Tags = @()
        $this.Status = "Collected"
        $this.IsVerified = $false
        $this.AccessLevel = "Restricted"
    }
}

class ChainOfCustodyEntry {
    [string]$EntryId
    [DateTime]$Timestamp
    [string]$Action
    [string]$PerformedBy
    [string]$FromLocation
    [string]$ToLocation
    [string]$Reason
    [string]$AuthorizedBy
    [hashtable]$AdditionalInfo

    ChainOfCustodyEntry() {
        $this.EntryId = "COC-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff")
        $this.Timestamp = Get-Date
        $this.AdditionalInfo = @{}
    }
}

class EvidenceRepository {
    [string]$RepositoryId
    [string]$Name
    [string]$Description
    [string]$Path
    [string]$Type
    [hashtable]$Configuration
    [array]$EvidenceItems
    [DateTime]$Created
    [string]$CreatedBy
    [bool]$IsEncrypted
    [string]$EncryptionMethod
    [array]$AccessControl

    EvidenceRepository() {
        $this.RepositoryId = "REPO-" + (Get-Date -Format "yyyyMMdd-HHmmss")
        $this.Created = Get-Date
        $this.EvidenceItems = @()
        $this.Configuration = @{}
        $this.AccessControl = @()
        $this.IsEncrypted = $false
    }
}