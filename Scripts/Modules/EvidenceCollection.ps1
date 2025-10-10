# EvidenceCollection.ps1
# Evidence collection functions for secure handling and initial processing

<#
.SYNOPSIS
    Evidence Collection Functions

.DESCRIPTION
    This file contains functions for collecting evidence including:
    - New-EvidenceItem: Creates new evidence items with hashing and chain of custody

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
    Depends on: EvidenceClasses.ps1
#>

function New-EvidenceItem {
    <#
    .SYNOPSIS
        Creates a new evidence item with proper collection and hashing

    .DESCRIPTION
        Collects evidence from a source, calculates cryptographic hashes, and creates proper chain of custody documentation

    .PARAMETER SourcePath
        Path to the source evidence file or directory

    .PARAMETER DestinationPath
        Path where evidence should be stored

    .PARAMETER CaseId
        Associated case identifier

    .PARAMETER Description
        Description of the evidence

    .PARAMETER Type
        Type of evidence (File, Memory, Network, Log, etc.)

    .PARAMETER CollectionMethod
        Method used to collect the evidence

    .PARAMETER CollectedBy
        Person collecting the evidence

    .PARAMETER Tags
        Array of tags to associate with the evidence

    .EXAMPLE
        $evidence = New-EvidenceItem -SourcePath "C:\Malware\sample.exe" -DestinationPath "E:\Evidence" -CaseId "IR-20231008-143022" -Description "Suspicious executable" -Type "File" -CollectedBy "Analyst"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [string]$CaseId,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [ValidateSet("File", "Directory", "Memory", "Network", "Log", "Database", "Registry", "System", "Custom")]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [string]$CollectionMethod = "Manual Collection",

        [Parameter(Mandatory = $false)]
        [string]$CollectedBy = $env:USERNAME,

        [Parameter(Mandatory = $false)]
        [string[]]$Tags = @()
    )

    try {
        Write-Host "Creating evidence item from: $SourcePath" -ForegroundColor Cyan

        # Validate source exists
        if (-not (Test-Path $SourcePath)) {
            throw "Source path does not exist: $SourcePath"
        }

        # Create evidence item
        $evidence = [EvidenceItem]::new()
        $evidence.CaseId = $CaseId
        $evidence.Name = Split-Path $SourcePath -Leaf
        $evidence.Description = $Description
        $evidence.Type = $Type
        $evidence.Source = $SourcePath
        $evidence.OriginalPath = $SourcePath
        $evidence.CollectionMethod = $CollectionMethod
        $evidence.CollectedBy = $CollectedBy
        $evidence.Tags = $Tags

        # Get file information
        $fileInfo = Get-Item $SourcePath
        $evidence.Size = $fileInfo.Length

        # Calculate hashes
        Write-Host "Calculating cryptographic hashes..." -ForegroundColor Gray
        $evidence.HashSHA256 = (Get-FileHash -Path $SourcePath -Algorithm SHA256).Hash
        $evidence.HashSHA1 = (Get-FileHash -Path $SourcePath -Algorithm SHA1).Hash
        $evidence.HashMD5 = (Get-FileHash -Path $SourcePath -Algorithm MD5).Hash

        # Create destination path
        $evidenceFileName = "$($evidence.EvidenceId)_$($evidence.Name)"
        $evidence.Path = Join-Path $DestinationPath $evidenceFileName
        $evidence.StorageLocation = $DestinationPath

        # Ensure destination directory exists
        $destDir = Split-Path $evidence.Path -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        # Copy evidence to secure location
        Write-Host "Copying evidence to secure storage..." -ForegroundColor Gray
        Copy-Item -Path $SourcePath -Destination $evidence.Path -Force

        # Verify copy integrity
        $copiedHash = (Get-FileHash -Path $evidence.Path -Algorithm SHA256).Hash
        if ($copiedHash -ne $evidence.HashSHA256) {
            throw "Evidence copy integrity check failed"
        }

        # Add initial chain of custody entry
        $cocEntry = [ChainOfCustodyEntry]::new()
        $cocEntry.Action = "Collected"
        $cocEntry.PerformedBy = $CollectedBy
        $cocEntry.FromLocation = $SourcePath
        $cocEntry.ToLocation = $evidence.Path
        $cocEntry.Reason = "Initial evidence collection"
        $cocEntry.AuthorizedBy = $CollectedBy
        $cocEntry.AdditionalInfo["CollectionMethod"] = $CollectionMethod
        $cocEntry.AdditionalInfo["OriginalHash"] = $evidence.HashSHA256

        $evidence.ChainOfCustody += $cocEntry
        $evidence.IsVerified = $true
        $evidence.LastVerified = Get-Date

        # Set metadata
        $evidence.Metadata["OriginalFileName"] = $evidence.Name
        $evidence.Metadata["OriginalPath"] = $SourcePath
        $evidence.Metadata["FileExtension"] = [System.IO.Path]::GetExtension($SourcePath)
        $evidence.Metadata["Created"] = $fileInfo.CreationTime
        $evidence.Metadata["Modified"] = $fileInfo.LastWriteTime
        $evidence.Metadata["Accessed"] = $fileInfo.LastAccessTime

        Write-Host "Evidence item created successfully: $($evidence.EvidenceId)" -ForegroundColor Green
        return $evidence
    }
    catch {
        Write-Error "Failed to create evidence item: $($_.Exception.Message)"
        return $null
    }
}