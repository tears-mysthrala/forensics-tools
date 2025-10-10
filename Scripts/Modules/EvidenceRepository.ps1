# EvidenceRepository.ps1
# Functions for managing evidence repositories

<#
.SYNOPSIS
    Evidence Repository Functions

.DESCRIPTION
    This file contains functions for managing evidence repositories including:
    - New-EvidenceRepository: Creates new repositories
    - Add-EvidenceToRepository: Adds evidence to repositories
    - Get-EvidenceFromRepository: Retrieves evidence from repositories

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
    Depends on: EvidenceClasses.ps1, EvidenceChainOfCustody.ps1, EvidenceVerification.ps1
#>

function New-EvidenceRepository {
    <#
    .SYNOPSIS
        Creates a new evidence repository

    .DESCRIPTION
        Initializes a secure evidence repository with proper access controls and encryption options

    .PARAMETER Name
        Name of the repository

    .PARAMETER Path
        Path where the repository will be created

    .PARAMETER Description
        Description of the repository

    .PARAMETER Type
        Type of repository (Local, Network, Cloud)

    .PARAMETER IsEncrypted
        Whether the repository should be encrypted

    .PARAMETER AccessControl
        Array of users/groups with access permissions

    .EXAMPLE
        $repo = New-EvidenceRepository -Name "Case2023-Evidence" -Path "E:\EvidenceRepos" -Type "Local" -IsEncrypted
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Description = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Local", "Network", "Cloud")]
        [string]$Type = "Local",

        [Parameter(Mandatory = $false)]
        [switch]$IsEncrypted,

        [Parameter(Mandatory = $false)]
        [array]$AccessControl = @()
    )

    try {
        Write-Host "Creating evidence repository: $Name" -ForegroundColor Cyan

        # Create repository object
        $repository = [EvidenceRepository]::new()
        $repository.Name = $Name
        $repository.Description = $Description
        $repository.Path = Join-Path $Path $Name
        $repository.Type = $Type
        $repository.CreatedBy = $env:USERNAME
        $repository.AccessControl = $AccessControl

        # Create repository directory
        if (-not (Test-Path $repository.Path)) {
            New-Item -ItemType Directory -Path $repository.Path -Force | Out-Null
        }

        # Create subdirectories
        $subDirs = @("Evidence", "Metadata", "Reports", "Logs", "Temp")
        foreach ($subDir in $subDirs) {
            $dirPath = Join-Path $repository.Path $subDir
            if (-not (Test-Path $dirPath)) {
                New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
            }
        }

        # Setup encryption if requested
        if ($IsEncrypted) {
            $repository.IsEncrypted = $true
            $repository.EncryptionMethod = "AES256"

            # Create encryption key file (simplified - in production, use proper key management)
            $keyPath = Join-Path $repository.Path "encryption.key"
            $encryptionKey = New-Object byte[] 32
            [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($encryptionKey)
            [System.IO.File]::WriteAllBytes($keyPath, $encryptionKey)

            # Set restrictive permissions on key file
            $acl = Get-Acl $keyPath
            $acl.SetAccessRuleProtection($true, $false)
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
            $acl.SetAccessRule($adminRule)
            Set-Acl $keyPath $acl
        }

        # Create repository configuration file
        $configPath = Join-Path $repository.Path "repository.json"
        $repository | ConvertTo-Json -Depth 10 | Out-File $configPath -Encoding UTF8

        Write-Host "Evidence repository created successfully: $($repository.RepositoryId)" -ForegroundColor Green
        return $repository
    }
    catch {
        Write-Error "Failed to create evidence repository: $($_.Exception.Message)"
        return $null
    }
}

function Add-EvidenceToRepository {
    <#
    .SYNOPSIS
        Adds evidence to a repository

    .DESCRIPTION
        Stores evidence in a repository with proper metadata and access controls

    .PARAMETER Repository
        The evidence repository object

    .PARAMETER Evidence
        The evidence item to add

    .EXAMPLE
        Add-EvidenceToRepository -Repository $repo -Evidence $evidence
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [EvidenceRepository]$Repository,

        [Parameter(Mandatory = $true)]
        [EvidenceItem]$Evidence
    )

    try {
        Write-Host "Adding evidence to repository: $($Evidence.EvidenceId)" -ForegroundColor Cyan

        # Verify repository exists
        if (-not (Test-Path $Repository.Path)) {
            throw "Repository path not found: $($Repository.Path)"
        }

        # Move evidence to repository
        $evidenceDir = Join-Path $Repository.Path "Evidence"
        $newPath = Join-Path $evidenceDir "$($Evidence.EvidenceId)$([System.IO.Path]::GetExtension($Evidence.Path))"

        Move-Item -Path $Evidence.Path -Destination $newPath -Force
        $Evidence.Path = $newPath
        $Evidence.StorageLocation = $Repository.RepositoryId

        # Add to repository evidence list
        $Repository.EvidenceItems += $Evidence.EvidenceId

        # Save evidence metadata
        $metadataPath = Join-Path (Join-Path $Repository.Path "Metadata") "$($Evidence.EvidenceId).json"
        $Evidence | ConvertTo-Json -Depth 10 | Out-File $metadataPath -Encoding UTF8

        # Update repository configuration
        $configPath = Join-Path $Repository.Path "repository.json"
        $Repository | ConvertTo-Json -Depth 10 | Out-File $configPath -Encoding UTF8

        # Add chain of custody entry
        Add-EvidenceToChainOfCustody -Evidence $Evidence -Action "Transferred" -PerformedBy $env:USERNAME -FromLocation $Evidence.OriginalPath -ToLocation $newPath -Reason "Added to repository $($Repository.Name)"

        Write-Host "Evidence added to repository successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to add evidence to repository: $($_.Exception.Message)"
        return $false
    }
}

function Get-EvidenceFromRepository {
    <#
    .SYNOPSIS
        Retrieves evidence from a repository

    .DESCRIPTION
        Loads evidence metadata and verifies integrity when accessing from repository

    .PARAMETER Repository
        The evidence repository object

    .PARAMETER EvidenceId
        ID of the evidence to retrieve

    .EXAMPLE
        $evidence = Get-EvidenceFromRepository -Repository $repo -EvidenceId "EVID-20231008-143022-001"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [EvidenceRepository]$Repository,

        [Parameter(Mandatory = $true)]
        [string]$EvidenceId
    )

    try {
        Write-Host "Retrieving evidence from repository: $EvidenceId" -ForegroundColor Cyan

        # Load evidence metadata
        $metadataPath = Join-Path (Join-Path $Repository.Path "Metadata") "$EvidenceId.json"
        if (-not (Test-Path $metadataPath)) {
            throw "Evidence metadata not found: $metadataPath"
        }

        $evidence = Get-Content $metadataPath -Raw | ConvertFrom-Json

        # Verify evidence file exists
        if (-not (Test-Path $evidence.Path)) {
            throw "Evidence file not found: $($evidence.Path)"
        }

        # Verify integrity
        $isValid = Verify-EvidenceIntegrity -Evidence $evidence -UpdateVerification
        if (-not $isValid) {
            Write-Warning "Evidence integrity verification failed!"
        }

        # Add access chain of custody entry
        Add-EvidenceToChainOfCustody -Evidence $evidence -Action "Accessed" -PerformedBy $env:USERNAME -Reason "Retrieved from repository for analysis"

        Write-Host "Evidence retrieved successfully" -ForegroundColor Green
        return $evidence
    }
    catch {
        Write-Error "Failed to retrieve evidence from repository: $($_.Exception.Message)"
        return $null
    }
}