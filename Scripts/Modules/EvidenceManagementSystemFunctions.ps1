# EvidenceManagementSystemFunctions.ps1
# Evidence management system with secure handling, chain of custody tracking, and integrity verification

<#
.SYNOPSIS
    Evidence Management System Functions

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

# Evidence Collection Functions

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

function Verify-EvidenceIntegrity {
    <#
    .SYNOPSIS
        Verifies the integrity of evidence files

    .DESCRIPTION
        Recalculates hashes and compares with stored values to ensure evidence hasn't been tampered with

    .PARAMETER Evidence
        The evidence item to verify

    .PARAMETER UpdateVerification
        Whether to update the verification timestamp

    .EXAMPLE
        $isValid = Verify-EvidenceIntegrity -Evidence $evidence
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [EvidenceItem]$Evidence,

        [Parameter(Mandatory = $false)]
        [switch]$UpdateVerification
    )

    try {
        Write-Host "Verifying evidence integrity: $($Evidence.EvidenceId)" -ForegroundColor Cyan

        # Check if evidence file exists
        if (-not (Test-Path $Evidence.Path)) {
            Write-Warning "Evidence file not found: $($Evidence.Path)"
            $Evidence.IsVerified = $false
            return $false
        }

        # Recalculate hashes
        $currentSHA256 = (Get-FileHash -Path $Evidence.Path -Algorithm SHA256).Hash
        $currentSHA1 = (Get-FileHash -Path $Evidence.Path -Algorithm SHA1).Hash
        $currentMD5 = (Get-FileHash -Path $Evidence.Path -Algorithm MD5).Hash

        # Compare hashes
        $isValid = ($currentSHA256 -eq $Evidence.HashSHA256) -and
                   ($currentSHA1 -eq $Evidence.HashSHA1) -and
                   ($currentMD5 -eq $Evidence.HashMD5)

        if ($isValid) {
            Write-Host "Evidence integrity verified successfully" -ForegroundColor Green
            $Evidence.IsVerified = $true
            if ($UpdateVerification) {
                $Evidence.LastVerified = Get-Date
            }
        } else {
            Write-Warning "Evidence integrity check FAILED!"
            $Evidence.IsVerified = $false

            # Log the discrepancy
            $discrepancy = [PSCustomObject]@{
                Timestamp = Get-Date
                EvidenceId = $Evidence.EvidenceId
                StoredSHA256 = $Evidence.HashSHA256
                CurrentSHA256 = $currentSHA256
                StoredSHA1 = $Evidence.HashSHA1
                CurrentSHA1 = $currentSHA1
                StoredMD5 = $Evidence.HashMD5
                CurrentMD5 = $currentMD5
            }

            Write-Warning "Hash discrepancy detected. Evidence may have been tampered with."
        }

        return $isValid
    }
    catch {
        Write-Error "Failed to verify evidence integrity: $($_.Exception.Message)"
        $Evidence.IsVerified = $false
        return $false
    }
}

# Evidence Repository Functions

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

# Evidence Analysis and Reporting Functions

function Export-EvidenceReport {
    <#
    .SYNOPSIS
        Generates a comprehensive evidence report

    .DESCRIPTION
        Creates detailed HTML reports for evidence items including metadata, chain of custody, and integrity information

    .PARAMETER Evidence
        Array of evidence items to include

    .PARAMETER OutputPath
        Path for the HTML report

    .PARAMETER IncludeChainOfCustody
        Whether to include full chain of custody details

    .EXAMPLE
        Export-EvidenceReport -Evidence $evidenceItems -OutputPath "C:\Reports\evidence-report.html" -IncludeChainOfCustody
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeChainOfCustody
    )

    try {
        Write-Host "Generating evidence report for $($Evidence.Count) items..." -ForegroundColor Cyan

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>🔐 Evidence Management Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .evidence-card { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .evidence-header { background: #3498db; color: white; padding: 15px; margin: 0; }
        .evidence-content { padding: 20px; }
        .evidence-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; color: #3498db; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .hash-section { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .status-verified { background-color: #27ae60; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-unverified { background-color: #e74c3c; color: white; padding: 2px 6px; border-radius: 3px; }
        .coc-timeline { position: relative; padding-left: 30px; }
        .coc-entry { margin-bottom: 15px; padding: 10px; border-left: 3px solid #3498db; background-color: #ecf0f1; }
        .coc-entry:before { content: '📋'; position: absolute; left: -5px; background: white; border-radius: 50%; width: 20px; height: 20px; text-align: center; line-height: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Evidence Management Report</h1>
        <h2>Chain of Custody & Integrity Verification</h2>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | <strong>Total Items:</strong> $($Evidence.Count)</p>
    </div>

    <div class="evidence-grid">
        <div class="metric">
            <h3>Total Evidence</h3>
            <div class="value">$($Evidence.Count)</div>
        </div>
        <div class="metric">
            <h3>Verified Items</h3>
            <div class="value">$($Evidence | Where-Object { $_.IsVerified }).Count)</div>
        </div>
        <div class="metric">
            <h3>Total Size</h3>
            <div class="value">$([math]::Round(($Evidence | Measure-Object -Property Size -Sum).Sum / 1MB, 2)) MB</div>
        </div>
        <div class="metric">
            <h3>Cases</h3>
            <div class="value">$($Evidence | Select-Object -Property CaseId -Unique | Measure-Object).Count</div>
        </div>
    </div>
"@

        foreach ($item in $Evidence) {
            $statusClass = $item.IsVerified ? "status-verified" : "status-unverified"
            $statusText = $item.IsVerified ? "Verified" : "Unverified"

            $html += @"

    <div class="evidence-card">
        <h2 class="evidence-header">📄 $($item.Name) - $($item.EvidenceId)</h2>
        <div class="evidence-content">
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Case ID</td><td>$($item.CaseId)</td></tr>
                <tr><td>Description</td><td>$($item.Description)</td></tr>
                <tr><td>Type</td><td>$($item.Type)</td></tr>
                <tr><td>Status</td><td><span class="$statusClass">$statusText</span></td></tr>
                <tr><td>Size</td><td>$([math]::Round($item.Size / 1MB, 2)) MB</td></tr>
                <tr><td>Collected</td><td>$($item.Collected.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
                <tr><td>Collected By</td><td>$($item.CollectedBy)</td></tr>
                <tr><td>Last Verified</td><td>$($item.LastVerified.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
                <tr><td>Source</td><td>$($item.Source)</td></tr>
                <tr><td>Storage Location</td><td>$($item.StorageLocation)</td></tr>
            </table>

            <div class="hash-section">
                <h4>🔒 Cryptographic Hashes</h4>
                <strong>SHA256:</strong> $($item.HashSHA256)<br>
                <strong>SHA1:</strong> $($item.HashSHA1)<br>
                <strong>MD5:</strong> $($item.HashMD5)
            </div>
"@

            if ($IncludeChainOfCustody -and $item.ChainOfCustody -and $item.ChainOfCustody.Count -gt 0) {
                $html += @"
            <h4>⛓️ Chain of Custody</h4>
            <div class="coc-timeline">
"@

                foreach ($coc in $item.ChainOfCustody | Sort-Object Timestamp) {
                    $html += @"
                <div class="coc-entry">
                    <strong>$($coc.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</strong><br>
                    <strong>Action:</strong> $($coc.Action)<br>
                    <strong>Performed By:</strong> $($coc.PerformedBy)<br>
                    <strong>Reason:</strong> $($coc.Reason)<br>
"@

                    if ($coc.FromLocation) {
                        $html += "<strong>From:</strong> $($coc.FromLocation)<br>"
                    }
                    if ($coc.ToLocation) {
                        $html += "<strong>To:</strong> $($coc.ToLocation)<br>"
                    }
                    if ($coc.AuthorizedBy -and $coc.AuthorizedBy -ne $coc.PerformedBy) {
                        $html += "<strong>Authorized By:</strong> $($coc.AuthorizedBy)<br>"
                    }

                    $html += @"
                </div>
"@
                }

                $html += @"
            </div>
"@
            }

            if ($item.Tags -and $item.Tags.Count -gt 0) {
                $html += @"
            <h4>🏷️ Tags</h4>
            <p>$($item.Tags -join ", ")</p>
"@
            }

            $html += @"
        </div>
    </div>
"@
        }

        $html += @"
</body>
</html>
"@

        $html | Out-File $OutputPath -Encoding UTF8

        Write-Host "Evidence report generated: $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to generate evidence report: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-EvidenceAudit {
    <#
    .SYNOPSIS
        Performs a comprehensive audit of evidence integrity

    .DESCRIPTION
        Audits all evidence in a repository or collection for integrity and chain of custody compliance

    .PARAMETER Evidence
        Array of evidence items to audit

    .PARAMETER Repository
        Repository to audit (alternative to Evidence parameter)

    .PARAMETER OutputPath
        Path for the audit report

    .EXAMPLE
        Invoke-EvidenceAudit -Evidence $evidenceItems -OutputPath "C:\Reports\evidence-audit.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$Evidence,

        [Parameter(Mandatory = $false)]
        [EvidenceRepository]$Repository,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Performing evidence integrity audit..." -ForegroundColor Cyan

        # Get evidence to audit
        if ($Repository) {
            $evidenceToAudit = @()
            foreach ($evidenceId in $Repository.EvidenceItems) {
                $evidence = Get-EvidenceFromRepository -Repository $Repository -EvidenceId $evidenceId
                if ($evidence) {
                    $evidenceToAudit += $evidence
                }
            }
        } elseif ($Evidence) {
            $evidenceToAudit = $Evidence
        } else {
            throw "Either Evidence or Repository parameter must be specified"
        }

        $auditResults = @()
        $totalItems = $evidenceToAudit.Count
        $verifiedItems = 0
        $failedItems = 0
        $missingItems = 0

        foreach ($item in $evidenceToAudit) {
            $auditResult = [PSCustomObject]@{
                EvidenceId = $item.EvidenceId
                Name = $item.Name
                IntegrityVerified = $false
                FileExists = $false
                ChainOfCustodyComplete = $false
                LastAudit = Get-Date
                Issues = @()
            }

            # Check if file exists
            if (Test-Path $item.Path) {
                $auditResult.FileExists = $true

                # Verify integrity
                $isValid = Verify-EvidenceIntegrity -Evidence $item
                $auditResult.IntegrityVerified = $isValid

                if ($isValid) {
                    $verifiedItems++
                } else {
                    $failedItems++
                    $auditResult.Issues += "Integrity verification failed"
                }
            } else {
                $missingItems++
                $auditResult.Issues += "Evidence file not found"
            }

            # Check chain of custody
            if ($item.ChainOfCustody -and $item.ChainOfCustody.Count -gt 0) {
                $auditResult.ChainOfCustodyComplete = $true
            } else {
                $auditResult.Issues += "Incomplete chain of custody"
            }

            $auditResults += $auditResult
        }

        # Generate audit report
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>🔍 Evidence Integrity Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; }
        .metric .value-good { color: #27ae60; }
        .metric .value-warning { color: #f39c12; }
        .metric .value-bad { color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #34495e; color: white; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .status-good { background-color: #27ae60; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-warning { background-color: #f39c12; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-bad { background-color: #e74c3c; color: white; padding: 2px 6px; border-radius: 3px; }
        .issues { color: #e74c3c; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Evidence Integrity Audit Report</h1>
        <h2>Security & Compliance Verification</h2>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | <strong>Total Items Audited:</strong> $totalItems</p>
    </div>

    <div class="summary-grid">
        <div class="metric">
            <h3>Verified Items</h3>
            <div class="value value-good">$verifiedItems</div>
        </div>
        <div class="metric">
            <h3>Failed Items</h3>
            <div class="value value-bad">$failedItems</div>
        </div>
        <div class="metric">
            <h3>Missing Items</h3>
            <div class="value value-warning">$missingItems</div>
        </div>
        <div class="metric">
            <h3>Success Rate</h3>
            <div class="value $(if (($verifiedItems / $totalItems) -gt 0.95) { 'value-good' } elseif (($verifiedItems / $totalItems) -gt 0.80) { 'value-warning' } else { 'value-bad' })">$([math]::Round(($verifiedItems / $totalItems) * 100, 1))%</div>
        </div>
    </div>

    <table>
        <tr>
            <th>Evidence ID</th>
            <th>Name</th>
            <th>File Exists</th>
            <th>Integrity</th>
            <th>Chain of Custody</th>
            <th>Issues</th>
        </tr>
"@

        foreach ($result in $auditResults) {
            $fileStatus = $result.FileExists ? "<span class='status-good'>Yes</span>" : "<span class='status-bad'>No</span>"
            $integrityStatus = $result.IntegrityVerified ? "<span class='status-good'>Verified</span>" : "<span class='status-bad'>Failed</span>"
            $cocStatus = $result.ChainOfCustodyComplete ? "<span class='status-good'>Complete</span>" : "<span class='status-warning'>Incomplete</span>"
            $issues = $result.Issues -join "; "

            $html += @"
        <tr>
            <td>$($result.EvidenceId)</td>
            <td>$($result.Name)</td>
            <td>$fileStatus</td>
            <td>$integrityStatus</td>
            <td>$cocStatus</td>
            <td class="issues">$issues</td>
        </tr>
"@
        }

        $html += @"
    </table>
</body>
</html>
"@

        $html | Out-File $OutputPath -Encoding UTF8

        Write-Host "Evidence audit completed. Report generated: $OutputPath" -ForegroundColor Green
        Write-Host "Results: $verifiedItems verified, $failedItems failed, $missingItems missing" -ForegroundColor $(if ($failedItems -eq 0 -and $missingItems -eq 0) { "Green" } else { "Yellow" })

        return [PSCustomObject]@{
            TotalItems = $totalItems
            VerifiedItems = $verifiedItems
            FailedItems = $failedItems
            MissingItems = $missingItems
            SuccessRate = [math]::Round(($verifiedItems / $totalItems) * 100, 2)
            AuditResults = $auditResults
            ReportPath = $OutputPath
        }
    }
    catch {
        Write-Error "Failed to perform evidence audit: $($_.Exception.Message)"
        return $null
    }
}