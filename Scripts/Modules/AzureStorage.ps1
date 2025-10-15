function Get-AzureStorageAnalysis {
    <#
    .SYNOPSIS
        Analyzes Azure Storage accounts for forensic artifacts.
    .DESCRIPTION
        Examines Azure Storage accounts, containers, blobs, and access patterns.
    .PARAMETER StorageAccountName
        Name of the storage account to analyze.
    .PARAMETER ResourceGroup
        Resource group containing the storage account.
    .PARAMETER OutputPath
        Directory to save analysis results.
    .EXAMPLE
        Get-AzureStorageAnalysis -StorageAccountName "mystorage" -ResourceGroup "myrg" -OutputPath C:\StorageAnalysis
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,
        [string]$OutputPath = "."
    )

    Write-Host "Analyzing Azure Storage account $StorageAccountName..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "AzureStorageAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $storageResults = @{
        Timestamp      = Get-Date
        StorageAccount = $StorageAccountName
        ResourceGroup  = $ResourceGroup
        Containers     = @()
        Blobs          = @()
        AccessPatterns = @()
    }

    # Check Azure CLI
    $azCli = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCli) {
        Write-Error "Azure CLI required for storage analysis. Please install from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        return $null
    }

    try {
        # Get storage account key
        $keyOutput = az storage account keys list --account-name $StorageAccountName --resource-group $ResourceGroup --output json | ConvertFrom-Json
        $storageKey = $keyOutput[0].value

        # List containers
        Write-Host "Listing storage containers..." -ForegroundColor Yellow
        $containersOutput = az storage container list --account-name $StorageAccountName --account-key $storageKey --output json | ConvertFrom-Json

        foreach ($container in $containersOutput) {
            $containerInfo = @{
                Name         = $container.name
                LastModified = $container.lastModified
                LeaseStatus  = $container.leaseStatus
                PublicAccess = $container.publicAccess
                BlobCount    = 0
                TotalSize    = 0
            }

            # List blobs in container
            try {
                $blobsOutput = az storage blob list --container-name $container.name --account-name $StorageAccountName --account-key $storageKey --output json | ConvertFrom-Json

                $containerInfo.BlobCount = $blobsOutput.Count
                $containerInfo.TotalSize = ($blobsOutput | Measure-Object -Property size -Sum).Sum

                # Analyze blobs
                foreach ($blob in $blobsOutput) {
                    $storageResults.Blobs += @{
                        Container    = $container.name
                        Name         = $blob.name
                        Size         = $blob.size
                        LastModified = $blob.lastModified
                        ContentType  = $blob.contentType
                        ContentMD5   = $blob.contentMD5
                    }
                }

            }
            catch {
                Write-Warning "Failed to list blobs in container $($container.name): $($_.Exception.Message)"
            }

            $storageResults.Containers += $containerInfo
        }

        Write-Host "[OK] Found $($storageResults.Containers.Count) containers with $($storageResults.Blobs.Count) total blobs" -ForegroundColor Green

        # Analyze access patterns (if logging enabled)
        Write-Host "Checking storage analytics..." -ForegroundColor Yellow
        try {
            $analyticsOutput = az storage logging show --account-name $StorageAccountName --account-key $storageKey --output json | ConvertFrom-Json

            if ($analyticsOutput) {
                $storageResults.AccessPatterns = @{
                    Read            = $analyticsOutput.read
                    Write           = $analyticsOutput.write
                    Delete          = $analyticsOutput.delete
                    RetentionPolicy = $analyticsOutput.retentionPolicy
                }
            }
        }
        catch {
            Write-Warning "Storage analytics not available or not enabled: $($_.Exception.Message)"
        }

    }
    catch {
        Write-Warning "Failed to analyze storage account: $($_.Exception.Message)"
        $storageResults.Error = $_.Exception.Message
    }

    # Export results
    $resultsFile = Join-Path $analysisDir "azure_storage_analysis.json"
    $storageResults | ConvertTo-Json -Depth 4 | Out-File $resultsFile

    # Create summary CSVs
    if ($storageResults.Containers) {
        $storageResults.Containers | Export-Csv (Join-Path $analysisDir "storage_containers.csv") -NoTypeInformation
    }

    if ($storageResults.Blobs) {
        $storageResults.Blobs | Export-Csv (Join-Path $analysisDir "storage_blobs.csv") -NoTypeInformation
    }

    Write-Host "Azure Storage analysis complete!" -ForegroundColor Green
    Write-Host "Containers: $($storageResults.Containers.Count)" -ForegroundColor Cyan
    Write-Host "Blobs: $($storageResults.Blobs.Count)" -ForegroundColor Cyan
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}