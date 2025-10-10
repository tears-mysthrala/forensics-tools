# CloudForensicsFunctions.ps1 - Cloud forensics and artifact collection

function Get-AzureResourceInventory {
    <#
    .SYNOPSIS
        Inventories Azure resources for forensic analysis.
    .DESCRIPTION
        Collects information about Azure resources, configurations, and access patterns.
    .PARAMETER SubscriptionId
        Azure subscription ID to analyze.
    .PARAMETER OutputPath
        Directory to save inventory results.
    .PARAMETER ResourceTypes
        Types of resources to inventory (default: all).
    .EXAMPLE
        Get-AzureResourceInventory -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputPath C:\AzureAnalysis
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,
        [string]$OutputPath = ".",
        [string[]]$ResourceTypes = @("Microsoft.Storage/storageAccounts", "Microsoft.Compute/virtualMachines", "Microsoft.Network/virtualNetworks", "Microsoft.KeyVault/vaults")
    )

    Write-Host "Starting Azure resource inventory..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $inventoryDir = Join-Path $OutputPath "AzureInventory_$timestamp"

    if (-not (Test-Path $inventoryDir)) {
        New-Item -ItemType Directory -Path $inventoryDir -Force | Out-Null
    }

    $inventoryResults = @{
        Timestamp = Get-Date
        SubscriptionId = $SubscriptionId
        Resources = @{}
    }

    # Check if Azure CLI is available
    $azCli = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCli) {
        Write-Warning "Azure CLI not found. Please install Azure CLI from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        Write-Host "Attempting to use Azure PowerShell modules..." -ForegroundColor Yellow

        # Check for Azure PowerShell
        $azModules = Get-Module -ListAvailable | Where-Object { $_.Name -like "Az.*" }
        if (-not $azModules) {
            Write-Error "Neither Azure CLI nor Azure PowerShell modules found. Please install one of them."
            return $null
        }
        $usePowerShell = $true
    }

    Write-Host "Connecting to Azure subscription $SubscriptionId..." -ForegroundColor Yellow

    try {
        if ($usePowerShell) {
            # Use Azure PowerShell
            Connect-AzAccount -ErrorAction Stop
            Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        } else {
            # Use Azure CLI
            az login --use-device-code
            az account set --subscription $SubscriptionId
        }

        Write-Host "[OK] Connected to Azure" -ForegroundColor Green

    } catch {
        Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
        return $null
    }

    # Collect resource inventory
    foreach ($resourceType in $ResourceTypes) {
        Write-Host "Inventorying $resourceType resources..." -ForegroundColor Gray

        try {
            $resources = @()

            if ($usePowerShell) {
                # Use Azure PowerShell
                $azResources = Get-AzResource -ResourceType $resourceType
                foreach ($res in $azResources) {
                    $resources += @{
                        Name = $res.Name
                        ResourceGroup = $res.ResourceGroupName
                        Location = $res.Location
                        Type = $res.ResourceType
                        Id = $res.ResourceId
                        Tags = $res.Tags
                        CreatedTime = $res.CreatedTime
                        ChangedTime = $res.ChangedTime
                    }
                }
            } else {
                # Use Azure CLI
                $azOutput = az resource list --resource-type $resourceType --output json | ConvertFrom-Json
                foreach ($res in $azOutput) {
                    $resources += @{
                        Name = $res.name
                        ResourceGroup = $res.resourceGroup
                        Location = $res.location
                        Type = $res.type
                        Id = $res.id
                        Tags = $res.tags
                        CreatedTime = $res.createdTime
                        ChangedTime = $res.changedTime
                    }
                }
            }

            $inventoryResults.Resources[$resourceType] = $resources

            Write-Host "[OK] Found $($resources.Count) $resourceType resources" -ForegroundColor Green

        } catch {
            Write-Warning "Failed to inventory $resourceType resources: $($_.Exception.Message)"
            $inventoryResults.Resources[$resourceType] = "Error: $($_.Exception.Message)"
        }
    }

    # Collect additional Azure information
    Write-Host "Collecting additional Azure information..." -ForegroundColor Yellow

    try {
        $additionalInfo = @{}

        if ($usePowerShell) {
            # Get subscription details
            $subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
            $additionalInfo.Subscription = @{
                Name = $subscription.Name
                State = $subscription.State
                TenantId = $subscription.TenantId
            }

            # Get role assignments
            $roleAssignments = Get-AzRoleAssignment
            $additionalInfo.RoleAssignments = $roleAssignments | Select-Object DisplayName, SignInName, RoleDefinitionName, Scope

        } else {
            # Get subscription details
            $subOutput = az account show --output json | ConvertFrom-Json
            $additionalInfo.Subscription = @{
                Name = $subOutput.name
                State = $subOutput.state
                TenantId = $subOutput.tenantId
            }

            # Get role assignments
            $roleOutput = az role assignment list --output json | ConvertFrom-Json
            $additionalInfo.RoleAssignments = $roleOutput | Select-Object displayName, signInName, roleDefinitionName, scope
        }

        $inventoryResults.AdditionalInfo = $additionalInfo

    } catch {
        Write-Warning "Failed to collect additional Azure information: $($_.Exception.Message)"
    }

    # Export results
    $resultsFile = Join-Path $inventoryDir "azure_inventory.json"
    $inventoryResults | ConvertTo-Json -Depth 4 | Out-File $resultsFile

    # Create summary CSV
    $summaryData = @()
    foreach ($resourceType in $inventoryResults.Resources.Keys) {
        if ($inventoryResults.Resources[$resourceType] -is [array]) {
            foreach ($resource in $inventoryResults.Resources[$resourceType]) {
                $summaryData += [PSCustomObject]@{
                    ResourceType = $resourceType
                    Name = $resource.Name
                    ResourceGroup = $resource.ResourceGroup
                    Location = $resource.Location
                    CreatedTime = $resource.CreatedTime
                    ChangedTime = $resource.ChangedTime
                }
            }
        }
    }

    if ($summaryData) {
        $summaryData | Export-Csv (Join-Path $inventoryDir "azure_resources_summary.csv") -NoTypeInformation
    }

    Write-Host "Azure resource inventory complete!" -ForegroundColor Green
    Write-Host "Resources inventoried: $($summaryData.Count)" -ForegroundColor Cyan
    Write-Host "Results saved to: $inventoryDir" -ForegroundColor Cyan

    return $inventoryDir
}

function Get-AzureActivityLogs {
    <#
    .SYNOPSIS
        Collects Azure activity logs for forensic analysis.
    .DESCRIPTION
        Retrieves Azure activity logs, audit events, and administrative actions.
    .PARAMETER SubscriptionId
        Azure subscription ID.
    .PARAMETER Days
        Number of days of logs to retrieve.
    .PARAMETER OutputPath
        Directory to save log results.
    .EXAMPLE
        Get-AzureActivityLogs -SubscriptionId "12345678-1234-1234-1234-123456789012" -Days 30 -OutputPath C:\AzureLogs
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,
        [int]$Days = 7,
        [string]$OutputPath = "."
    )

    Write-Host "Collecting Azure activity logs..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logsDir = Join-Path $OutputPath "AzureActivityLogs_$timestamp"

    if (-not (Test-Path $logsDir)) {
        New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    }

    $logsResults = @{
        Timestamp = Get-Date
        SubscriptionId = $SubscriptionId
        Days = $Days
        Logs = @()
    }

    # Check Azure CLI
    $azCli = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCli) {
        Write-Error "Azure CLI required for activity log collection. Please install from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        return $null
    }

    try {
        # Set subscription
        az account set --subscription $SubscriptionId

        # Calculate date range
        $endDate = Get-Date
        $startDate = $endDate.AddDays(-$Days)
        $startDateStr = $startDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endDateStr = $endDate.ToString("yyyy-MM-ddTHH:mm:ssZ")

        Write-Host "Retrieving activity logs from $startDateStr to $endDateStr..." -ForegroundColor Yellow

        # Get activity logs
        $logsOutput = az monitor activity-log list --start-time $startDateStr --end-time $endDateStr --output json

        if ($logsOutput) {
            $logs = $logsOutput | ConvertFrom-Json

            foreach ($log in $logs) {
                $logsResults.Logs += @{
                    Timestamp = $log.eventTimestamp
                    Level = $log.level
                    OperationName = $log.operationName
                    ResourceType = $log.resourceType
                    ResourceGroup = $log.resourceGroupName
                    Resource = $log.resource
                    Status = $log.status.value
                    Caller = $log.caller
                    CorrelationId = $log.correlationId
                    Category = $log.category.value
                    Properties = $log.properties
                }
            }

            Write-Host "[OK] Retrieved $($logs.Count) activity log entries" -ForegroundColor Green
        } else {
            Write-Host "[OK] No activity logs found in the specified time range" -ForegroundColor Green
        }

    } catch {
        Write-Warning "Failed to collect activity logs: $($_.Exception.Message)"
        $logsResults.Error = $_.Exception.Message
    }

    # Export results
    $resultsFile = Join-Path $logsDir "azure_activity_logs.json"
    $logsResults | ConvertTo-Json -Depth 4 | Out-File $resultsFile

    # Create summary CSV
    $csvData = $logsResults.Logs | ForEach-Object {
        [PSCustomObject]@{
            Timestamp = $_.Timestamp
            Level = $_.Level
            OperationName = $_.OperationName
            ResourceType = $_.ResourceType
            ResourceGroup = $_.ResourceGroup
            Status = $_.Status
            Caller = $_.Caller
        }
    }

    if ($csvData) {
        $csvData | Export-Csv (Join-Path $logsDir "activity_logs_summary.csv") -NoTypeInformation
    }

    Write-Host "Azure activity logs collection complete!" -ForegroundColor Green
    Write-Host "Log entries: $($logsResults.Logs.Count)" -ForegroundColor Cyan
    Write-Host "Results saved to: $logsDir" -ForegroundColor Cyan

    return $logsDir
}

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
        [Parameter(Mandatory=$true)]
        [string]$StorageAccountName,
        [Parameter(Mandatory=$true)]
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
        Timestamp = Get-Date
        StorageAccount = $StorageAccountName
        ResourceGroup = $ResourceGroup
        Containers = @()
        Blobs = @()
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
                Name = $container.name
                LastModified = $container.lastModified
                LeaseStatus = $container.leaseStatus
                PublicAccess = $container.publicAccess
                BlobCount = 0
                TotalSize = 0
            }

            # List blobs in container
            try {
                $blobsOutput = az storage blob list --container-name $container.name --account-name $StorageAccountName --account-key $storageKey --output json | ConvertFrom-Json

                $containerInfo.BlobCount = $blobsOutput.Count
                $containerInfo.TotalSize = ($blobsOutput | Measure-Object -Property size -Sum).Sum

                # Analyze blobs
                foreach ($blob in $blobsOutput) {
                    $storageResults.Blobs += @{
                        Container = $container.name
                        Name = $blob.name
                        Size = $blob.size
                        LastModified = $blob.lastModified
                        ContentType = $blob.contentType
                        ContentMD5 = $blob.contentMD5
                    }
                }

            } catch {
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
                    Read = $analyticsOutput.read
                    Write = $analyticsOutput.write
                    Delete = $analyticsOutput.delete
                    RetentionPolicy = $analyticsOutput.retentionPolicy
                }
            }
        } catch {
            Write-Warning "Storage analytics not available or not enabled: $($_.Exception.Message)"
        }

    } catch {
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

function Get-AzureVMArtifacts {
    <#
    .SYNOPSIS
        Collects forensic artifacts from Azure Virtual Machines.
    .DESCRIPTION
        Gathers logs, configurations, and other artifacts from Azure VMs.
    .PARAMETER VMName
        Name of the virtual machine.
    .PARAMETER ResourceGroup
        Resource group containing the VM.
    .PARAMETER OutputPath
        Directory to save artifacts.
    .EXAMPLE
        Get-AzureVMArtifacts -VMName "myvm" -ResourceGroup "myrg" -OutputPath C:\VMArtifacts
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMName,
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroup,
        [string]$OutputPath = "."
    )

    Write-Host "Collecting artifacts from Azure VM $VMName..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $artifactsDir = Join-Path $OutputPath "AzureVMArtifacts_$timestamp"

    if (-not (Test-Path $artifactsDir)) {
        New-Item -ItemType Directory -Path $artifactsDir -Force | Out-Null
    }

    $artifactsResults = @{
        Timestamp = Get-Date
        VMName = $VMName
        ResourceGroup = $ResourceGroup
        Artifacts = @{}
    }

    # Check Azure CLI
    $azCli = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCli) {
        Write-Error "Azure CLI required for VM artifact collection. Please install from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        return $null
    }

    try {
        # Get VM information
        Write-Host "Getting VM information..." -ForegroundColor Yellow
        $vmOutput = az vm show --name $VMName --resource-group $ResourceGroup --output json | ConvertFrom-Json

        $artifactsResults.Artifacts.VMInfo = @{
            Name = $vmOutput.name
            Location = $vmOutput.location
            Size = $vmOutput.hardwareProfile.vmSize
            OS = $vmOutput.storageProfile.osDisk.osType
            State = $vmOutput.powerState
            CreatedTime = $vmOutput.timeCreated
            Tags = $vmOutput.tags
        }

        # Get VM extensions
        Write-Host "Getting VM extensions..." -ForegroundColor Yellow
        try {
            $extensionsOutput = az vm extension list --vm-name $VMName --resource-group $ResourceGroup --output json | ConvertFrom-Json
            $artifactsResults.Artifacts.Extensions = $extensionsOutput | Select-Object name, type, publisher, version, settings
        } catch {
            Write-Warning "Failed to get VM extensions: $($_.Exception.Message)"
        }

        # Get VM disks
        Write-Host "Getting VM disks..." -ForegroundColor Yellow
        try {
            $disksOutput = az vm show --name $VMName --resource-group $ResourceGroup --query "storageProfile" --output json | ConvertFrom-Json
            $artifactsResults.Artifacts.Disks = @{
                OSDisk = $disksOutput.osDisk
                DataDisks = $disksOutput.dataDisks
            }
        } catch {
            Write-Warning "Failed to get VM disks: $($_.Exception.Message)"
        }

        # Get VM network interfaces
        Write-Host "Getting VM network configuration..." -ForegroundColor Yellow
        try {
            $nicOutput = az vm show --name $VMName --resource-group $ResourceGroup --query "networkProfile" --output json | ConvertFrom-Json
            $artifactsResults.Artifacts.NetworkInterfaces = $nicOutput.networkInterfaces
        } catch {
            Write-Warning "Failed to get VM network configuration: $($_.Exception.Message)"
        }

        # Get VM logs (if available)
        Write-Host "Checking for VM diagnostic logs..." -ForegroundColor Yellow
        try {
            $logsOutput = az monitor diagnostic-settings list --resource "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$VMName" --output json | ConvertFrom-Json
            $artifactsResults.Artifacts.DiagnosticSettings = $logsOutput
        } catch {
            Write-Warning "Failed to get diagnostic settings: $($_.Exception.Message)"
        }

        Write-Host "[OK] Collected VM artifacts" -ForegroundColor Green

    } catch {
        Write-Warning "Failed to collect VM artifacts: $($_.Exception.Message)"
        $artifactsResults.Error = $_.Exception.Message
    }

    # Export results
    $resultsFile = Join-Path $artifactsDir "azure_vm_artifacts.json"
    $artifactsResults | ConvertTo-Json -Depth 4 | Out-File $resultsFile

    Write-Host "Azure VM artifact collection complete!" -ForegroundColor Green
    Write-Host "Results saved to: $artifactsDir" -ForegroundColor Cyan

    return $artifactsDir
}

function Invoke-AzureCloudForensics {
    <#
    .SYNOPSIS
        Performs comprehensive Azure cloud forensics analysis.
    .DESCRIPTION
        Combines resource inventory, activity logs, storage analysis, and VM artifacts collection.
    .PARAMETER SubscriptionId
        Azure subscription ID to analyze.
    .PARAMETER OutputPath
        Directory to save all analysis results.
    .PARAMETER IncludeStorage
        Whether to include storage account analysis.
    .PARAMETER IncludeVMs
        Whether to include VM artifact collection.
    .EXAMPLE
        Invoke-AzureCloudForensics -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputPath C:\AzureForensics
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,
        [string]$OutputPath = ".",
        [bool]$IncludeStorage = $true,
        [bool]$IncludeVMs = $true
    )

    Write-Host "=== AZURE CLOUD FORENSICS ANALYSIS ===" -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "AzureCloudForensics_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $workflow = @{
        Timestamp = Get-Date
        SubscriptionId = $SubscriptionId
        IncludeStorage = $IncludeStorage
        IncludeVMs = $IncludeVMs
        Steps = @()
        Results = @{}
    }

    # Step 1: Resource Inventory
    Write-Host "`nStep 1: Azure Resource Inventory" -ForegroundColor Yellow
    try {
        $inventoryResults = Get-AzureResourceInventory -SubscriptionId $SubscriptionId -OutputPath $analysisDir
        $workflow.Results.ResourceInventory = $inventoryResults
        $workflow.Steps += "Resource Inventory: Success - $inventoryResults"
        Write-Host "[OK] Resource inventory completed" -ForegroundColor Green
    } catch {
        $workflow.Steps += "Resource Inventory: Error - $($_.Exception.Message)"
        Write-Warning "Resource inventory error: $($_.Exception.Message)"
    }

    # Step 2: Activity Logs
    Write-Host "`nStep 2: Azure Activity Logs Collection" -ForegroundColor Yellow
    try {
        $logsResults = Get-AzureActivityLogs -SubscriptionId $SubscriptionId -Days 30 -OutputPath $analysisDir
        $workflow.Results.ActivityLogs = $logsResults
        $workflow.Steps += "Activity Logs: Success - $logsResults"
        Write-Host "[OK] Activity logs collected" -ForegroundColor Green
    } catch {
        $workflow.Steps += "Activity Logs: Error - $($_.Exception.Message)"
        Write-Warning "Activity logs error: $($_.Exception.Message)"
    }

    # Step 3: Storage Analysis (optional)
    if ($IncludeStorage) {
        Write-Host "`nStep 3: Azure Storage Analysis" -ForegroundColor Yellow
        try {
            # Get storage accounts from inventory
            $inventoryFile = Join-Path $analysisDir "AzureInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss')" "azure_inventory.json"
            if (Test-Path $inventoryFile) {
                $inventory = Get-Content $inventoryFile | ConvertFrom-Json
                $storageAccounts = $inventory.Resources."Microsoft.Storage/storageAccounts"

                if ($storageAccounts) {
                    $storageResults = @()
                    foreach ($storage in $storageAccounts) {
                        $result = Get-AzureStorageAnalysis -StorageAccountName $storage.Name -ResourceGroup $storage.ResourceGroup -OutputPath $analysisDir
                        $storageResults += $result
                    }
                    $workflow.Results.StorageAnalysis = $storageResults
                    $workflow.Steps += "Storage Analysis: Success - Analyzed $($storageAccounts.Count) accounts"
                    Write-Host "[OK] Storage analysis completed" -ForegroundColor Green
                } else {
                    $workflow.Steps += "Storage Analysis: No storage accounts found"
                }
            } else {
                $workflow.Steps += "Storage Analysis: Inventory not available"
            }
        } catch {
            $workflow.Steps += "Storage Analysis: Error - $($_.Exception.Message)"
            Write-Warning "Storage analysis error: $($_.Exception.Message)"
        }
    }

    # Step 4: VM Artifacts (optional)
    if ($IncludeVMs) {
        Write-Host "`nStep 4: Azure VM Artifact Collection" -ForegroundColor Yellow
        try {
            # Get VMs from inventory
            $inventoryFile = Join-Path $analysisDir "AzureInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss')" "azure_inventory.json"
            if (Test-Path $inventoryFile) {
                $inventory = Get-Content $inventoryFile | ConvertFrom-Json
                $vms = $inventory.Resources."Microsoft.Compute/virtualMachines"

                if ($vms) {
                    $vmResults = @()
                    foreach ($vm in $vms) {
                        $result = Get-AzureVMArtifacts -VMName $vm.Name -ResourceGroup $vm.ResourceGroup -OutputPath $analysisDir
                        $vmResults += $result
                    }
                    $workflow.Results.VMArtifacts = $vmResults
                    $workflow.Steps += "VM Artifacts: Success - Collected from $($vms.Count) VMs"
                    Write-Host "[OK] VM artifact collection completed" -ForegroundColor Green
                } else {
                    $workflow.Steps += "VM Artifacts: No VMs found"
                }
            } else {
                $workflow.Steps += "VM Artifacts: Inventory not available"
            }
        } catch {
            $workflow.Steps += "VM Artifacts: Error - $($_.Exception.Message)"
            Write-Warning "VM artifacts error: $($_.Exception.Message)"
        }
    }

    # Save workflow summary
    $summaryFile = Join-Path $analysisDir "azure_cloud_forensics_workflow.json"
    $workflow | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "`n=== AZURE CLOUD FORENSICS COMPLETE ===" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan
    Write-Host "Summary: $summaryFile" -ForegroundColor Cyan

    return $analysisDir
}