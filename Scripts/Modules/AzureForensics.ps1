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
        [Parameter(Mandatory = $true)]
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
        Timestamp      = Get-Date
        SubscriptionId = $SubscriptionId
        IncludeStorage = $IncludeStorage
        IncludeVMs     = $IncludeVMs
        Steps          = @()
        Results        = @{}
    }

    # Step 1: Resource Inventory
    Write-Host "`nStep 1: Azure Resource Inventory" -ForegroundColor Yellow
    try {
        $inventoryResults = Get-AzureResourceInventory -SubscriptionId $SubscriptionId -OutputPath $analysisDir
        $workflow.Results.ResourceInventory = $inventoryResults
        $workflow.Steps += "Resource Inventory: Success - $inventoryResults"
        Write-Host "[OK] Resource inventory completed" -ForegroundColor Green
    }
    catch {
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
    }
    catch {
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
                }
                else {
                    $workflow.Steps += "Storage Analysis: No storage accounts found"
                }
            }
            else {
                $workflow.Steps += "Storage Analysis: Inventory not available"
            }
        }
        catch {
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
                }
                else {
                    $workflow.Steps += "VM Artifacts: No VMs found"
                }
            }
            else {
                $workflow.Steps += "VM Artifacts: Inventory not available"
            }
        }
        catch {
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