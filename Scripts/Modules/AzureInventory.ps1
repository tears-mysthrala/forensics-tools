# AzureInventory.ps1
# Azure resource inventory functions for cloud forensics

<#
.SYNOPSIS
    Azure Inventory Functions

.DESCRIPTION
    This module provides Azure resource inventory capabilities for cloud forensics:
    - Get-AzureResourceInventory: Collects information about Azure resources, configurations, and access patterns

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

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
        [Parameter(Mandatory = $true)]
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
        Timestamp      = Get-Date
        SubscriptionId = $SubscriptionId
        Resources      = @{}
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
        }
        else {
            # Use Azure CLI
            az login --use-device-code
            az account set --subscription $SubscriptionId
        }

        Write-Host "[OK] Connected to Azure" -ForegroundColor Green

    }
    catch {
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
                        Name          = $res.Name
                        ResourceGroup = $res.ResourceGroupName
                        Location      = $res.Location
                        Type          = $res.ResourceType
                        Id            = $res.ResourceId
                        Tags          = $res.Tags
                        CreatedTime   = $res.CreatedTime
                        ChangedTime   = $res.ChangedTime
                    }
                }
            }
            else {
                # Use Azure CLI
                $azOutput = az resource list --resource-type $resourceType --output json | ConvertFrom-Json
                foreach ($res in $azOutput) {
                    $resources += @{
                        Name          = $res.name
                        ResourceGroup = $res.resourceGroup
                        Location      = $res.location
                        Type          = $res.type
                        Id            = $res.id
                        Tags          = $res.tags
                        CreatedTime   = $res.createdTime
                        ChangedTime   = $res.changedTime
                    }
                }
            }

            $inventoryResults.Resources[$resourceType] = $resources

            Write-Host "[OK] Found $($resources.Count) $resourceType resources" -ForegroundColor Green

        }
        catch {
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
                Name     = $subscription.Name
                State    = $subscription.State
                TenantId = $subscription.TenantId
            }

            # Get role assignments
            $roleAssignments = Get-AzRoleAssignment
            $additionalInfo.RoleAssignments = $roleAssignments | Select-Object DisplayName, SignInName, RoleDefinitionName, Scope

        }
        else {
            # Get subscription details
            $subOutput = az account show --output json | ConvertFrom-Json
            $additionalInfo.Subscription = @{
                Name     = $subOutput.name
                State    = $subOutput.state
                TenantId = $subOutput.tenantId
            }

            # Get role assignments
            $roleOutput = az role assignment list --output json | ConvertFrom-Json
            $additionalInfo.RoleAssignments = $roleOutput | Select-Object displayName, signInName, roleDefinitionName, scope
        }

        $inventoryResults.AdditionalInfo = $additionalInfo

    }
    catch {
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
                    ResourceType  = $resourceType
                    Name          = $resource.Name
                    ResourceGroup = $resource.ResourceGroup
                    Location      = $resource.Location
                    CreatedTime   = $resource.CreatedTime
                    ChangedTime   = $resource.ChangedTime
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