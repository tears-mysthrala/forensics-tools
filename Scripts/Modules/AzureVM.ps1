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
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        [Parameter(Mandatory = $true)]
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
        Timestamp     = Get-Date
        VMName        = $VMName
        ResourceGroup = $ResourceGroup
        Artifacts     = @{}
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
            Name        = $vmOutput.name
            Location    = $vmOutput.location
            Size        = $vmOutput.hardwareProfile.vmSize
            OS          = $vmOutput.storageProfile.osDisk.osType
            State       = $vmOutput.powerState
            CreatedTime = $vmOutput.timeCreated
            Tags        = $vmOutput.tags
        }

        # Get VM extensions
        Write-Host "Getting VM extensions..." -ForegroundColor Yellow
        try {
            $extensionsOutput = az vm extension list --vm-name $VMName --resource-group $ResourceGroup --output json | ConvertFrom-Json
            $artifactsResults.Artifacts.Extensions = $extensionsOutput | Select-Object name, type, publisher, version, settings
        }
        catch {
            Write-Warning "Failed to get VM extensions: $($_.Exception.Message)"
        }

        # Get VM disks
        Write-Host "Getting VM disks..." -ForegroundColor Yellow
        try {
            $disksOutput = az vm show --name $VMName --resource-group $ResourceGroup --query "storageProfile" --output json | ConvertFrom-Json
            $artifactsResults.Artifacts.Disks = @{
                OSDisk    = $disksOutput.osDisk
                DataDisks = $disksOutput.dataDisks
            }
        }
        catch {
            Write-Warning "Failed to get VM disks: $($_.Exception.Message)"
        }

        # Get VM network interfaces
        Write-Host "Getting VM network configuration..." -ForegroundColor Yellow
        try {
            $nicOutput = az vm show --name $VMName --resource-group $ResourceGroup --query "networkProfile" --output json | ConvertFrom-Json
            $artifactsResults.Artifacts.NetworkInterfaces = $nicOutput.networkInterfaces
        }
        catch {
            Write-Warning "Failed to get VM network configuration: $($_.Exception.Message)"
        }

        # Get VM logs (if available)
        Write-Host "Checking for VM diagnostic logs..." -ForegroundColor Yellow
        try {
            $logsOutput = az monitor diagnostic-settings list --resource "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$VMName" --output json | ConvertFrom-Json
            $artifactsResults.Artifacts.DiagnosticSettings = $logsOutput
        }
        catch {
            Write-Warning "Failed to get diagnostic settings: $($_.Exception.Message)"
        }

        Write-Host "[OK] Collected VM artifacts" -ForegroundColor Green

    }
    catch {
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