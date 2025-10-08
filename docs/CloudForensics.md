# Cloud Forensics

Cloud forensics for Azure resources, logs, storage, and VM artifacts.

## Functions

### Get-AzureResourceInventory

Inventories Azure resources, configurations, and access patterns.

```powershell
Get-AzureResourceInventory -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputPath "C:\AzureAnalysis"
```

**Parameters:**

- `SubscriptionId`: Azure subscription ID
- `OutputPath`: Directory for inventory data

**Returns:**

- Resource inventory and configurations
- Access patterns and permissions

### Get-AzureActivityLogs

Collects Azure activity logs, audit events, and administrative actions.

```powershell
Get-AzureActivityLogs -SubscriptionId "12345678-1234-1234-1234-123456789012" -Days 30 -OutputPath "C:\AzureLogs"
```

**Parameters:**

- `SubscriptionId`: Azure subscription ID
- `Days`: Days of logs to collect
- `OutputPath`: Directory for log data

**Returns:**

- Activity logs and audit events
- Administrative action history

### Get-AzureStorageAnalysis

Analyzes Azure Storage accounts, containers, blobs, and access patterns.

```powershell
Get-AzureStorageAnalysis -StorageAccountName "mystorage" -ResourceGroup "myrg" -OutputPath "C:\StorageAnalysis"
```

**Parameters:**

- `StorageAccountName`: Storage account name
- `ResourceGroup`: Resource group name
- `OutputPath`: Directory for analysis

**Returns:**

- Storage account analysis
- Blob and container inventory

### Get-AzureVMArtifacts

Collects forensic artifacts from Azure Virtual Machines.

```powershell
Get-AzureVMArtifacts -VMName "myVM" -ResourceGroup "myrg" -OutputPath "C:\VMArtifacts"
```

**Parameters:**

- `VMName`: Virtual machine name
- `ResourceGroup`: Resource group name
- `OutputPath`: Directory for artifacts

**Returns:**

- VM logs and configurations
- System artifacts and evidence

### Invoke-AzureCloudForensics

Complete Azure cloud forensics workflow.

```powershell
Invoke-AzureCloudForensics -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputPath "C:\CompleteAzureForensics"
```

**Parameters:**

- `SubscriptionId`: Azure subscription ID
- `OutputPath`: Directory for complete analysis

**Returns:**

- Comprehensive Azure forensics package
- Resources, logs, storage, and VM analysis