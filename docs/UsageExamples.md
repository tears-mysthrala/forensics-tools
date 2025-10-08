# Usage Examples

This document provides comprehensive usage examples for all forensic functions.

## Core System Analysis

### System Information

```powershell
# Get basic system information
Get-SystemInfo

# Get detailed system information with export
Get-SystemInfo | Export-Csv -Path "system_info.csv" -NoTypeInformation
```

### Process Analysis

```powershell
# Get enhanced process details
Get-ProcessDetails

# Find suspicious processes
Get-ProcessDetails | Where-Object { $_.Path -like "*temp*" -or $_.Path -like "*downloads*" }

# Export process information
Get-ProcessDetails | Export-Csv -Path "processes.csv" -NoTypeInformation
```

### User and Account Analysis

```powershell
# List all user accounts
Get-UserAccounts

# Get detailed user information
Get-UserAccounts | Format-Table -AutoSize

# Check for recently created accounts
Get-UserAccounts | Where-Object { $_.Created -gt (Get-Date).AddDays(-30) }
```

### Services and Tasks

```powershell
# Get running services
Get-ServicesStatus

# Find suspicious services
Get-ServicesStatus | Where-Object { $_.Status -eq "Running" -and $_.StartMode -eq "Auto" }

# Get scheduled tasks
Get-ScheduledTasks

# Find tasks that run with high privileges
Get-ScheduledTasks | Where-Object { $_.RunLevel -eq "Highest" }
```

## Network Forensics

### Network Connections

```powershell
# Get active network connections
Get-NetworkConnections

# Find suspicious connections
Get-NetworkConnections | Where-Object { $_.RemoteAddress -notlike "192.168.*" -and $_.RemoteAddress -notlike "10.*" }

# Export network data
Get-NetworkConnections | Export-Csv -Path "network_connections.csv" -NoTypeInformation
```

### Network Shares and USB History

```powershell
# List network shares
Get-NetworkShares

# Get USB device history
Get-USBDeviceHistory

# Find recently connected USB devices
Get-USBDeviceHistory | Where-Object { $_.LastConnected -gt (Get-Date).AddDays(-7) }
```

## File System Forensics

### File Analysis

```powershell
# Compute file hashes
Get-FileHashes -Path "C:\Suspicious"

# Analyze a specific file
Analyze-File -Path "C:\Windows\System32\cmd.exe"

# Find recently modified files
Get-RecentFiles -Days 1 -Path "C:\Users"

# Find large files
Get-LargeFiles -MinSizeMB 500 -Path "C:\"

# Scan for alternate data streams
Get-AlternateDataStreams -Path "C:\"
```

### File Signatures and Carving

```powershell
# Analyze file signatures
Get-FileSignatures -Path "C:\Downloads"

# Perform file carving
Get-FileCarving -Path "C:\Unallocated" -OutputPath "C:\CarvedFiles"

# Create file system timeline
Get-FileSystemTimeline -Path "C:\" -OutputPath "C:\Timeline"

# Analyze deleted files
Get-DeletedFilesAnalysis -Path "C:\" -OutputPath "C:\DeletedAnalysis"

# Detect file anomalies
Get-FileAnomalyDetection -Path "C:\Suspicious" -OutputPath "C:\Anomalies"
```

## Registry Forensics

### Registry Analysis

```powershell
# Get registry keys
Get-RegistryKeys -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Export registry data
Get-RegistryKeys -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Export-Csv -Path "services.csv"
```

## Event Log Analysis

### Event Log Operations

```powershell
# Get event log summary
Get-EventLogsSummary -Hours 24

# Search event logs
Search-EventLogs -Keyword "failed" -LogName "Security"

# Export security events
Search-EventLogs -Keyword "4625" -LogName "Security" -Hours 168 | Export-Csv -Path "failed_logins.csv"
```

## Memory Forensics

### Memory Dumping

```powershell
# Capture memory dump (PowerShell method)
Get-MemoryDump -OutputPath "C:\Evidence" -Method PowerShell

# Install memory dumping tools
Install-ForensicTools

# Capture with WinPMEM (if available)
Get-MemoryDump -OutputPath "C:\Evidence" -Method WinPMEM
```

### Volatility Analysis

```powershell
# List available Volatility plugins
Get-VolatilityPlugins

# Basic process analysis
Invoke-VolatilityAnalysis -MemoryDump "C:\Evidence\memory.dmp" -AnalysisType "pslist" -OutputPath "C:\Analysis"

# Full analysis
Invoke-VolatilityAnalysis -MemoryDump "C:\Evidence\memory.dmp" -AnalysisType "full" -OutputPath "C:\Analysis"
```

### Advanced Memory Forensics

```powershell
# Dump specific process memory
Get-ProcessMemoryDump -ProcessName "notepad" -OutputPath "C:\Evidence"

# Create memory timeline
Get-MemoryTimeline -MemoryDump "C:\Evidence\memory.dmp" -OutputPath "C:\Analysis"

# Extract strings from memory
Get-MemoryStrings -MemoryDump "C:\Evidence\memory.dmp" -MinLength 8 -OutputPath "C:\Analysis"

# Collect memory artifacts
Get-MemoryArtifacts -OutputPath "C:\Evidence"

# Complete memory forensics workflow
Invoke-MemoryForensicAnalysis -OutputPath "C:\MemoryAnalysis" -IncludeProcessDumps $true
```

## Advanced Network Forensics

### Network Capture

```powershell
# Start network capture
Start-NetworkCapture -Duration 60 -OutputPath "C:\Evidence"

# Analyze captured traffic
Get-NetworkTrafficAnalysis -CaptureFile "C:\Evidence\network_capture.pcap" -OutputPath "C:\Analysis"
```

### Network Analysis

```powershell
# DNS analysis
Get-DNSAnalysis -OutputPath "C:\Evidence"

# Firewall log analysis
Get-FirewallLogAnalysis -OutputPath "C:\Evidence"

# Network anomaly detection
Get-NetworkAnomalies -OutputPath "C:\Evidence"

# Complete network analysis
Invoke-AdvancedNetworkAnalysis -CaptureDuration 60 -OutputPath "C:\NetworkAnalysis"
```

## Advanced File System Forensics

```powershell
# Complete file system analysis
Invoke-AdvancedFileSystemAnalysis -Path "C:\Suspicious" -OutputPath "C:\Analysis" -IncludeCarving $true
```

## Malware Analysis

### YARA Operations

```powershell
# Download YARA rules
Get-YaraRules -OutputPath "C:\YaraRules"

# Scan with YARA
Invoke-YaraScan -Path "C:\Suspicious" -RulesPath "C:\YaraRules" -OutputPath "C:\ScanResults"
```

### Static Analysis

```powershell
# Static file analysis
Get-FileStaticAnalysis -Path "C:\Malware.exe" -OutputPath "C:\Analysis"
```

### Behavioral Analysis

```powershell
# Monitor process behavior
Get-BehavioralAnalysis -ProcessName "suspicious.exe" -Duration 300 -OutputPath "C:\Analysis"
```

### Complete Malware Analysis

```powershell
# Full malware analysis workflow
Invoke-MalwareAnalysis -Path "C:\Suspicious" -OutputPath "C:\MalwareAnalysis" -IncludeBehavioral $true
```

## Cloud Forensics

### Azure Resource Inventory

```powershell
# Get Azure resource inventory
Get-AzureResourceInventory -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputPath "C:\AzureAnalysis"
```

### Azure Activity Logs

```powershell
# Collect activity logs
Get-AzureActivityLogs -SubscriptionId "12345678-1234-1234-1234-123456789012" -Days 30 -OutputPath "C:\AzureLogs"
```

### Azure Storage Analysis

```powershell
# Analyze storage accounts
Get-AzureStorageAnalysis -StorageAccountName "mystorage" -ResourceGroup "myrg" -OutputPath "C:\StorageAnalysis"
```

### Azure VM Artifacts

```powershell
# Collect VM artifacts
Get-AzureVMArtifacts -VMName "myVM" -ResourceGroup "myrg" -OutputPath "C:\VMArtifacts"
```

### Complete Azure Forensics

```powershell
# Full Azure forensics workflow
Invoke-AzureCloudForensics -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputPath "C:\CompleteAzureForensics"
```

## Reporting and Visualization

### HTML Reports

```powershell
# Create forensic HTML report
New-ForensicHTMLReport -InputPath "C:\Analysis" -OutputPath "C:\Report.html"
```

### Timeline Visualization

```powershell
# Generate timeline visualization
New-ForensicTimelineVisualization -InputPath "C:\Analysis\Timeline.json" -OutputPath "C:\TimelineReport.html"
```

### Evidence Correlation

```powershell
# Create evidence correlation dashboard
New-EvidenceCorrelationDashboard -InputPath "C:\Analysis\EvidenceCorrelation.json" -OutputPath "C:\CorrelationDashboard.html"
```

### Report Export

```powershell
# Export reports in multiple formats
Export-ForensicReport -InputPath "C:\Analysis" -OutputPath "C:\ForensicReport.zip"
```

## Automation and Orchestration

### Evidence Collection Workflows

```powershell
# Create automated workflow
New-AutomatedEvidenceCollectionWorkflow -WorkflowName "DailySystemAudit" -Sources @("Memory", "Network", "Filesystem") -Schedule "Daily" -RetentionDays 30

# Execute workflow
Start-AutomatedEvidenceCollection -WorkflowName "DailySystemAudit"
```

### Scheduled Tasks

```powershell
# Create scheduled forensic task
New-ScheduledForensicTask -TaskName "DailyForensics" -WorkflowName "DailySystemAudit" -Schedule "Daily" -StartTime "02:00"

# List scheduled tasks
Get-ScheduledForensicTasks
```

### SIEM Integration

```powershell
# Configure SIEM integration
New-SIEMIntegration -SIEMType "Splunk" -Server "splunk.company.com" -Port 8088 -APIKey "your-api-key"

# Send alert to SIEM
Send-SIEMAlert -SIEMType "Splunk" -AlertData @{ Severity = "High"; Message = "Malware detected"; Details = $malwareInfo; Score = 9 }
```

### Workflow Orchestration

```powershell
# Create workflow orchestrator
New-ForensicWorkflowOrchestrator -OrchestratorName "IncidentResponse" -Workflows @("MemoryAnalysis", "NetworkAnalysis", "FileSystemAnalysis")

# Execute orchestrated workflows
Start-ForensicWorkflowOrchestration -OrchestratorName "IncidentResponse"
```

### Automation Management

```powershell
# Get automation status
Get-AutomationStatus

# Export automation configuration
Export-AutomationConfiguration -OutputPath "C:\Backup\ForensicAutomation.json"

# Import automation configuration
Import-AutomationConfiguration -InputPath "C:\Backup\ForensicAutomation.json"
```

## Complete Analysis Workflows

### Quick System Status

```powershell
# Quick live system status
Invoke-LiveSystemStatus
```

### Comprehensive Analysis

```powershell
# System analysis
Invoke-SystemAnalysis -OutputPath "C:\Analysis"

# Network analysis
Invoke-NetworkAnalysis -OutputPath "C:\Analysis"

# File system analysis
Invoke-FileSystemAnalysis -Path "C:\" -OutputPath "C:\Analysis"

# Event log analysis
Invoke-EventLogAnalysis -Hours 48 -OutputPath "C:\Analysis"

# Registry analysis
Invoke-RegistryAnalysis -OutputPath "C:\Analysis"
```

### Complete Forensics

```powershell
# Full forensic analysis
Invoke-CompleteForensics -OutputPath "C:\Forensics" -IncludeMemory $true
```

## Error Handling and Troubleshooting

```powershell
# Run with verbose output
Get-SystemInfo -Verbose

# Check for errors
try {
    Get-MemoryDump -OutputPath "C:\Evidence"
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Test function availability
Get-Command Get-SystemInfo
```

## Performance Optimization

```powershell
# Use parallel processing where available
$paths = @("C:\", "D:\", "E:\")
$paths | ForEach-Object -Parallel {
    Get-FileHashes -Path $_
}

# Limit output for large directories
Get-RecentFiles -Days 1 -Path "C:\Users" -MaxFiles 1000
```

## Export and Reporting

```powershell
# Export to multiple formats
Get-SystemInfo | Export-Csv -Path "system.csv" -NoTypeInformation
Get-SystemInfo | Export-Clixml -Path "system.xml"
Get-SystemInfo | ConvertTo-Json | Out-File "system.json"

# Create comprehensive reports
$evidence = @{
    System = Get-SystemInfo
    Processes = Get-ProcessDetails
    Network = Get-NetworkConnections
}

$evidence | ConvertTo-Json -Depth 10 | Out-File "evidence.json"
```