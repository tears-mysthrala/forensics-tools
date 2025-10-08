# PowerShell Forensics and Incident Response Profile

A specialized PowerShell profile designed for digital forensics and incident response investigations.

## Quick Start

```powershell
# Clone the repository
git clone https://github.com/tears-mysthrala/PowerShell-profile.git $HOME\Documents\PowerShell

# Switch to forensics branch
git checkout forensics-profile

# Load the profile
. $PROFILE
```

## Features

- **Modular Architecture**: Functions organized into logical modules for better maintainability
- **System Analysis**: Functions to gather system information, process details, and network connections
- **Event Log Analysis**: Tools for summarizing and searching Windows event logs
- **File Forensics**: Hash computation, file analysis, and registry inspection
- **Memory Analysis**: Live memory dumping and Volatility analysis
- **Evidence Collection**: Comprehensive evidence gathering and reporting
- **Integrated Modules**: Automatic installation of forensic PowerShell modules

## Modular Structure

The forensic functions are organized into the following modules:

- **CoreSystemFunctions.ps1**: System information, processes, users, services, tasks
- **NetworkFunctions.ps1**: Network connections, shares, USB device history
- **FileSystemFunctions.ps1**: File analysis, hashes, alternate data streams
- **RegistryFunctions.ps1**: Registry forensics and persistence analysis
- **EventLogFunctions.ps1**: Event log analysis and security monitoring
- **MemoryFunctions.ps1**: Memory dumping and Volatility analysis
- **AdvancedMemoryFunctions.ps1**: Advanced memory forensics with Volatility plugins and artifact extraction
- **AdvancedNetworkFunctions.ps1**: Advanced network forensics with packet capture and traffic analysis
- **AdvancedFileSystemFunctions.ps1**: Advanced file system forensics with carving, timelines, and anomaly detection
- **AdvancedMalwareAnalysisFunctions.ps1**: Advanced malware analysis with YARA scanning, static analysis, and behavioral monitoring
- **CloudForensicsFunctions.ps1**: Cloud forensics for Azure resources, logs, storage, and VM artifacts
- **ReportingFunctions.ps1**: Forensic reporting and visualization with interactive HTML reports and evidence correlation
- **EvidenceCollectionFunctions.ps1**: Evidence collection and reporting
- **AnalysisWrapperFunctions.ps1**: Single-command analysis workflows

## Available Functions

### System Information

- `Get-SystemInfo`: Retrieves basic system details for forensic analysis.

### Process Analysis

- `Get-ProcessDetails`: Enhanced process listing with file paths and hashes.

### Network Analysis

- `Get-NetworkConnections`: Lists active network connections with process information.

### Event Log Analysis

- `Get-EventLogsSummary`: Summarizes event counts by type.
- `Search-EventLogs`: Searches event logs for specific keywords.

### File Analysis

- `Get-FileHashes`: Computes hashes for files in a directory.
- `Analyze-File`: Provides detailed file metadata.
- `Get-RecentFiles`: Finds files modified within last X days.
- `Get-LargeFiles`: Finds files larger than specified size.
- `Get-AlternateDataStreams`: Scans for alternate data streams.

### Registry Analysis

- `Get-RegistryKeys`: Retrieves registry key values.

### Additional Functions

- `Get-InstalledSoftware`: Lists installed software from registry.
- `Get-ScheduledTasks`: Lists scheduled tasks.
- `Get-ServicesStatus`: Shows running services.
- `Get-StartupPrograms`: Lists startup programs.
- `Get-UserAccounts`: Lists user accounts and status.
- `Get-NetworkShares`: Lists network shares.
- `Get-USBDeviceHistory`: Shows USB device connection history.

### Log Analysis

- `Get-SystemLogsSummary`: Provides summary of system logs.

### Memory & Live Analysis

- `Get-MemoryDump`: Captures live memory dumps using WinPMEM/DumpIt/PowerShell.
- `Get-VolatilityAnalysis`: Performs Volatility 3 analysis on memory dumps.
- `Collect-SystemEvidence`: Gathers comprehensive system evidence.
- `Get-PythonForensicsTools`: Checks/installs Python forensics libraries.
- `Invoke-LiveForensics`: Performs complete live forensics analysis.
- `Install-ForensicTools`: Downloads and installs required forensic tools.

### Advanced Memory Forensics

- `Get-VolatilityPlugins`: Lists all available Volatility 3 plugins.
- `Invoke-VolatilityAnalysis`: Runs comprehensive Volatility analysis (processes, network, filesystem, malware, timeline).
- `Get-ProcessMemoryDump`: Dumps memory of specific processes for analysis.
- `Get-MemoryTimeline`: Creates chronological timeline from memory artifacts.
- `Get-MemoryStrings`: Extracts readable strings from memory dumps.
- `Get-MemoryArtifacts`: Collects memory-resident artifacts (clipboard, environment, history).
- `Invoke-MemoryForensicAnalysis`: Complete memory forensics workflow (dump + analysis + timeline + artifacts).

### Advanced Network Forensics

- `Start-NetworkCapture`: Captures network traffic using Wireshark/tshark, netsh, or PowerShell.
- `Get-NetworkTrafficAnalysis`: Analyzes captured traffic for connections, protocols, and suspicious activity.
- `Get-DNSAnalysis`: Examines DNS cache, queries, and suspicious domain lookups.
- `Get-FirewallLogAnalysis`: Parses Windows Firewall logs for blocked connections and security events.
- `Get-NetworkAnomalies`: Detects unusual network activity and suspicious connections.
- `Invoke-AdvancedNetworkAnalysis`: Complete network forensics workflow (capture + analysis + detection).

### Advanced File System Forensics

- `Get-FileSignatures`: Analyzes file signatures and headers for forensic insights (magic bytes, extension mismatches).
- `Get-FileCarving`: Performs file carving to recover deleted or hidden files based on signatures.
- `Get-FileSystemTimeline`: Creates comprehensive chronological timelines of file system activity.
- `Get-DeletedFilesAnalysis`: Analyzes traces of deleted files and recoverable data (Recycle Bin, temp files, prefetch).
- `Get-FileAnomalyDetection`: Detects file system anomalies and suspicious file activity.
- `Invoke-AdvancedFileSystemAnalysis`: Complete file system forensics workflow (signatures + timeline + deleted files + anomalies + optional carving).

### Advanced Malware Analysis

- `Get-YaraRules`: Downloads and manages YARA rules for malware detection from public repositories.
- `Invoke-YaraScan`: Scans files using YARA rules for malware signatures and suspicious patterns.
- `Get-FileStaticAnalysis`: Performs static analysis on files for malware indicators (strings, imports, properties).
- `Get-BehavioralAnalysis`: Monitors process behavior, network connections, and system activity.
- `Invoke-MalwareAnalysis`: Complete malware analysis workflow (YARA scanning + static analysis + optional behavioral monitoring).

### Cloud Forensics

- `Get-AzureResourceInventory`: Inventories Azure resources, configurations, and access patterns.
- `Get-AzureActivityLogs`: Collects Azure activity logs, audit events, and administrative actions.
- `Get-AzureStorageAnalysis`: Analyzes Azure Storage accounts, containers, blobs, and access patterns.
- `Get-AzureVMArtifacts`: Collects forensic artifacts from Azure Virtual Machines (logs, configurations, disks).
- `Invoke-AzureCloudForensics`: Complete Azure cloud forensics workflow (inventory + logs + storage + VMs).

### Forensic Reporting and Visualization

- `New-ForensicHTMLReport`: Creates an interactive HTML forensic report with charts, timelines, and evidence correlation.
- `New-ForensicTimelineVisualization`: Generates an interactive timeline visualization of forensic events and activities.
- `New-EvidenceCorrelationDashboard`: Creates an evidence correlation dashboard showing relationships between different evidence types.
- `Export-ForensicReport`: Exports comprehensive forensic reports in multiple formats (JSON, CSV, HTML).

### Complete Analysis Functions

- `Invoke-LiveSystemStatus`: Quick system overview (console output or file).
- `Invoke-SystemAnalysis`: Comprehensive system information and configuration.
- `Invoke-NetworkAnalysis`: Network connections, shares, and USB history.
- `Invoke-FileSystemAnalysis`: File system artifacts and anomalies.
- `Invoke-EventLogAnalysis`: Event log analysis and security events.
- `Invoke-RegistryAnalysis`: Registry forensics and persistence mechanisms.
- `Invoke-CompleteForensics`: Full system forensic analysis (all phases).

### Automation and Orchestration

- `New-AutomatedEvidenceCollectionWorkflow`: Creates automated evidence collection workflows for systematic data gathering.
- `Start-AutomatedEvidenceCollection`: Executes automated evidence collection workflows with timeout and error handling.
- `New-ScheduledForensicTask`: Creates Windows scheduled tasks for automated forensic analysis and evidence collection.
- `Get-ScheduledForensicTasks`: Retrieves information about all configured scheduled forensic tasks.
- `New-SIEMIntegration`: Configures integration with SIEM systems (Splunk, ELK, QRadar) for automated alerting.
- `Send-SIEMAlert`: Sends forensic findings and alerts to integrated SIEM systems with threshold checking.
- `New-ForensicWorkflowOrchestrator`: Creates orchestrators to manage complex forensic workflows with dependencies.
- `Start-ForensicWorkflowOrchestration`: Executes orchestrated workflows with dependency resolution and parallel execution.
- `Get-AutomationStatus`: Provides comprehensive status information for all automation components.
- `Export-AutomationConfiguration`: Exports automation configurations for backup and migration.
- `Import-AutomationConfiguration`: Imports automation configurations from backup files.

## Usage Examples

```powershell
# Get system information
Get-SystemInfo

# Analyze running processes
Get-ProcessDetails | Export-Csv -Path processes.csv

# Search security logs for failed logins
Search-EventLogs -Keyword "failed" -LogName Security

# Hash all files in a directory
Get-FileHashes -Path C:\Suspicious | Export-Csv -Path hashes.csv

# Analyze a specific file
Analyze-File -Path C:\Windows\System32\cmd.exe

# Find recently modified files
Get-RecentFiles -Days 1 -Path C:\Users

# Find large files that might be suspicious
Get-LargeFiles -MinSizeMB 500

# Check installed software
Get-InstalledSoftware | Where-Object { $_.DisplayName -like "*suspicious*" }

# Analyze scheduled tasks
Get-ScheduledTasks

# Check running services
Get-ServicesStatus

# Find startup programs
Get-StartupPrograms

# List user accounts
Get-UserAccounts

# Scan for alternate data streams
Get-AlternateDataStreams -Path C:\

# Get system logs summary
Get-SystemLogsSummary -Hours 48

# Check network shares
Get-NetworkShares

# View USB device history
Get-USBDeviceHistory

# Collect comprehensive system evidence
Collect-SystemEvidence -OutputPath C:\Evidence

# Perform live forensics analysis
Invoke-LiveForensics -OutputPath C:\LiveAnalysis -IncludeMemory $false

# Capture memory dump (PowerShell method works without external tools)
Get-MemoryDump -OutputPath C:\Evidence -Method PowerShell

# Install forensic tools to profile directory (USB-compatible)
Install-ForensicTools

# Analyze memory dump with Volatility (requires Python)
Get-VolatilityAnalysis -MemoryDump C:\Evidence\memory.dmp -AnalysisType pslist

# Setup Python forensics tools
Get-PythonForensicsTools

# Quick live system status check
Invoke-LiveSystemStatus

# Comprehensive system analysis
Invoke-SystemAnalysis -OutputPath C:\Analysis

# Network forensic analysis
Invoke-NetworkAnalysis -OutputPath C:\Analysis

# File system analysis
Invoke-FileSystemAnalysis -Path C:\ -OutputPath C:\Analysis

# Event log analysis
Invoke-EventLogAnalysis -Hours 48 -OutputPath C:\Analysis

# Registry analysis
Invoke-RegistryAnalysis -OutputPath C:\Analysis

# Complete forensic analysis (all phases)
Invoke-CompleteForensics -OutputPath C:\Forensics -IncludeMemory $true

# Advanced Memory Forensics
Get-VolatilityPlugins  # List available Volatility plugins
Invoke-VolatilityAnalysis -MemoryDump C:\Evidence\memory.dmp -AnalysisType full -OutputPath C:\Analysis
Get-ProcessMemoryDump -ProcessName "notepad" -OutputPath C:\Evidence
Get-MemoryTimeline -MemoryDump C:\Evidence\memory.dmp -OutputPath C:\Analysis
Get-MemoryStrings -MemoryDump C:\Evidence\memory.dmp -MinLength 8 -OutputPath C:\Analysis
Get-MemoryArtifacts -OutputPath C:\Evidence
Invoke-MemoryForensicAnalysis -OutputPath C:\MemoryAnalysis -IncludeProcessDumps $true

# Advanced Network Forensics
Start-NetworkCapture -Duration 60 -OutputPath C:\Evidence  # Capture network traffic
Get-NetworkTrafficAnalysis -CaptureFile C:\Evidence\network_capture.pcap -OutputPath C:\Analysis
Get-DNSAnalysis -OutputPath C:\Evidence  # Analyze DNS cache and queries
Get-FirewallLogAnalysis -OutputPath C:\Evidence  # Analyze firewall logs
Get-NetworkAnomalies -OutputPath C:\Evidence  # Detect network anomalies
Invoke-AdvancedNetworkAnalysis -CaptureDuration 60 -OutputPath C:\NetworkAnalysis

# Advanced File System Forensics
Get-FileSignatures -Path C:\SuspiciousFiles  # Analyze file signatures
Get-FileCarving -Path C:\RecoveredFiles  # Perform file carving
Get-FileSystemTimeline -Path C:\  # Create file system timeline
Get-DeletedFilesAnalysis -Path C:\  # Analyze deleted files
Get-FileAnomalyDetection -Path C:\SuspiciousFiles  # Detect file anomalies
Invoke-AdvancedFileSystemAnalysis -Path C:\Suspicious -OutputPath C:\Analysis

# Advanced Malware Analysis
Get-YaraRules -OutputPath C:\YaraRules  # Download YARA rules
Invoke-YaraScan -Path C:\Suspicious -RulesPath C:\YaraRules -OutputPath C:\ScanResults  # YARA scanning
Get-FileStaticAnalysis -Path C:\Malware.exe -OutputPath C:\Analysis  # Static analysis
Get-BehavioralAnalysis -ProcessName "suspicious.exe" -Duration 300 -OutputPath C:\Analysis  # Behavioral monitoring
Invoke-MalwareAnalysis -Path C:\Suspicious -OutputPath C:\MalwareAnalysis -IncludeBehavioral $true

# Cloud Forensics
Get-AzureResourceInventory -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputPath C:\AzureAnalysis  # Azure resource inventory
Get-AzureActivityLogs -SubscriptionId "12345678-1234-1234-1234-123456789012" -Days 30 -OutputPath C:\AzureLogs  # Activity logs
Get-AzureStorageAnalysis -StorageAccountName "mystorage" -ResourceGroup "myrg" -OutputPath C:\StorageAnalysis  # Storage analysis
Get-AzureVMArtifacts -VMName "myVM" -ResourceGroup "myrg" -OutputPath C:\VMArtifacts  # VM artifacts
Invoke-AzureCloudForensics -SubscriptionId "12345678-1234-1234-1234-123456789012" -OutputPath C:\CompleteAzureForensics  # Complete Azure forensics workflow

# Forensic Reporting and Visualization
New-ForensicHTMLReport -InputPath C:\Analysis -OutputPath C:\Report.html  # Create forensic HTML report
New-ForensicTimelineVisualization -InputPath C:\Analysis\Timeline.json -OutputPath C:\TimelineReport.html  # Timeline visualization
New-EvidenceCorrelationDashboard -InputPath C:\Analysis\EvidenceCorrelation.json -OutputPath C:\CorrelationDashboard.html  # Evidence correlation dashboard
Export-ForensicReport -InputPath C:\Analysis -OutputPath C:\ForensicReport.zip  # Export forensic report in multiple formats

# Automation and Orchestration
New-AutomatedEvidenceCollectionWorkflow -WorkflowName "DailySystemAudit" -Sources @("Memory", "Network", "Filesystem") -Schedule "Daily" -RetentionDays 30  # Create automated evidence collection workflow
Start-AutomatedEvidenceCollection -WorkflowName "DailySystemAudit"  # Execute automated evidence collection workflow
New-ScheduledForensicTask -TaskName "DailyForensics" -WorkflowName "DailySystemAudit" -Schedule "Daily" -StartTime "02:00"  # Create scheduled forensic task
Get-ScheduledForensicTasks  # Get all scheduled forensic tasks
New-SIEMIntegration -SIEMType "Splunk" -Server "splunk.company.com" -Port 8088 -APIKey "your-api-key"  # Configure SIEM integration
Send-SIEMAlert -SIEMType "Splunk" -AlertData @{ Severity = "High"; Message = "Malware detected"; Details = $malwareInfo; Score = 9 }  # Send alert to SIEM
New-ForensicWorkflowOrchestrator -OrchestratorName "IncidentResponse" -Workflows @("MemoryAnalysis", "NetworkAnalysis", "FileSystemAnalysis")  # Create workflow orchestrator
Start-ForensicWorkflowOrchestration -OrchestratorName "IncidentResponse"  # Execute workflow orchestration
Get-AutomationStatus  # Get comprehensive automation status
Export-AutomationConfiguration -OutputPath "C:\Backup\ForensicAutomation.json"  # Export automation configuration
Import-AutomationConfiguration -InputPath "C:\Backup\ForensicAutomation.json"  # Import automation configuration
```
