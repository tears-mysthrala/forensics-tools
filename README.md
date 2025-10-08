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

### Complete Analysis Functions

- `Invoke-LiveSystemStatus`: Quick system overview (console output or file).
- `Invoke-SystemAnalysis`: Comprehensive system information and configuration.
- `Invoke-NetworkAnalysis`: Network connections, shares, and USB history.
- `Invoke-FileSystemAnalysis`: File system artifacts and anomalies.
- `Invoke-EventLogAnalysis`: Event log analysis and security events.
- `Invoke-RegistryAnalysis`: Registry forensics and persistence mechanisms.
- `Invoke-CompleteForensics`: Full system forensic analysis (all phases).

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
```

## Requirements

- PowerShell 5.1 or 7+
- Administrator privileges for some functions
- Internet access for module installation

## Integrated Tools

The profile automatically attempts to install and import the following forensic modules:

- PowerForensics
- PSRecon
- Invoke-LiveResponse

## Dependencies

### Required for Full Functionality

**Memory Analysis Tools** (Optional - PowerShell method works without them):

- **WinPMEM**: `Get-MemoryDump -Method WinPMEM`
  - Automatically downloaded by `Install-ForensicTools`
  - Stored in profile `Tools\` directory for USB compatibility

- **DumpIt**: `Get-MemoryDump -Method DumpIt`
  - Download: [MoonSols DumpIt](https://www.moonsols.com/windows-memory-toolkit/)
  - Place in profile `Tools\` directory

**Note**: PowerShell method provides valuable memory information without external tools.

**Python Forensics Tools** (for advanced analysis):

- **Python 3.8+**: [python.org](https://python.org)
- **Volatility 3**: `pip install volatility3`
- **PEFile**: `pip install pefile`
- **YARA**: `pip install yara-python`

### Automatic Setup

Run `Get-PythonForensicsTools` to automatically check and install Python dependencies.

## Contributing

When adding new forensic functions:

1. Choose the appropriate module in `Scripts/Modules/` based on function purpose
2. Add the function with proper help documentation
3. Test on a non-production system
4. Update this README if adding new function categories

### Module Guidelines

- **CoreSystemFunctions.ps1**: System information, processes, users, services, scheduled tasks
- **NetworkFunctions.ps1**: Network analysis, connections, shares, USB devices
- **FileSystemFunctions.ps1**: File operations, hashes, alternate data streams
- **RegistryFunctions.ps1**: Registry access and analysis
- **EventLogFunctions.ps1**: Event log parsing and analysis
- **MemoryFunctions.ps1**: Memory acquisition and analysis
- **EvidenceCollectionFunctions.ps1**: Evidence gathering and reporting
- **AnalysisWrapperFunctions.ps1**: High-level analysis workflows

## Disclaimer

This profile is intended for authorized forensic investigations only. Ensure compliance with legal and organizational policies before use.

## Windows Terminal Integration

The repository includes Windows Terminal configuration for dedicated forensics monitoring:

### Setup Instructions

1. **Deploy to Desktop** (for monitoring):

   ```powershell
   .\Deploy-ForensicsProfile.ps1
   ```

2. **Update Windows Terminal Settings**:
   - Copy the contents of `windows_terminal_settings` to your Windows Terminal settings file
   - Or manually add the "🔍 Forensics IR" profile

3. **Launch Forensics Session**:
   - Open Windows Terminal
   - Select the "🔍 Forensics IR" profile
   - The profile will automatically load with timestamped prompts for full traceability

### Profile Features

- **Distinctive Appearance**: Uses Dracula color scheme with 🔍 icon
- **Automatic Profile Loading**: Loads forensics profile from desktop
- **Monitoring Ready**: Position on desktop for constant visibility
- **Timestamped Prompts**: Every command is logged with date/time

## Testing & Validation

The profile has been tested and validated with the following functions:

### Core Functionality Tests ✅

- **Profile Loading**: Successfully loads all modules and displays system information
- **Python Tools Setup**: `Get-PythonForensicsTools` automatically installs required libraries
- **Memory Dump**: `Get-MemoryDump -Method PowerShell` creates memory information JSON files
- **Evidence Collection**: `Collect-SystemEvidence` gathers 10 evidence files without errors
- **Live Forensics**: `Invoke-LiveForensics` performs complete analysis workflow
- **Tool Installation**: `Install-ForensicTools` sets up tools in profile directory
- **Permission Handling**: Functions gracefully handle access denied errors with timeouts
- **Wrapper Functions**: All analysis wrapper functions execute successfully

### Test Results

```powershell
# Live system status check (tested successfully)
Invoke-LiveSystemStatus
# Output: Displays system info, processes, network, services

# System analysis (tested successfully)
Invoke-SystemAnalysis -OutputPath '.\test_analysis'
# Output: Creates SystemAnalysis directory with 6 XML files

# Network analysis (tested successfully)
Invoke-NetworkAnalysis -OutputPath '.\test_analysis'
# Output: Creates NetworkAnalysis directory with connection/share data

# File system analysis (tested successfully)
Invoke-FileSystemAnalysis -Path "C:\" -OutputPath '.\test_analysis'
# Output: Creates FileSystemAnalysis directory with file artifacts

# Event log analysis (tested successfully)
Invoke-EventLogAnalysis -Hours 24 -OutputPath '.\test_analysis'
# Output: Creates EventLogAnalysis directory with log summaries

# Registry analysis (tested successfully)
Invoke-RegistryAnalysis -OutputPath '.\test_analysis'
# Output: Creates RegistryAnalysis directory with registry data

# Complete forensics (tested successfully)
Invoke-CompleteForensics -OutputPath '.\test_complete' -IncludeMemory $false
# Output: Runs all analysis phases, creates comprehensive report
```
