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

- **System Analysis**: Functions to gather system information, process details, and network connections.
- **Event Log Analysis**: Tools for summarizing and searching Windows event logs.
- **File Forensics**: Hash computation, file analysis, and registry inspection.
- **Integrated Modules**: Automatic installation of forensic PowerShell modules like PowerForensics.

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

### Registry Analysis

- `Get-RegistryKeys`: Retrieves registry key values.

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

## Contributing

When adding new forensic functions:

1. Add them to `Scripts/ForensicFunctions.ps1`
2. Include proper help documentation
3. Test on a non-production system

## Disclaimer

This profile is intended for authorized forensic investigations only. Ensure compliance with legal and organizational policies before use.
