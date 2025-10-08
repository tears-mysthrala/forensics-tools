# Installation Guide

This guide covers the installation and setup of the PowerShell Forensics and Incident Response Profile.

## Prerequisites

- **PowerShell 7.0+** (Windows PowerShell 5.1 has limited functionality)
- **Windows 10/11** or **Windows Server 2016+**
- **Administrator privileges** for most forensic operations
- **Internet access** for downloading tools and dependencies

## Quick Installation

### Option 1: Direct Download

```powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/tears-mysthrala/forensics-tools/archive/main.zip" -OutFile "forensics-tools.zip"
Expand-Archive -Path "forensics-tools.zip" -DestinationPath "."
cd forensics-tools-main

# Load the profile
. .\Scripts\ForensicFunctions.ps1
```

### Option 2: Git Clone

```powershell
# Clone the repository
git clone https://github.com/tears-mysthrala/forensics-tools.git
cd forensics-tools

# Load the profile
. .\Scripts\ForensicFunctions.ps1
```

## Profile Integration

### Option 1: Load on Demand

```powershell
# Load the forensic functions when needed
. .\Scripts\ForensicFunctions.ps1
```

### Option 2: Add to PowerShell Profile

```powershell
# Add to your PowerShell profile ($PROFILE)
Add-Content -Path $PROFILE -Value ". `"$PSScriptRoot\Scripts\ForensicFunctions.ps1`""
```

### Option 3: USB-Compatible Setup

```powershell
# For USB drives or portable installations
$forensicPath = "D:\Forensics"  # Adjust path as needed
. "$forensicPath\Scripts\ForensicFunctions.ps1"
```

## Required Tools and Dependencies

The profile includes a comprehensive installation function that automatically downloads and installs all required forensic tools:

### Automatic Installation

```powershell
# Install all required forensic tools automatically
Install-ForensicTools
```

This command will install:

- **WinPMEM** - Memory acquisition tool
- **Python 3.11+** - Required for advanced memory analysis
- **Volatility3** - Memory forensics framework
- **YARA** - Pattern matching tool for malware analysis
- **Azure CLI** - For cloud forensics operations
- **Wireshark/TShark** - Network packet analysis
- **Python packages** - pefile, yara-python, construct, and others

### Manual Installation

If automatic installation fails or you prefer manual control, you can install tools individually:

#### Python and Volatility3

```powershell
# Install Python 3.8+
winget install Python.Python.3.11

# Install Volatility3
pip install volatility3
```

#### YARA

```powershell
# Download and install YARA from GitHub releases
# https://github.com/VirusTotal/yara/releases
```

#### Azure CLI (for cloud forensics)

```powershell
# Install Azure CLI
winget install Microsoft.AzureCLI
```

## Module Dependencies

| Module | Dependencies | Installation |
|--------|-------------|--------------|
| Core System | None | Built-in |
| Network | None | Built-in |
| File System | None | Built-in |
| Registry | None | Built-in |
| Event Logs | None | Built-in |
| Memory | WinPMEM (optional) | `Install-ForensicTools` |
| Advanced Memory | Python, Volatility3 | `pip install volatility3` |
| Advanced Network | Wireshark/tshark | `Install-ForensicTools` |
| Advanced File System | None | Built-in |
| Malware Analysis | YARA | Manual download |
| Cloud Forensics | Azure CLI/PowerShell | `winget install Microsoft.AzureCLI` |
| Reporting | None | Built-in |
| Automation | None | Built-in |

## Verification

After installation, verify the setup:

```powershell
# Check if functions are loaded
Get-Command -Module ForensicFunctions

# Test basic functionality
Get-SystemInfo

# Test advanced features
Get-VolatilityPlugins  # Requires Python/Volatility3
```

## Troubleshooting

### Common Issues

#### Execution Policy Errors

```powershell
# Set execution policy for current session
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# Or set globally (requires admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
```

#### Module Loading Errors

```powershell
# Check if files exist
Test-Path "Scripts\ForensicFunctions.ps1"

# Check PowerShell version
$PSVersionTable.PSVersion
```

#### Tool Installation Failures

```powershell
# Manual tool installation
Install-ForensicTools -Verbose

# Check installation logs
Get-Content "$env:TEMP\ForensicTools_Install.log"
```

### Support

If you encounter issues:

1. Check the [Usage Examples](UsageExamples.md)
2. Verify prerequisites are met
3. Run with `-Verbose` flag for detailed output
4. Check PowerShell execution policy
5. Ensure administrator privileges for forensic operations

## USB Deployment

For portable/USB deployments:

```powershell
# Create portable forensic toolkit
$usbDrive = "E:\"  # Adjust drive letter
Copy-Item -Path ".\*" -Destination $usbDrive -Recurse

# Load from USB
. "$usbDrive\Scripts\ForensicFunctions.ps1"
```

## Enterprise Deployment

For enterprise environments:

1. Clone repository to network share
2. Create group policy for profile loading
3. Configure SIEM integration
4. Set up automated evidence collection workflows
5. Deploy scheduled tasks via GPO

See [Automation](Automation.md) for enterprise integration details.