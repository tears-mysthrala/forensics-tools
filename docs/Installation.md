# Installation Guide

This guide covers the installation and setup of the PowerShell Forensics and Incident Response Profile.

## Prerequisites

- **Windows 10/11** or **Windows Server 2016+**
- **Administrator privileges** for most forensic operations
- **Internet access** for downloading tools and dependencies

### PowerShell Compatibility

The toolkit now supports multiple PowerShell versions:

- **PowerShell 7.0+**: Full functionality with modern features
- **PowerShell 5.1**: Legacy compatibility mode with portable PowerShell Core
- **CMD/Command Prompt**: Basic launcher support via batch files

## Quick Installation

### Universal Installer (Recommended)

```powershell
# Run the universal installer - it automatically detects your PowerShell version
.\Install-ForensicsToolkit.ps1
```

This installer will:
- Detect your PowerShell version
- Set up portable PowerShell Core if needed (for PS 5.1 systems)
- Install required forensic tools
- Create appropriate launchers

### Option 1: Direct Download

```powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/tears-mysthrala/forensics-tools/archive/main.zip" -OutFile "forensics-tools.zip"
Expand-Archive -Path "forensics-tools.zip" -DestinationPath "."
cd forensics-tools-main

# Run installer
.\Install-ForensicsToolkit.ps1
```

### Option 2: Git Clone

```powershell
# Clone the repository
git clone https://github.com/tears-mysthrala/forensics-tools.git
cd forensics-tools

# Run installer
.\Install-ForensicsToolkit.ps1
```

## Installation Modes

### Automatic Mode (Default)

The installer automatically detects your environment:

- **PowerShell 7.0+**: Uses native installation with full features
- **PowerShell 5.1**: Sets up portable PowerShell Core for compatibility
- **Force Portable**: Use `-PortableMode` to force portable installation

### Portable Mode

For USB drives, shared drives, or systems without PowerShell 7.0+:

```powershell
# Force portable mode installation
.\Install-ForensicsToolkit.ps1 -PortableMode
```

### Desktop Installation

Install to a specific location (like desktop):

```powershell
# Install to desktop
.\Install-ForensicsToolkit.ps1 -InstallPath "$env:USERPROFILE\Desktop\forensics-tools"
```

## Profile Integration

### PowerShell 7.0+ Systems

```powershell
# Load the forensic functions when needed
. .\Scripts\ForensicFunctions.ps1
```

### PowerShell 5.1 / Portable Mode

```powershell
# Launch using the portable launcher
.\Launch-ForensicsToolkit.ps1

# Or from CMD/Command Prompt
.\Launch-ForensicsToolkit.cmd
```

### Option 3: USB-Compatible Setup

```powershell
# For USB drives or portable installations
$forensicPath = "D:\Forensics"  # Adjust path as needed
. "$forensicPath\Launch-ForensicsToolkit.ps1"
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
