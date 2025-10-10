# PowerShell Forensics and Incident Response Profile

A specialized PowerShell profile designed for digital forensics and incident response investigations.

## Quick Start

```powershell
# Clone the repository
git clone https://github.com/tears-mysthrala/forensics-tools.git
cd forensics-tools

# Option 1: Manual load (one-time per session)
. .\Scripts\ForensicFunctions.ps1

# Option 2: Auto-load on shell start (set as PowerShell profile)
# Copy or link Microsoft.PowerShell_profile.ps1 to $PROFILE
# For example:
Copy-Item .\Microsoft.PowerShell_profile.ps1 $PROFILE -Force
```

## Features

- **Modular Architecture**: Functions organized into logical modules for better maintainability
- **Comprehensive Forensics**: Memory, network, filesystem, malware, and cloud forensics
- **Automation & Orchestration**: Scheduled tasks, workflow orchestration, and SIEM integration
- **Interactive Reporting**: HTML dashboards, timeline visualizations, and evidence correlation
- **Enterprise Ready**: Error handling, logging, and scalable architecture

## Module Overview

| Module | Description | Documentation |
|--------|-------------|---------------|
| Core System | System information, processes, users, services | [Core System](docs/CoreSystem.md) |
| Network | Network connections, shares, USB history | [Network](docs/Network.md) |
| File System | File analysis, hashes, alternate data streams | [File System](docs/FileSystem.md) |
| Registry | Registry forensics and persistence analysis | [Registry](docs/Registry.md) |
| Event Logs | Event log analysis and security monitoring | [Event Logs](docs/EventLogs.md) |
| Memory | Memory dumping and Volatility analysis | [Memory](docs/Memory.md) |
| Advanced Memory | Volatility plugins, process dumps, timelines | [Advanced Memory](docs/AdvancedMemory.md) |
| Advanced Network | Packet capture, traffic analysis, DNS | [Advanced Network](docs/AdvancedNetwork.md) |
| Advanced File System | File carving, timelines, anomaly detection | [Advanced File System](docs/AdvancedFileSystem.md) |
| Malware Analysis | YARA scanning, static analysis, behavioral monitoring | [Malware Analysis](docs/MalwareAnalysis.md) |
| Cloud Forensics | Azure resource inventory, logs, storage | [Cloud Forensics](docs/CloudForensics.md) |
| Reporting | Interactive HTML reports and visualizations | [Reporting](docs/Reporting.md) |
| Automation | Scheduled tasks, orchestration, SIEM integration | [Automation](docs/Automation.md) |

## Installation

See [Installation Guide](docs/Installation.md) for detailed setup instructions.

## Usage Examples

See [Usage Examples](docs/UsageExamples.md) for comprehensive command examples.

## Contributing

1. Follow the modular architecture
2. Add comprehensive error handling
3. Include detailed documentation
4. Test functions thoroughly
5. Update relevant documentation files

## License

This project is licensed under the MIT License - see the LICENSE file for details.
