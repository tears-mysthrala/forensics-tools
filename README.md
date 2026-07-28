# PowerShell Forensics and Incident Response Profile

A specialized PowerShell profile designed for digital forensics and incident response investigations.

> **Status: laboratory / learning toolkit — no guarantees.**
> These scripts were built for experimentation and practice in lab environments.
> They are **not** a production DFIR platform, have **no** chain-of-custody,
> evidentiary-integrity, or support guarantees, and must not be relied upon as the
> sole basis for real incident-response or legal proceedings. Validate every output
> with established forensic tooling and methodology.

## Relationship with Oroitz

[Oroitz](https://github.com/tears-mysthrala/Oroitz) is a separate, educational
Python wrapper around Volatility 3 focused exclusively on memory forensics. This
repository is a much broader Windows-oriented PowerShell DFIR profile (registry,
event logs, browser artifacts, mobile, cloud, reporting, automation). The only
overlap is a thin set of PowerShell helpers that shell out to the Volatility 3 CLI
(`Scripts/Modules/SystemVolatilityAnalysis.ps1`, `VolatilityPlugins.ps1`, and the
`Memory*.ps1` modules); Oroitz already covers that use case in more depth
(sessions, caching, normalized output). The two projects are intentionally kept
separate: different language, scope, and audience.

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

## Testing

Pester 5 tests live in [`Tests/`](Tests/) and can be run with [`RunTests.ps1`](RunTests.ps1).
Coverage is partial (core modules only) and several modules have no tests at all —
treat untested modules as experimental.

## License

No `LICENSE` file is currently present in this repository. Earlier versions of this
README referenced the MIT License, but the license text was never committed. The
final license choice is a pending decision by the repository owner; until then, no
license is granted.
