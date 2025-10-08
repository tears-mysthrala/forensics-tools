# Core System Functions

Core system analysis functions for basic forensic information gathering.

## Functions

### Get-SystemInfo

Retrieves basic system details for forensic analysis.

```powershell
Get-SystemInfo
```

**Returns:**

- Computer name, domain, OS version
- Hardware information (CPU, RAM, disks)
- Network configuration
- Current user and privileges

### Get-ProcessDetails

Enhanced process listing with file paths and hashes.

```powershell
Get-ProcessDetails
Get-ProcessDetails -IncludeHashes
```

**Parameters:**

- `IncludeHashes`: Include file hashes for process executables

**Returns:**

- Process ID, name, path, command line
- Owner, CPU/memory usage
- File hashes (if requested)

### Get-UserAccounts

Lists user accounts and their status.

```powershell
Get-UserAccounts
Get-UserAccounts -IncludeDisabled
```

**Parameters:**

- `IncludeDisabled`: Include disabled accounts

**Returns:**

- Username, full name, description
- Account status, last login
- Group memberships

### Get-ServicesStatus

Shows running services and their configuration.

```powershell
Get-ServicesStatus
Get-ServicesStatus -RunningOnly
```

**Parameters:**

- `RunningOnly`: Show only running services

**Returns:**

- Service name, display name, status
- Start mode, account, description

### Get-ScheduledTasks

Lists scheduled tasks and their properties.

```powershell
Get-ScheduledTasks
Get-ScheduledTasks -IncludeDisabled
```

**Parameters:**

- `IncludeDisabled`: Include disabled tasks

**Returns:**

- Task name, path, status
- Triggers, actions, run level

### Get-StartupPrograms

Lists programs configured to start automatically.

```powershell
Get-StartupPrograms
```

**Returns:**

- Program name, command, location
- Registry key or startup folder path

### Get-InstalledSoftware

Lists installed software from registry.

```powershell
Get-InstalledSoftware
Get-InstalledSoftware -Publisher "Microsoft"
```

**Parameters:**

- `Publisher`: Filter by software publisher

**Returns:**

- Display name, version, publisher
- Install date, uninstall command