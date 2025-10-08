# Advanced Memory Forensics

Advanced memory forensics with Volatility plugins and artifact extraction.

## Functions

### Get-VolatilityPlugins

Lists all available Volatility 3 plugins.

```powershell
Get-VolatilityPlugins
```

**Returns:**

- Plugin name and description
- Category and requirements

### Invoke-VolatilityAnalysis

Runs comprehensive Volatility analysis.

```powershell
Invoke-VolatilityAnalysis -MemoryDump "C:\Evidence\memory.dmp" -AnalysisType full -OutputPath "C:\Analysis"
```

**Parameters:**

- `MemoryDump`: Path to memory dump
- `AnalysisType`: Analysis type (processes, network, filesystem, malware, timeline)
- `OutputPath`: Directory for results

**Returns:**

- Comprehensive analysis results
- Timeline data and artifacts

### Get-ProcessMemoryDump

Dumps memory of specific processes.

```powershell
Get-ProcessMemoryDump -ProcessName "notepad" -OutputPath "C:\Evidence"
```

**Parameters:**

- `ProcessName`: Name of process to dump
- `ProcessId`: Process ID to dump
- `OutputPath`: Directory for dump files

**Returns:**

- Process dump files
- Memory region information

### Get-MemoryTimeline

Creates chronological timeline from memory artifacts.

```powershell
Get-MemoryTimeline -MemoryDump "C:\Evidence\memory.dmp" -OutputPath "C:\Analysis"
```

**Parameters:**

- `MemoryDump`: Path to memory dump
- `OutputPath`: Directory for timeline data

**Returns:**

- Timeline JSON data
- Chronological event sequence

### Get-MemoryStrings

Extracts readable strings from memory dumps.

```powershell
Get-MemoryStrings -MemoryDump "C:\Evidence\memory.dmp" -MinLength 8 -OutputPath "C:\Analysis"
```

**Parameters:**

- `MemoryDump`: Path to memory dump
- `MinLength`: Minimum string length
- `OutputPath`: Directory for results

**Returns:**

- Extracted strings with offsets
- ASCII and Unicode strings

### Get-MemoryArtifacts

Collects memory-resident artifacts.

```powershell
Get-MemoryArtifacts -OutputPath "C:\Evidence"
```

**Parameters:**

- `OutputPath`: Directory for artifacts

**Returns:**

- Clipboard contents, environment variables
- Command history, network connections

### Invoke-MemoryForensicAnalysis

Complete memory forensics workflow.

```powershell
Invoke-MemoryForensicAnalysis -OutputPath "C:\MemoryAnalysis" -IncludeProcessDumps $true
```

**Parameters:**

- `OutputPath`: Directory for complete analysis
- `IncludeProcessDumps`: Include individual process dumps

**Returns:**

- Complete memory analysis package
- Timeline, artifacts, and reports