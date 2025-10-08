# Memory Functions

Memory dumping and basic Volatility analysis functions.

## Functions

### Get-MemoryDump

Captures live memory dumps using various methods.

```powershell
Get-MemoryDump -OutputPath "C:\Evidence" -Method PowerShell
```

**Parameters:**

- `OutputPath`: Directory to save memory dump
- `Method`: Dump method (PowerShell, WinPMEM, DumpIt)

**Returns:**

- Dump file path and size
- Capture method and timestamp

### Get-VolatilityAnalysis

Performs Volatility 3 analysis on memory dumps.

```powershell
Get-VolatilityAnalysis -MemoryDump "C:\Evidence\memory.dmp" -AnalysisType pslist
```

**Parameters:**

- `MemoryDump`: Path to memory dump file
- `AnalysisType`: Analysis type (pslist, pstree, netscan, etc.)

**Returns:**

- Analysis results based on type
- Formatted output for forensic review

### Collect-SystemEvidence

Gathers comprehensive system evidence.

```powershell
Collect-SystemEvidence -OutputPath "C:\Evidence"
```

**Parameters:**

- `OutputPath`: Directory for evidence collection
- `IncludeMemory`: Include memory dump

**Returns:**

- Evidence files and metadata
- Collection timestamp and status