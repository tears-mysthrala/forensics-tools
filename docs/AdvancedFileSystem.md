# Advanced File System Forensics

Advanced file system forensics with carving, timelines, and anomaly detection.

## Functions

### Get-FileSignatures

Analyzes file signatures and headers for forensic insights.

```powershell
Get-FileSignatures -Path "C:\SuspiciousFiles"
```

**Parameters:**

- `Path`: Directory to analyze
- `OutputPath`: Directory for results

**Returns:**

- File signature analysis
- Extension mismatches, header validation

### Get-FileCarving

Performs file carving to recover deleted or hidden files.

```powershell
Get-FileCarving -Path "C:\RecoveredFiles"
```

**Parameters:**

- `Path`: Directory for carved files
- `Signatures`: File signatures to carve for

**Returns:**

- Recovered files from unallocated space
- Carving statistics and metadata

### Get-FileSystemTimeline

Creates comprehensive chronological timelines of file system activity.

```powershell
Get-FileSystemTimeline -Path "C:\" -OutputPath "C:\Timeline"
```

**Parameters:**

- `Path`: Directory to analyze
- `OutputPath`: Directory for timeline data

**Returns:**

- Chronological file system events
- Timeline JSON for visualization

### Get-DeletedFilesAnalysis

Analyzes traces of deleted files and recoverable data.

```powershell
Get-DeletedFilesAnalysis -Path "C:\" -OutputPath "C:\DeletedAnalysis"
```

**Parameters:**

- `Path`: Directory to analyze
- `OutputPath`: Directory for results

**Returns:**

- Deleted file traces
- Recoverable data analysis

### Get-FileAnomalyDetection

Detects file system anomalies and suspicious file activity.

```powershell
Get-FileAnomalyDetection -Path "C:\Suspicious" -OutputPath "C:\Anomalies"
```

**Parameters:**

- `Path`: Directory to analyze
- `OutputPath`: Directory for results

**Returns:**

- File system anomalies
- Suspicious activity patterns

### Invoke-AdvancedFileSystemAnalysis

Complete file system forensics workflow.

```powershell
Invoke-AdvancedFileSystemAnalysis -Path "C:\Suspicious" -OutputPath "C:\Analysis" -IncludeCarving $true
```

**Parameters:**

- `Path`: Directory to analyze
- `OutputPath`: Directory for complete analysis
- `IncludeCarving`: Include file carving

**Returns:**

- Comprehensive file system analysis
- Timeline, anomalies, and recovered files