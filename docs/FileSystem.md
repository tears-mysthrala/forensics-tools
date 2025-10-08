# File System Functions

File analysis, hashing, and metadata extraction functions.

## Functions

### Get-FileHashes

Computes hashes for files in a directory.

```powershell
Get-FileHashes -Path "C:\Suspicious"
Get-FileHashes -Path "C:\Windows\System32" -Algorithm SHA256
```

**Parameters:**

- `Path`: Directory or file path to hash
- `Algorithm`: Hash algorithm (MD5, SHA1, SHA256, SHA384, SHA512)
- `Recursive`: Include subdirectories
- `IncludeHidden`: Include hidden files

**Returns:**

- File path, size, timestamps
- Hash values for specified algorithms

### Analyze-File

Provides detailed file metadata.

```powershell
Analyze-File -Path "C:\Windows\System32\cmd.exe"
```

**Parameters:**

- `Path`: File path to analyze

**Returns:**

- File properties, timestamps, permissions
- Hash values, signature information
- Alternate data streams

### Get-RecentFiles

Finds files modified within last X days.

```powershell
Get-RecentFiles -Days 1 -Path "C:\Users"
```

**Parameters:**

- `Days`: Number of days to look back
- `Path`: Starting directory path
- `MaxFiles`: Maximum number of files to return

**Returns:**

- File path, size, modification time
- Creation and access times

### Get-LargeFiles

Finds files larger than specified size.

```powershell
Get-LargeFiles -MinSizeMB 500 -Path "C:\"
```

**Parameters:**

- `MinSizeMB`: Minimum file size in MB
- `Path`: Directory to search
- `MaxFiles`: Maximum files to return

**Returns:**

- File path, size, timestamps

### Get-AlternateDataStreams

Scans for alternate data streams.

```powershell
Get-AlternateDataStreams -Path "C:\"
```

**Parameters:**

- `Path`: Directory to scan
- `Recursive`: Include subdirectories

**Returns:**

- File path, stream name, size
- Stream content preview