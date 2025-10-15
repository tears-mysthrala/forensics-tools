# FileSystemFunctions.ps1 - File system analysis functions

function Get-FileHashes {
    <#
    .SYNOPSIS
        Computes hashes for files in a directory.
    .PARAMETER Path
        Directory path to scan.
    .PARAMETER Algorithm
        Hash algorithm (default: SHA256).
    .EXAMPLE
        Get-FileHashes -Path C:\Windows\System32
    #>
    param(
        [string]$Path,
        [string]$Algorithm = 'SHA256'
    )
    Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $hash = Get-FileHash $_.FullName -Algorithm $Algorithm
        [PSCustomObject]@{
            Path = $_.FullName
            Size = $_.Length
            LastWriteTime = $_.LastWriteTime
            Hash = $hash.Hash
            Algorithm = $Algorithm
        }
    }
}

function Analyze-File {
    <#
    .SYNOPSIS
        Basic file analysis: type, size, timestamps.
    .PARAMETER Path
        File path.
    .EXAMPLE
        Analyze-File -Path C:\example.txt
    #>
    param([string]$Path)
    if (Test-Path $Path) {
        $file = Get-Item $Path
        $type = if ($file.Extension) { $file.Extension } else { 'Unknown' }
        [PSCustomObject]@{
            Name = $file.Name
            FullPath = $file.FullName
            Size = $file.Length
            Created = $file.CreationTime
            Modified = $file.LastWriteTime
            Accessed = $file.LastAccessTime
            Type = $type
            Attributes = $file.Attributes
        }
    } else {
        Write-Warning "File not found: $Path"
    }
}

function Get-RecentFiles {
    <#
    .SYNOPSIS
        Finds files modified within the last X days.
    .PARAMETER Days
        Number of days to look back (default: 7).
    .PARAMETER Path
        Directory to search (default: C:\).
    .EXAMPLE
        Get-RecentFiles -Days 1 -Path C:\Users
    #>
    param(
        [int]$Days = 7,
        [string]$Path = "C:\"
    )
    $cutoffDate = (Get-Date).AddDays(-$Days)
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $cutoffDate } |
    Select-Object FullName, LastWriteTime, Length |
    Sort-Object LastWriteTime -Descending
}

function Get-LargeFiles {
    <#
    .SYNOPSIS
        Finds files larger than specified size.
    .PARAMETER MinSizeMB
        Minimum file size in MB (default: 100).
    .PARAMETER Path
        Directory to search (default: C:\).
    .EXAMPLE
        Get-LargeFiles -MinSizeMB 500 -Path C:\Users
    #>
    param(
        [int]$MinSizeMB = 100,
        [string]$Path = "C:\"
    )
    $minSize = $MinSizeMB * 1MB
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt $minSize } |
    Select-Object FullName, @{Name="SizeMB";Expression={[math]::Round($_.Length/1MB,2)}}, LastWriteTime |
    Sort-Object SizeMB -Descending
}

function Get-AlternateDataStreams {
    <#
    .SYNOPSIS
        Scans for alternate data streams in files.
    .PARAMETER Path
        Directory to scan (default: current directory).
    .EXAMPLE
        Get-AlternateDataStreams -Path C:\Suspicious
    #>
    param([string]$Path = ".")
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
        $streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue |
        Where-Object { $_.Stream -ne ':$DATA' }

        foreach ($stream in $streams) {
            [PSCustomObject]@{
                FilePath = $_.FullName
                StreamName = $stream.Stream
                Size = $stream.Size
            }
        }
    }
}