# AdvancedFileSystemFunctions.ps1 - Advanced file system forensics and analysis

function Get-FileSignatures {
    <#
    .SYNOPSIS
        Analyzes file signatures and headers for forensic insights.
    .DESCRIPTION
        Examines file headers, magic bytes, and signatures to identify file types and potential tampering.
    .PARAMETER Path
        Directory or file path to analyze.
    .PARAMETER OutputPath
        Directory to save signature analysis results.
    .EXAMPLE
        Get-FileSignatures -Path C:\Windows\System32 -OutputPath C:\Analysis
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$OutputPath = "."
    )

    Write-Host "Analyzing file signatures..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "FileSignatures_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    # Common file signatures (magic bytes)
    $fileSignatures = @{
        "FFD8FF" = "JPEG Image"
        "89504E47" = "PNG Image"
        "47494638" = "GIF Image"
        "424D" = "BMP Image"
        "4D5A" = "Windows Executable (PE)"
        "7F454C46" = "ELF Executable"
        "504B0304" = "ZIP Archive"
        "52617221" = "RAR Archive"
        "377ABCAF271C" = "7-Zip Archive"
        "255044462D" = "PDF Document"
        "D0CF11E0A1B11AE1" = "Microsoft Office Document"
        "000001BA" = "MPEG Video"
        "000001B3" = "MPEG Video"
        "464C5601" = "FLV Video"
        "1F8B08" = "GZIP Archive"
        "425A68" = "BZIP2 Archive"
    }

    $signatureAnalysis = @{
        Timestamp = Get-Date
        Path = $Path
        Signatures = @{}
    }

    Write-Host "Scanning files for signatures..." -ForegroundColor Yellow

    try {
        $files = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1000  # Limit for performance

        $results = @()
        foreach ($file in $files) {
            try {
                # Read first 16 bytes for signature analysis
                $bytes = [System.IO.File]::ReadAllBytes($file.FullName)[0..15]
                $hexSignature = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""

                # Check against known signatures
                $identifiedType = "Unknown"
                foreach ($sig in $fileSignatures.Keys) {
                    if ($hexSignature.StartsWith($sig)) {
                        $identifiedType = $fileSignatures[$sig]
                        break
                    }
                }

                # Check for extension mismatch
                $extension = $file.Extension.ToLower()
                $expectedExtension = switch ($identifiedType) {
                    "JPEG Image" { ".jpg"; ".jpeg" }
                    "PNG Image" { ".png" }
                    "GIF Image" { ".gif" }
                    "BMP Image" { ".bmp" }
                    "Windows Executable (PE)" { ".exe"; ".dll"; ".sys" }
                    "ELF Executable" { ".elf" }
                    "ZIP Archive" { ".zip" }
                    "RAR Archive" { ".rar" }
                    "7-Zip Archive" { ".7z" }
                    "PDF Document" { ".pdf" }
                    "Microsoft Office Document" { ".doc"; ".xls"; ".ppt" }
                    "MPEG Video" { ".mpg"; ".mpeg" }
                    "FLV Video" { ".flv" }
                    "GZIP Archive" { ".gz" }
                    "BZIP2 Archive" { ".bz2" }
                    default { $null }
                }

                $extensionMismatch = $false
                if ($expectedExtension -and $expectedExtension -notcontains $extension) {
                    $extensionMismatch = $true
                }

                $results += [PSCustomObject]@{
                    FileName = $file.Name
                    FullPath = $file.FullName
                    Size = $file.Length
                    Extension = $extension
                    IdentifiedType = $identifiedType
                    HexSignature = $hexSignature
                    ExtensionMismatch = $extensionMismatch
                    LastWriteTime = $file.LastWriteTime
                }

            } catch {
                Write-Warning "Failed to analyze $($file.FullName): $($_.Exception.Message)"
            }
        }

        # Export results
        $results | Export-Csv (Join-Path $analysisDir "file_signatures.csv") -NoTypeInformation

        # Analyze mismatches
        $mismatches = $results | Where-Object { $_.ExtensionMismatch }
        if ($mismatches) {
            $mismatches | Export-Csv (Join-Path $analysisDir "extension_mismatches.csv") -NoTypeInformation
            $signatureAnalysis.Signatures.ExtensionMismatches = $mismatches.Count
            Write-Host "⚠ Found $($mismatches.Count) files with extension mismatches" -ForegroundColor Red
        } else {
            $signatureAnalysis.Signatures.ExtensionMismatches = 0
            Write-Host "✓ No extension mismatches found" -ForegroundColor Green
        }

        # Analyze by type
        $typeSummary = $results | Group-Object IdentifiedType | Sort-Object Count -Descending
        $typeSummary | Export-Csv (Join-Path $analysisDir "file_types_summary.csv") -NoTypeInformation

        $signatureAnalysis.Signatures.TotalFiles = $results.Count
        $signatureAnalysis.Signatures.FileTypes = $typeSummary

        Write-Host "✓ Analyzed $($results.Count) files" -ForegroundColor Green

    } catch {
        Write-Warning "Failed to analyze file signatures: $($_.Exception.Message)"
        $signatureAnalysis.Signatures.Error = $_.Exception.Message
    }

    # Save analysis summary
    $summaryFile = Join-Path $analysisDir "file_signature_analysis.json"
    $signatureAnalysis | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "File signature analysis complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}

function Get-FileCarving {
    <#
    .SYNOPSIS
        Performs file carving to recover deleted or hidden files.
    .DESCRIPTION
        Scans raw disk sectors or unallocated space to recover files based on signatures.
    .PARAMETER DriveLetter
        Drive letter to scan (e.g., "C:").
    .PARAMETER OutputPath
        Directory to save carved files.
    .PARAMETER FileTypes
        Types of files to carve (default: common executables and documents).
    .EXAMPLE
        Get-FileCarving -DriveLetter "C:" -OutputPath C:\CarvedFiles
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$DriveLetter,
        [string]$OutputPath = ".",
        [string[]]$FileTypes = @("exe", "dll", "pdf", "doc", "jpg", "png")
    )

    Write-Host "Starting file carving on drive $DriveLetter..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $carvingDir = Join-Path $OutputPath "FileCarving_$timestamp"

    if (-not (Test-Path $carvingDir)) {
        New-Item -ItemType Directory -Path $carvingDir -Force | Out-Null
    }

    # File signatures for carving
    $carveSignatures = @{
        "exe" = @{ Signature = "4D5A"; Extension = ".exe"; Description = "Windows Executable" }
        "dll" = @{ Signature = "4D5A"; Extension = ".dll"; Description = "Windows DLL" }
        "pdf" = @{ Signature = "255044462D"; Extension = ".pdf"; Description = "PDF Document" }
        "doc" = @{ Signature = "D0CF11E0A1B11AE1"; Extension = ".doc"; Description = "Microsoft Word Document" }
        "jpg" = @{ Signature = "FFD8FF"; Extension = ".jpg"; Description = "JPEG Image" }
        "png" = @{ Signature = "89504E47"; Extension = ".png"; Description = "PNG Image" }
        "zip" = @{ Signature = "504B0304"; Extension = ".zip"; Description = "ZIP Archive" }
    }

    $carvingResults = @{
        Timestamp = Get-Date
        Drive = $DriveLetter
        FileTypes = $FileTypes
        Results = @{}
    }

    Write-Host "This is a basic file carving implementation." -ForegroundColor Yellow
    Write-Host "For advanced carving, consider using tools like:" -ForegroundColor Yellow
    Write-Host "  - Autopsy (https://www.autopsy.com/)" -ForegroundColor Yellow
    Write-Host "  - Scalpel (https://github.com/sleuthkit/scalpel)" -ForegroundColor Yellow
    Write-Host "  - Foremost (http://foremost.sourceforge.net/)" -ForegroundColor Yellow

    # Basic carving using PowerShell (limited but demonstrates concept)
    Write-Host "Performing basic signature-based carving..." -ForegroundColor Yellow

    foreach ($type in $FileTypes) {
        if ($carveSignatures.ContainsKey($type)) {
            $sig = $carveSignatures[$type]
            Write-Host "Carving $($sig.Description) files..." -ForegroundColor Gray

            try {
                # This is a simplified carving approach
                # In practice, you'd need to read raw disk sectors
                $foundFiles = Get-ChildItem -Path $DriveLetter -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object {
                        try {
                            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)[0..15]
                            $hexSig = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""
                            $hexSig.StartsWith($sig.Signature)
                        } catch {
                            $false
                        }
                    } | Select-Object -First 10  # Limit results

                if ($foundFiles) {
                    $typeDir = Join-Path $carvingDir $type
                    if (-not (Test-Path $typeDir)) {
                        New-Item -ItemType Directory -Path $typeDir -Force | Out-Null
                    }

                    $results = @()
                    foreach ($file in $foundFiles) {
                        $destFile = Join-Path $typeDir ($file.Name + "_carved" + $sig.Extension)
                        Copy-Item $file.FullName $destFile -ErrorAction SilentlyContinue
                        $results += [PSCustomObject]@{
                            OriginalPath = $file.FullName
                            CarvedPath = $destFile
                            Size = $file.Length
                            LastWriteTime = $file.LastWriteTime
                        }
                    }

                    $results | Export-Csv (Join-Path $typeDir "carved_files.csv") -NoTypeInformation
                    $carvingResults.Results[$type] = "Found $($results.Count) files"
                    Write-Host "✓ Carved $($results.Count) $($sig.Description) files" -ForegroundColor Green
                } else {
                    $carvingResults.Results[$type] = "No files found"
                }

            } catch {
                Write-Warning "Failed to carve $type files: $($_.Exception.Message)"
                $carvingResults.Results[$type] = "Error: $($_.Exception.Message)"
            }
        }
    }

    # Save carving summary
    $summaryFile = Join-Path $carvingDir "file_carving_summary.json"
    $carvingResults | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "File carving complete!" -ForegroundColor Green
    Write-Host "Results saved to: $carvingDir" -ForegroundColor Cyan
    Write-Host "Note: This is a basic implementation. Use specialized tools for comprehensive carving." -ForegroundColor Yellow

    return $carvingDir
}

function Get-FileSystemTimeline {
    <#
    .SYNOPSIS
        Creates a comprehensive file system timeline.
    .DESCRIPTION
        Analyzes file system metadata to create chronological timelines of file activity.
    .PARAMETER Path
        Directory path to analyze.
    .PARAMETER OutputPath
        Directory to save timeline results.
    .PARAMETER Days
        Number of days to look back (default: 30).
    .EXAMPLE
        Get-FileSystemTimeline -Path C:\ -OutputPath C:\Timeline
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$OutputPath = ".",
        [int]$Days = 30
    )

    Write-Host "Creating file system timeline..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $timelineDir = Join-Path $OutputPath "FileSystemTimeline_$timestamp"

    if (-not (Test-Path $timelineDir)) {
        New-Item -ItemType Directory -Path $timelineDir -Force | Out-Null
    }

    $timelineData = @{
        Timestamp = Get-Date
        Path = $Path
        DaysAnalyzed = $Days
        Timeline = @()
    }

    $cutoffDate = (Get-Date).AddDays(-$Days)

    Write-Host "Scanning file system for timeline data (last $Days days)..." -ForegroundColor Yellow

    try {
        # Get all files and directories
        $items = Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoffDate } |
            Select-Object FullName, Name, Length, CreationTime, LastWriteTime, LastAccessTime, Attributes

        $timeline = @()

        foreach ($item in $items) {
            # Creation event
            if ($item.CreationTime -gt $cutoffDate) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $item.CreationTime
                    EventType = "File Created"
                    Path = $item.FullName
                    Size = $item.Length
                    Attributes = $item.Attributes
                }
            }

            # Last write event
            if ($item.LastWriteTime -gt $cutoffDate) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $item.LastWriteTime
                    EventType = "File Modified"
                    Path = $item.FullName
                    Size = $item.Length
                    Attributes = $item.Attributes
                }
            }

            # Last access event (if different from write)
            if ($item.LastAccessTime -gt $cutoffDate -and
                [math]::Abs(($item.LastAccessTime - $item.LastWriteTime).TotalMinutes) -gt 1) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $item.LastAccessTime
                    EventType = "File Accessed"
                    Path = $item.FullName
                    Size = $item.Length
                    Attributes = $item.Attributes
                }
            }
        }

        # Sort timeline by timestamp
        $timeline = $timeline | Sort-Object Timestamp

        # Export timeline
        $timeline | Export-Csv (Join-Path $timelineDir "filesystem_timeline.csv") -NoTypeInformation

        # Create summary by event type
        $eventSummary = $timeline | Group-Object EventType | Sort-Object Count -Descending
        $eventSummary | Export-Csv (Join-Path $timelineDir "timeline_summary.csv") -NoTypeInformation

        # Create hourly activity chart
        $hourlyActivity = $timeline | Group-Object { $_.Timestamp.Hour } |
            Sort-Object Name |
            Select-Object @{Name="Hour";Expression={$_.Name}}, Count
        $hourlyActivity | Export-Csv (Join-Path $timelineDir "hourly_activity.csv") -NoTypeInformation

        $timelineData.Timeline = $timeline
        $timelineData.TotalEvents = $timeline.Count
        $timelineData.EventSummary = $eventSummary

        Write-Host "✓ Created timeline with $($timeline.Count) events" -ForegroundColor Green
        Write-Host "  Date range: $cutoffDate to $(Get-Date)" -ForegroundColor Cyan

    } catch {
        Write-Warning "Failed to create file system timeline: $($_.Exception.Message)"
        $timelineData.Error = $_.Exception.Message
    }

    # Save timeline metadata
    $metadataFile = Join-Path $timelineDir "timeline_metadata.json"
    $timelineData | ConvertTo-Json -Depth 3 | Out-File $metadataFile

    Write-Host "File system timeline complete!" -ForegroundColor Green
    Write-Host "Results saved to: $timelineDir" -ForegroundColor Cyan

    return $timelineDir
}

function Get-DeletedFilesAnalysis {
    <#
    .SYNOPSIS
        Analyzes traces of deleted files and recoverable data.
    .DESCRIPTION
        Examines file system for deleted file artifacts and recovery possibilities.
    .PARAMETER DriveLetter
        Drive letter to analyze.
    .PARAMETER OutputPath
        Directory to save analysis results.
    .EXAMPLE
        Get-DeletedFilesAnalysis -DriveLetter "C:" -OutputPath C:\Analysis
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$DriveLetter,
        [string]$OutputPath = "."
    )

    Write-Host "Analyzing deleted files and recovery traces..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "DeletedFilesAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $deletedAnalysis = @{
        Timestamp = Get-Date
        Drive = $DriveLetter
        Analysis = @{}
    }

    # Check Recycle Bin
    Write-Host "Analyzing Recycle Bin contents..." -ForegroundColor Yellow
    try {
        $recycleBin = "$DriveLetter\$Recycle.Bin"
        if (Test-Path $recycleBin) {
            $recycleItems = Get-ChildItem -Path $recycleBin -Recurse -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } |
                Select-Object FullName, Name, Length, LastWriteTime

            if ($recycleItems) {
                $recycleItems | Export-Csv (Join-Path $analysisDir "recycle_bin_contents.csv") -NoTypeInformation
                $deletedAnalysis.Analysis.RecycleBinItems = $recycleItems.Count
                Write-Host "✓ Found $($recycleItems.Count) items in Recycle Bin" -ForegroundColor Green
            } else {
                $deletedAnalysis.Analysis.RecycleBinItems = 0
                Write-Host "✓ Recycle Bin is empty" -ForegroundColor Green
            }
        } else {
            $deletedAnalysis.Analysis.RecycleBinItems = "Recycle Bin not accessible"
        }
    } catch {
        Write-Warning "Failed to analyze Recycle Bin: $($_.Exception.Message)"
        $deletedAnalysis.Analysis.RecycleBinItems = "Error: $($_.Exception.Message)"
    }

    # Check for shadow copies
    Write-Host "Checking Volume Shadow Copies..." -ForegroundColor Yellow
    try {
        $shadowCopies = vssadmin list shadows /for=$DriveLetter 2>$null |
            Select-String "Shadow Copy Volume:" |
            ForEach-Object { $_.Line.Trim() }

        if ($shadowCopies) {
            $shadowCopies | Out-File (Join-Path $analysisDir "shadow_copies.txt")
            $deletedAnalysis.Analysis.ShadowCopies = $shadowCopies.Count
            Write-Host "✓ Found $($shadowCopies.Count) shadow copies" -ForegroundColor Green
        } else {
            $deletedAnalysis.Analysis.ShadowCopies = 0
            Write-Host "✓ No shadow copies found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check shadow copies: $($_.Exception.Message)"
        $deletedAnalysis.Analysis.ShadowCopies = "Error: $($_.Exception.Message)"
    }

    # Check for temporary files
    Write-Host "Analyzing temporary files..." -ForegroundColor Yellow
    try {
        $tempPaths = @(
            "$env:TEMP",
            "$env:TMP",
            "$DriveLetter\Windows\Temp",
            "$DriveLetter\Temp"
        )

        $tempFiles = @()
        foreach ($tempPath in $tempPaths) {
            if (Test-Path $tempPath) {
                $files = Get-ChildItem -Path $tempPath -File -ErrorAction SilentlyContinue |
                    Select-Object FullName, Name, Length, LastWriteTime
                $tempFiles += $files
            }
        }

        if ($tempFiles) {
            $tempFiles | Export-Csv (Join-Path $analysisDir "temporary_files.csv") -NoTypeInformation
            $deletedAnalysis.Analysis.TemporaryFiles = $tempFiles.Count
            Write-Host "✓ Found $($tempFiles.Count) temporary files" -ForegroundColor Green
        } else {
            $deletedAnalysis.Analysis.TemporaryFiles = 0
            Write-Host "✓ No temporary files found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to analyze temporary files: $($_.Exception.Message)"
        $deletedAnalysis.Analysis.TemporaryFiles = "Error: $($_.Exception.Message)"
    }

    # Check for prefetch files (indicates recently run programs)
    Write-Host "Analyzing prefetch files..." -ForegroundColor Yellow
    try {
        $prefetchPath = "$DriveLetter\Windows\Prefetch"
        if (Test-Path $prefetchPath) {
            $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
                Select-Object Name, Length, LastWriteTime |
                Sort-Object LastWriteTime -Descending

            if ($prefetchFiles) {
                $prefetchFiles | Export-Csv (Join-Path $analysisDir "prefetch_files.csv") -NoTypeInformation
                $deletedAnalysis.Analysis.PrefetchFiles = $prefetchFiles.Count
                Write-Host "✓ Found $($prefetchFiles.Count) prefetch files" -ForegroundColor Green
            } else {
                $deletedAnalysis.Analysis.PrefetchFiles = 0
                Write-Host "✓ No prefetch files found" -ForegroundColor Green
            }
        } else {
            $deletedAnalysis.Analysis.PrefetchFiles = "Prefetch directory not accessible"
        }
    } catch {
        Write-Warning "Failed to analyze prefetch files: $($_.Exception.Message)"
        $deletedAnalysis.Analysis.PrefetchFiles = "Error: $($_.Exception.Message)"
    }

    # Save analysis summary
    $summaryFile = Join-Path $analysisDir "deleted_files_analysis.json"
    $deletedAnalysis | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "Deleted files analysis complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}

function Get-FileAnomalyDetection {
    <#
    .SYNOPSIS
        Detects file system anomalies and suspicious file activity.
    .DESCRIPTION
        Identifies unusual file patterns, suspicious locations, and potential security issues.
    .PARAMETER Path
        Directory path to analyze.
    .PARAMETER OutputPath
        Directory to save anomaly analysis results.
    .EXAMPLE
        Get-FileAnomalyDetection -Path C:\ -OutputPath C:\Analysis
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$OutputPath = "."
    )

    Write-Host "Detecting file system anomalies..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "FileAnomalies_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $anomalies = @{
        Timestamp = Get-Date
        Path = $Path
        Anomalies = @{}
    }

    # Suspicious file locations
    Write-Host "Checking for suspicious file locations..." -ForegroundColor Yellow
    try {
        $suspiciousLocations = @(
            "$Path\Windows\System32\*.exe",
            "$Path\Windows\System32\*.dll",
            "$Path\Windows\SysWOW64\*.exe",
            "$Path\Windows\SysWOW64\*.dll"
        )

        $suspiciousFiles = @()
        foreach ($location in $suspiciousLocations) {
            if (Test-Path $location) {
                $files = Get-ChildItem -Path $location -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.CreationTime -gt (Get-Date).AddDays(-7) -or
                        $_.LastWriteTime -gt (Get-Date).AddDays(-7)
                    } |
                    Select-Object FullName, Name, Length, CreationTime, LastWriteTime

                $suspiciousFiles += $files
            }
        }

        if ($suspiciousFiles) {
            $suspiciousFiles | Export-Csv (Join-Path $analysisDir "suspicious_locations.csv") -NoTypeInformation
            $anomalies.Anomalies.SuspiciousLocations = $suspiciousFiles.Count
            Write-Host "⚠ Found $($suspiciousFiles.Count) recently modified system files" -ForegroundColor Red
        } else {
            $anomalies.Anomalies.SuspiciousLocations = 0
            Write-Host "✓ No suspicious file locations found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check suspicious locations: $($_.Exception.Message)"
        $anomalies.Anomalies.SuspiciousLocations = "Error: $($_.Exception.Message)"
    }

    # Hidden files analysis
    Write-Host "Analyzing hidden files..." -ForegroundColor Yellow
    try {
        $hiddenFiles = Get-ChildItem -Path $Path -Hidden -Recurse -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            Select-Object FullName, Name, Length, LastWriteTime |
            Sort-Object LastWriteTime -Descending

        if ($hiddenFiles) {
            $hiddenFiles | Export-Csv (Join-Path $analysisDir "hidden_files.csv") -NoTypeInformation
            $anomalies.Anomalies.HiddenFiles = $hiddenFiles.Count
            Write-Host "✓ Found $($hiddenFiles.Count) hidden files" -ForegroundColor Green
        } else {
            $anomalies.Anomalies.HiddenFiles = 0
            Write-Host "✓ No hidden files found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to analyze hidden files: $($_.Exception.Message)"
        $anomalies.Anomalies.HiddenFiles = "Error: $($_.Exception.Message)"
    }

    # Large files in unusual locations
    Write-Host "Checking for large files in unusual locations..." -ForegroundColor Yellow
    try {
        $unusualLargeFiles = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Length -gt 100MB -and
                $_.FullName -notmatch "Windows|Program Files|Users\\.*\\Downloads|Users\\.*\\Desktop"
            } |
            Select-Object FullName, Name, Length, LastWriteTime |
            Sort-Object Length -Descending

        if ($unusualLargeFiles) {
            $unusualLargeFiles | Export-Csv (Join-Path $analysisDir "unusual_large_files.csv") -NoTypeInformation
            $anomalies.Anomalies.UnusualLargeFiles = $unusualLargeFiles.Count
            Write-Host "⚠ Found $($unusualLargeFiles.Count) large files in unusual locations" -ForegroundColor Yellow
        } else {
            $anomalies.Anomalies.UnusualLargeFiles = 0
            Write-Host "✓ No unusual large files found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check unusual large files: $($_.Exception.Message)"
        $anomalies.Anomalies.UnusualLargeFiles = "Error: $($_.Exception.Message)"
    }

    # Recently created executables
    Write-Host "Checking for recently created executables..." -ForegroundColor Yellow
    try {
        $recentExecutables = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -match "\.(exe|dll|bat|cmd|ps1|vbs|js)" -and
                $_.CreationTime -gt (Get-Date).AddHours(-24)
            } |
            Select-Object FullName, Name, Length, CreationTime, LastWriteTime

        if ($recentExecutables) {
            $recentExecutables | Export-Csv (Join-Path $analysisDir "recent_executables.csv") -NoTypeInformation
            $anomalies.Anomalies.RecentExecutables = $recentExecutables.Count
            Write-Host "⚠ Found $($recentExecutables.Count) recently created executables" -ForegroundColor Red
        } else {
            $anomalies.Anomalies.RecentExecutables = 0
            Write-Host "✓ No recently created executables found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check recent executables: $($_.Exception.Message)"
        $anomalies.Anomalies.RecentExecutables = "Error: $($_.Exception.Message)"
    }

    # Save anomalies summary
    $summaryFile = Join-Path $analysisDir "file_anomalies_summary.json"
    $anomalies | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "File anomaly detection complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}

function Invoke-AdvancedFileSystemAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive advanced file system forensics analysis.
    .DESCRIPTION
        Combines file signatures, carving, timeline creation, deleted files analysis, and anomaly detection.
    .PARAMETER Path
        Directory path to analyze.
    .PARAMETER OutputPath
        Directory to save all analysis results.
    .PARAMETER IncludeCarving
        Whether to include file carving (can be resource intensive).
    .EXAMPLE
        Invoke-AdvancedFileSystemAnalysis -Path C:\ -OutputPath C:\FileAnalysis
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$OutputPath = ".",
        [bool]$IncludeCarving = $false
    )

    Write-Host "=== ADVANCED FILE SYSTEM FORENSICS ANALYSIS ===" -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "AdvancedFileSystem_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $workflow = @{
        Timestamp = Get-Date
        Path = $Path
        IncludeCarving = $IncludeCarving
        Steps = @()
        Results = @{}
    }

    # Step 1: File Signature Analysis
    Write-Host "`nStep 1: Analyzing File Signatures" -ForegroundColor Yellow
    try {
        $signatureResults = Get-FileSignatures -Path $Path -OutputPath $analysisDir
        $workflow.Results.FileSignatures = $signatureResults
        $workflow.Steps += "File Signatures: Success - $signatureResults"
        Write-Host "✓ File signature analysis completed" -ForegroundColor Green
    } catch {
        $workflow.Steps += "File Signatures: Error - $($_.Exception.Message)"
        Write-Warning "File signature analysis error: $($_.Exception.Message)"
    }

    # Step 2: File System Timeline
    Write-Host "`nStep 2: Creating File System Timeline" -ForegroundColor Yellow
    try {
        $timelineResults = Get-FileSystemTimeline -Path $Path -OutputPath $analysisDir -Days 30
        $workflow.Results.FileSystemTimeline = $timelineResults
        $workflow.Steps += "File System Timeline: Success - $timelineResults"
        Write-Host "✓ File system timeline created" -ForegroundColor Green
    } catch {
        $workflow.Steps += "File System Timeline: Error - $($_.Exception.Message)"
        Write-Warning "File system timeline error: $($_.Exception.Message)"
    }

    # Step 3: Deleted Files Analysis
    Write-Host "`nStep 3: Analyzing Deleted Files" -ForegroundColor Yellow
    try {
        $driveLetter = if ($Path -match "^([A-Z]):") { $matches[1] + ":" } else { "C:" }
        $deletedResults = Get-DeletedFilesAnalysis -DriveLetter $driveLetter -OutputPath $analysisDir
        $workflow.Results.DeletedFilesAnalysis = $deletedResults
        $workflow.Steps += "Deleted Files Analysis: Success - $deletedResults"
        Write-Host "✓ Deleted files analysis completed" -ForegroundColor Green
    } catch {
        $workflow.Steps += "Deleted Files Analysis: Error - $($_.Exception.Message)"
        Write-Warning "Deleted files analysis error: $($_.Exception.Message)"
    }

    # Step 4: File Anomaly Detection
    Write-Host "`nStep 4: Detecting File Anomalies" -ForegroundColor Yellow
    try {
        $anomalyResults = Get-FileAnomalyDetection -Path $Path -OutputPath $analysisDir
        $workflow.Results.FileAnomalies = $anomalyResults
        $workflow.Steps += "File Anomaly Detection: Success - $anomalyResults"
        Write-Host "✓ File anomaly detection completed" -ForegroundColor Green
    } catch {
        $workflow.Steps += "File Anomaly Detection: Error - $($_.Exception.Message)"
        Write-Warning "File anomaly detection error: $($_.Exception.Message)"
    }

    # Step 5: File Carving (optional)
    if ($IncludeCarving) {
        Write-Host "`nStep 5: Performing File Carving" -ForegroundColor Yellow
        try {
            $driveLetter = if ($Path -match "^([A-Z]):") { $matches[1] + ":" } else { "C:" }
            $carvingResults = Get-FileCarving -DriveLetter $driveLetter -OutputPath $analysisDir
            $workflow.Results.FileCarving = $carvingResults
            $workflow.Steps += "File Carving: Success - $carvingResults"
            Write-Host "✓ File carving completed" -ForegroundColor Green
        } catch {
            $workflow.Steps += "File Carving: Error - $($_.Exception.Message)"
            Write-Warning "File carving error: $($_.Exception.Message)"
        }
    }

    # Save workflow summary
    $summaryFile = Join-Path $analysisDir "advanced_filesystem_analysis_workflow.json"
    $workflow | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "`n=== ADVANCED FILE SYSTEM ANALYSIS COMPLETE ===" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan
    Write-Host "Summary: $summaryFile" -ForegroundColor Cyan

    return $analysisDir
}