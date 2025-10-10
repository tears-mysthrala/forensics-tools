# DeletedFilesFunctions.ps1 - Deleted files analysis and recovery traces

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
                Write-Host "[OK] Found $($recycleItems.Count) items in Recycle Bin" -ForegroundColor Green
            } else {
                $deletedAnalysis.Analysis.RecycleBinItems = 0
                Write-Host "[OK] Recycle Bin is empty" -ForegroundColor Green
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
            Write-Host "[OK] Found $($shadowCopies.Count) shadow copies" -ForegroundColor Green
        } else {
            $deletedAnalysis.Analysis.ShadowCopies = 0
            Write-Host "[OK] No shadow copies found" -ForegroundColor Green
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
            Write-Host "[OK] Found $($tempFiles.Count) temporary files" -ForegroundColor Green
        } else {
            $deletedAnalysis.Analysis.TemporaryFiles = 0
            Write-Host "[OK] No temporary files found" -ForegroundColor Green
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
                Write-Host "[OK] Found $($prefetchFiles.Count) prefetch files" -ForegroundColor Green
            } else {
                $deletedAnalysis.Analysis.PrefetchFiles = 0
                Write-Host "[OK] No prefetch files found" -ForegroundColor Green
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