# AdvancedFileSystemAnalysisFunctions.ps1 - Comprehensive file system forensics workflow

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
        Write-Host "[OK] File signature analysis completed" -ForegroundColor Green
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
        Write-Host "[OK] File system timeline created" -ForegroundColor Green
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
        Write-Host "[OK] Deleted files analysis completed" -ForegroundColor Green
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
        Write-Host "[OK] File anomaly detection completed" -ForegroundColor Green
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
            Write-Host "[OK] File carving completed" -ForegroundColor Green
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