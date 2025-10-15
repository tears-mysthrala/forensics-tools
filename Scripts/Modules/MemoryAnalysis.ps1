function Invoke-MemoryForensicAnalysis {
    <#
    .SYNOPSIS
        Performs complete memory forensic analysis workflow.
    .DESCRIPTION
        Combines memory dumping, Volatility analysis, timeline creation, and artifact extraction.
    .PARAMETER OutputPath
        Directory to save all analysis results.
    .PARAMETER IncludeProcessDumps
        Whether to dump individual process memories.
    .EXAMPLE
        Invoke-MemoryForensicAnalysis -OutputPath C:\MemoryAnalysis
    #>
    param(
        [string]$OutputPath = ".",
        [bool]$IncludeProcessDumps = $false
    )

    Write-Host "=== MEMORY FORENSIC ANALYSIS WORKFLOW ===" -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "MemoryForensics_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $workflow = @{
        Timestamp = Get-Date
        Steps     = @()
        Results   = @{}
    }

    # Step 1: Memory Dump
    Write-Host "`nStep 1: Acquiring Memory Dump" -ForegroundColor Yellow
    try {
        $memoryDump = Get-MemoryDump -OutputPath $analysisDir
        if ($memoryDump) {
            $workflow.Results.MemoryDump = $memoryDump
            $workflow.Steps += "Memory Dump: Success - $memoryDump"
            Write-Host "[OK] Memory dump acquired" -ForegroundColor Green
        }
        else {
            $workflow.Steps += "Memory Dump: Failed - No dump tool available"
            Write-Warning "Memory dump failed"
        }
    }
    catch {
        $workflow.Steps += "Memory Dump: Error - $($_.Exception.Message)"
        Write-Warning "Memory dump error: $($_.Exception.Message)"
    }

    # Step 2: Volatility Analysis
    if ($memoryDump) {
        Write-Host "`nStep 2: Running Volatility Analysis" -ForegroundColor Yellow
        try {
            $volResults = Invoke-VolatilityAnalysis -MemoryDump $memoryDump -AnalysisType 'processes' -OutputPath $analysisDir
            $workflow.Results.VolatilityAnalysis = $volResults
            $workflow.Steps += "Volatility Analysis: Success"
            Write-Host "[OK] Volatility analysis completed" -ForegroundColor Green
        }
        catch {
            $workflow.Steps += "Volatility Analysis: Error - $($_.Exception.Message)"
            Write-Warning "Volatility analysis error: $($_.Exception.Message)"
        }
    }

    # Step 3: Memory Timeline
    if ($memoryDump) {
        Write-Host "`nStep 3: Creating Memory Timeline" -ForegroundColor Yellow
        try {
            $timeline = Get-MemoryTimeline -MemoryDump $memoryDump -OutputPath $analysisDir
            if ($timeline) {
                $workflow.Results.MemoryTimeline = $timeline
                $workflow.Steps += "Memory Timeline: Success - $timeline"
                Write-Host "[OK] Memory timeline created" -ForegroundColor Green
            }
            else {
                $workflow.Steps += "Memory Timeline: Failed"
                Write-Warning "Memory timeline creation failed"
            }
        }
        catch {
            $workflow.Steps += "Memory Timeline: Error - $($_.Exception.Message)"
            Write-Warning "Memory timeline error: $($_.Exception.Message)"
        }
    }

    # Step 4: Memory Artifacts
    Write-Host "`nStep 4: Collecting Memory Artifacts" -ForegroundColor Yellow
    try {
        $artifacts = Get-MemoryArtifacts -OutputPath $analysisDir
        $workflow.Results.MemoryArtifacts = $artifacts
        $workflow.Steps += "Memory Artifacts: Success - $artifacts"
        Write-Host "[OK] Memory artifacts collected" -ForegroundColor Green
    }
    catch {
        $workflow.Steps += "Memory Artifacts: Error - $($_.Exception.Message)"
        Write-Warning "Memory artifacts error: $($_.Exception.Message)"
    }

    # Step 5: Process Memory Dumps (optional)
    if ($IncludeProcessDumps) {
        Write-Host "`nStep 5: Dumping Process Memories" -ForegroundColor Yellow
        try {
            $suspiciousProcesses = Get-Process | Where-Object {
                $_.ProcessName -match "(?i)(cmd|powershell|net|wmic|reg|sc)" -and
                $_.StartTime -gt (Get-Date).AddHours(-1)
            } | Select-Object -First 5

            $processDumps = @()
            foreach ($proc in $suspiciousProcesses) {
                $dump = Get-ProcessMemoryDump -ProcessId $proc.Id -OutputPath $analysisDir
                if ($dump) {
                    $processDumps += $dump
                }
            }

            $workflow.Results.ProcessDumps = $processDumps
            $workflow.Steps += "Process Dumps: Success - $($processDumps.Count) dumps created"
            Write-Host "[OK] Process memory dumps completed" -ForegroundColor Green
        }
        catch {
            $workflow.Steps += "Process Dumps: Error - $($_.Exception.Message)"
            Write-Warning "Process dumps error: $($_.Exception.Message)"
        }
    }

    # Save workflow summary
    $summaryFile = Join-Path $analysisDir "memory_analysis_workflow.json"
    $workflow | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "`n=== MEMORY FORENSIC ANALYSIS COMPLETE ===" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan
    Write-Host "Summary: $summaryFile" -ForegroundColor Cyan

    return $analysisDir
}