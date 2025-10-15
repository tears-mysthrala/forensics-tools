# EvidenceCollection-Core.ps1 - Core evidence collection and live forensics functions

function Collect-SystemEvidence {
    <#
    .SYNOPSIS
        Collects comprehensive system evidence for forensic analysis.
    .DESCRIPTION
        Gathers system information, processes, network connections, file hashes, and other artifacts.
    .PARAMETER OutputPath
        Directory where to save evidence files.
    .PARAMETER IncludeMemory
        Whether to attempt memory acquisition (requires admin privileges).
    .PARAMETER IncludeNetwork
        Whether to collect network evidence.
    .PARAMETER IncludeFiles
        Whether to collect file system evidence.
    .EXAMPLE
        Collect-SystemEvidence -OutputPath C:\Evidence
        Collect-SystemEvidence -OutputPath C:\Evidence -IncludeMemory $false
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [bool]$IncludeMemory = $true,
        [bool]$IncludeNetwork = $true,
        [bool]$IncludeFiles = $true
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $evidenceDir = Join-Path $OutputPath "Evidence_$timestamp"

    # Create evidence directory
    if (-not (Test-Path $evidenceDir)) {
        New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
    }

    Write-Host "Collecting system evidence to: $evidenceDir" -ForegroundColor Cyan

    # System Information
    Write-Host "Collecting system information..." -ForegroundColor Yellow
    try {
        $systemInfo = Get-SystemInfo
        $systemInfo | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "system_info.json")
        Write-Host "System information collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to collect system information: $($_.Exception.Message)"
    }

    # Process Information
    Write-Host "Collecting process information..." -ForegroundColor Yellow
    try {
        $processes = Get-ProcessDetails
        $processes | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "processes.json")
        Write-Host "Process information collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to collect process information: $($_.Exception.Message)"
    }

    # Network Evidence
    if ($IncludeNetwork) {
        Write-Host "Collecting network evidence..." -ForegroundColor Yellow
        try {
            $networkConnections = Get-NetworkConnections
            $networkConnections | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "network_connections.json")

            $networkShares = Get-NetworkShares
            $networkShares | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "network_shares.json")

            $usbHistory = Get-USBDeviceHistory
            $usbHistory | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "usb_history.json")

            Write-Host "Network evidence collected" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to collect network evidence: $($_.Exception.Message)"
        }
    }

    # File System Evidence
    if ($IncludeFiles) {
        Write-Host "Collecting file system evidence..." -ForegroundColor Yellow
        try {
            # Recent files
            $recentFiles = Get-RecentFiles -Days 7
            $recentFiles | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "recent_files.json")

            # Large files
            $largeFiles = Get-LargeFiles -SizeMB 100
            $largeFiles | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "large_files.json")

            # Alternate data streams
            $adsFiles = Get-AlternateDataStreams -Path "C:\"
            $adsFiles | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "alternate_data_streams.json")

            Write-Host "File system evidence collected" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to collect file system evidence: $($_.Exception.Message)"
        }
    }

    # Memory Evidence (requires admin)
    if ($IncludeMemory) {
        Write-Host "Attempting memory acquisition..." -ForegroundColor Yellow
        try {
            $memoryDump = Get-MemoryDump -OutputPath $evidenceDir
            if ($memoryDump) {
                Write-Host "Memory dump collected: $memoryDump" -ForegroundColor Green
            }
            else {
                Write-Warning "Memory acquisition failed or not available"
            }
        }
        catch {
            Write-Warning "Failed to collect memory evidence: $($_.Exception.Message)"
        }
    }

    # Registry Evidence
    Write-Host "Collecting registry evidence..." -ForegroundColor Yellow
    try {
        $registryKeys = Get-RegistryKeys -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $registryKeys | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "registry_run_keys.json")
        Write-Host "Registry evidence collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to collect registry evidence: $($_.Exception.Message)"
    }

    # Event Log Evidence
    Write-Host "Collecting event log evidence..." -ForegroundColor Yellow
    try {
        $eventLogs = Get-SystemLogsSummary
        $eventLogs | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "event_logs_summary.json")
        Write-Host "Event log evidence collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to collect event log evidence: $($_.Exception.Message)"
    }

    # Create evidence manifest
    $manifest = @{
        CollectionTimestamp = Get-Date
        Hostname            = $env:COMPUTERNAME
        Username            = $env:USERNAME
        EvidenceTypes       = @()
        Files               = @()
    }

    if ($systemInfo) { $manifest.EvidenceTypes += "System Information" }
    if ($processes) { $manifest.EvidenceTypes += "Process Information" }
    if ($IncludeNetwork) { $manifest.EvidenceTypes += "Network Evidence" }
    if ($IncludeFiles) { $manifest.EvidenceTypes += "File System Evidence" }
    if ($IncludeMemory -and $memoryDump) { $manifest.EvidenceTypes += "Memory Dump" }
    $manifest.EvidenceTypes += "Registry Evidence"
    $manifest.EvidenceTypes += "Event Log Evidence"

    # List all files in evidence directory
    $manifest.Files = Get-ChildItem $evidenceDir -File | Select-Object Name, Length, LastWriteTime

    $manifest | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "evidence_manifest.json")

    Write-Host "Evidence collection complete!" -ForegroundColor Green
    Write-Host "Evidence saved to: $evidenceDir" -ForegroundColor Cyan
    Write-Host "Manifest: $(Join-Path $evidenceDir "evidence_manifest.json")" -ForegroundColor Cyan

    return $evidenceDir
}

function Invoke-LiveForensics {
    <#
    .SYNOPSIS
        Performs comprehensive live forensics analysis.
    .DESCRIPTION
        Runs all available forensic functions and saves results to timestamped directory.
    .PARAMETER OutputPath
        Directory where to save analysis results.
    .PARAMETER QuickScan
        Perform quick scan (skip memory analysis and detailed file scanning).
    .EXAMPLE
        Invoke-LiveForensics -OutputPath C:\Forensics
        Invoke-LiveForensics -QuickScan
    #>
    param(
        [string]$OutputPath = ".",
        [switch]$QuickScan
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "LiveForensics_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    Write-Host "Starting live forensics analysis..." -ForegroundColor Cyan
    Write-Host "Results will be saved to: $analysisDir" -ForegroundColor Cyan

    # System Status
    Write-Host "`n=== SYSTEM STATUS ===" -ForegroundColor Yellow
    try {
        $status = Invoke-LiveSystemStatus
        $status | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "system_status.json")
    }
    catch {
        Write-Warning "System status check failed: $($_.Exception.Message)"
    }

    # System Analysis
    Write-Host "`n=== SYSTEM ANALYSIS ===" -ForegroundColor Yellow
    try {
        $analysis = Invoke-SystemAnalysis
        $analysis | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "system_analysis.json")
    }
    catch {
        Write-Warning "System analysis failed: $($_.Exception.Message)"
    }

    # Network Analysis
    Write-Host "`n=== NETWORK ANALYSIS ===" -ForegroundColor Yellow
    try {
        $network = Invoke-NetworkAnalysis
        $network | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "network_analysis.json")
    }
    catch {
        Write-Warning "Network analysis failed: $($_.Exception.Message)"
    }

    # File System Analysis
    Write-Host "`n=== FILE SYSTEM ANALYSIS ===" -ForegroundColor Yellow
    try {
        $filesystem = Invoke-FileSystemAnalysis
        $filesystem | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "filesystem_analysis.json")
    }
    catch {
        Write-Warning "File system analysis failed: $($_.Exception.Message)"
    }

    # Security Analysis
    Write-Host "`n=== SECURITY ANALYSIS ===" -ForegroundColor Yellow
    try {
        $security = Invoke-SecurityAnalysis
        $security | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "security_analysis.json")
    }
    catch {
        Write-Warning "Security analysis failed: $($_.Exception.Message)"
    }

    # Memory Analysis (skip if QuickScan)
    if (-not $QuickScan) {
        Write-Host "`n=== MEMORY ANALYSIS ===" -ForegroundColor Yellow
        try {
            $memoryDump = Get-MemoryDump -OutputPath $analysisDir
            if ($memoryDump) {
                Write-Host "Memory dump saved: $memoryDump" -ForegroundColor Green

                # Try Volatility analysis if available
                if (Get-PythonForensicsTools) {
                    Write-Host "Running Volatility analysis..." -ForegroundColor Cyan
                    $volResults = Get-VolatilityAnalysis -MemoryDump $memoryDump -AnalysisType windows.pslist
                    $volResults | Out-File (Join-Path $analysisDir "volatility_pslist.txt")
                }
            }
        }
        catch {
            Write-Warning "Memory analysis failed: $($_.Exception.Message)"
        }
    }

    # Create analysis summary
    $summary = @{
        AnalysisTimestamp = Get-Date
        Hostname          = $env:COMPUTERNAME
        Username          = $env:USERNAME
        QuickScan         = $QuickScan
        AnalysisTypes     = @("System Status", "System Analysis", "Network Analysis", "File System Analysis", "Security Analysis")
        ResultsDirectory  = $analysisDir
    }

    if (-not $QuickScan) {
        $summary.AnalysisTypes += "Memory Analysis"
    }

    $summary | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "analysis_summary.json")

    Write-Host "`n=== ANALYSIS COMPLETE ===" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan
    Write-Host "Summary: $(Join-Path $analysisDir "analysis_summary.json")" -ForegroundColor Cyan

    return $analysisDir
}