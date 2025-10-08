# EvidenceCollectionFunctions.ps1 - Evidence collection and analysis functions

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
        [Parameter(Mandatory=$true)]
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
    } catch {
        Write-Warning "Failed to collect system information: $($_.Exception.Message)"
    }

    # Process Information
    Write-Host "Collecting process information..." -ForegroundColor Yellow
    try {
        $processes = Get-ProcessDetails
        $processes | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "processes.json")
        Write-Host "Process information collected" -ForegroundColor Green
    } catch {
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
        } catch {
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
        } catch {
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
            } else {
                Write-Warning "Memory acquisition failed or not available"
            }
        } catch {
            Write-Warning "Failed to collect memory evidence: $($_.Exception.Message)"
        }
    }

    # Registry Evidence
    Write-Host "Collecting registry evidence..." -ForegroundColor Yellow
    try {
        $registryKeys = Get-RegistryKeys -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $registryKeys | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "registry_run_keys.json")
        Write-Host "Registry evidence collected" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect registry evidence: $($_.Exception.Message)"
    }

    # Event Log Evidence
    Write-Host "Collecting event log evidence..." -ForegroundColor Yellow
    try {
        $eventLogs = Get-SystemLogsSummary
        $eventLogs | ConvertTo-Json -Depth 3 | Out-File (Join-Path $evidenceDir "event_logs_summary.json")
        Write-Host "Event log evidence collected" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect event log evidence: $($_.Exception.Message)"
    }

    # Create evidence manifest
    $manifest = @{
        CollectionTimestamp = Get-Date
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        EvidenceTypes = @()
        Files = @()
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
    } catch {
        Write-Warning "System status check failed: $($_.Exception.Message)"
    }

    # System Analysis
    Write-Host "`n=== SYSTEM ANALYSIS ===" -ForegroundColor Yellow
    try {
        $analysis = Invoke-SystemAnalysis
        $analysis | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "system_analysis.json")
    } catch {
        Write-Warning "System analysis failed: $($_.Exception.Message)"
    }

    # Network Analysis
    Write-Host "`n=== NETWORK ANALYSIS ===" -ForegroundColor Yellow
    try {
        $network = Invoke-NetworkAnalysis
        $network | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "network_analysis.json")
    } catch {
        Write-Warning "Network analysis failed: $($_.Exception.Message)"
    }

    # File System Analysis
    Write-Host "`n=== FILE SYSTEM ANALYSIS ===" -ForegroundColor Yellow
    try {
        $filesystem = Invoke-FileSystemAnalysis
        $filesystem | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "filesystem_analysis.json")
    } catch {
        Write-Warning "File system analysis failed: $($_.Exception.Message)"
    }

    # Security Analysis
    Write-Host "`n=== SECURITY ANALYSIS ===" -ForegroundColor Yellow
    try {
        $security = Invoke-SecurityAnalysis
        $security | ConvertTo-Json -Depth 3 | Out-File (Join-Path $analysisDir "security_analysis.json")
    } catch {
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
                    $volResults = Get-VolatilityAnalysis -MemoryDump $memoryDump -AnalysisType pslist
                    $volResults | Out-File (Join-Path $analysisDir "volatility_pslist.txt")
                }
            }
        } catch {
            Write-Warning "Memory analysis failed: $($_.Exception.Message)"
        }
    }

    # Create analysis summary
    $summary = @{
        AnalysisTimestamp = Get-Date
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        QuickScan = $QuickScan
        AnalysisTypes = @("System Status", "System Analysis", "Network Analysis", "File System Analysis", "Security Analysis")
        ResultsDirectory = $analysisDir
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

function Export-ForensicReport {
    <#
    .SYNOPSIS
        Generates a comprehensive forensic report from collected evidence.
    .DESCRIPTION
        Creates an HTML report summarizing all collected evidence and analysis results.
    .PARAMETER EvidencePath
        Path to the evidence directory.
    .PARAMETER OutputFile
        Path for the HTML report file.
    .EXAMPLE
        Export-ForensicReport -EvidencePath C:\Evidence\Evidence_20231201_120000 -OutputFile C:\Reports\forensic_report.html
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$EvidencePath,
        [string]$OutputFile = $null
    )

    if (-not (Test-Path $EvidencePath)) {
        Write-Error "Evidence path not found: $EvidencePath"
        return
    }

    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputFile = Join-Path $EvidencePath "forensic_report_$timestamp.html"
    }

    Write-Host "Generating forensic report..." -ForegroundColor Cyan

    # Read evidence files
    $evidenceFiles = Get-ChildItem $EvidencePath -Filter "*.json" | Where-Object { $_.Name -ne "evidence_manifest.json" }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2E86C1; }
        h2 { color: #5DADE2; border-bottom: 1px solid #BDC3C7; padding-bottom: 5px; }
        .section { margin-bottom: 30px; }
        .evidence-item { background-color: #F8F9FA; padding: 10px; margin: 10px 0; border-left: 4px solid #2E86C1; }
        .warning { color: #E74C3C; }
        .success { color: #27AE60; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #BDC3C7; padding: 8px; text-align: left; }
        th { background-color: #F4F6F7; }
        pre { background-color: #F8F9FA; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>Forensic Analysis Report</h1>
    <p><strong>Generated:</strong> $(Get-Date)</p>
    <p><strong>Hostname:</strong> $env:COMPUTERNAME</p>
    <p><strong>Analyst:</strong> $env:USERNAME</p>
    <p><strong>Evidence Path:</strong> $EvidencePath</p>
"@

    foreach ($file in $evidenceFiles) {
        try {
            $data = Get-Content $file.FullName | ConvertFrom-Json
            $sectionName = ($file.Name -replace '_', ' ' -replace '\.json$', '')

            $html += "<div class='section'><h2>$sectionName</h2>"

            if ($data -is [array]) {
                $html += "<table><thead><tr>"
                if ($data.Count -gt 0) {
                    $data[0].PSObject.Properties.Name | ForEach-Object { $html += "<th>$_</th>" }
                }
                $html += "</tr></thead><tbody>"
                foreach ($item in $data) {
                    $html += "<tr>"
                    $item.PSObject.Properties.Value | ForEach-Object { $html += "<td>$_</td>" }
                    $html += "</tr>"
                }
                $html += "</tbody></table>"
            } elseif ($data -is [PSCustomObject]) {
                $html += "<div class='evidence-item'><pre>" + ($data | ConvertTo-Json -Depth 3) + "</pre></div>"
            } else {
                $html += "<div class='evidence-item'><pre>$data</pre></div>"
            }

            $html += "</div>"
        } catch {
            Write-Warning "Failed to process $($file.Name): $($_.Exception.Message)"
        }
    }

    $html += "</body></html>"

    try {
        $html | Out-File $OutputFile -Encoding UTF8
        Write-Host "Report generated: $OutputFile" -ForegroundColor Green
        return $OutputFile
    } catch {
        Write-Error "Failed to save report: $($_.Exception.Message)"
        return $null
    }
}

function Get-ForensicTimeline {
    <#
    .SYNOPSIS
        Creates a timeline of forensic events from collected evidence.
    .DESCRIPTION
        Analyzes event logs, file timestamps, and other evidence to create a chronological timeline.
    .PARAMETER EvidencePath
        Path to the evidence directory.
    .PARAMETER OutputFile
        Path for the timeline CSV file.
    .EXAMPLE
        Get-ForensicTimeline -EvidencePath C:\Evidence\Evidence_20231201_120000
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$EvidencePath,
        [string]$OutputFile = $null
    )

    if (-not (Test-Path $EvidencePath)) {
        Write-Error "Evidence path not found: $EvidencePath"
        return
    }

    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputFile = Join-Path $EvidencePath "forensic_timeline_$timestamp.csv"
    }

    Write-Host "Creating forensic timeline..." -ForegroundColor Cyan

    $timeline = @()

    # Add collection timestamp
    $timeline += [PSCustomObject]@{
        Timestamp = Get-Date
        EventType = "Evidence Collection"
        Description = "Forensic evidence collection started"
        Source = "Forensic Script"
        Details = "Evidence collected to $EvidencePath"
    }

    # Process event logs if available
    $eventLogFile = Join-Path $EvidencePath "event_logs_summary.json"
    if (Test-Path $eventLogFile) {
        try {
            $eventData = Get-Content $eventLogFile | ConvertFrom-Json
            foreach ($log in $eventData) {
                if ($log.Records -and $log.Records.Count -gt 0) {
                    foreach ($record in $log.Records | Select-Object -First 10) {  # Limit to recent records
                        $timeline += [PSCustomObject]@{
                            Timestamp = $record.TimeCreated
                            EventType = "Event Log"
                            Description = $record.Message
                            Source = "$($log.LogName) - $($record.Id)"
                            Details = "Level: $($record.LevelDisplayName)"
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Failed to process event logs for timeline: $($_.Exception.Message)"
        }
    }

    # Process recent files
    $recentFilesFile = Join-Path $EvidencePath "recent_files.json"
    if (Test-Path $recentFilesFile) {
        try {
            $fileData = Get-Content $recentFilesFile | ConvertFrom-Json
            foreach ($file in $fileData | Select-Object -First 20) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $file.LastWriteTime
                    EventType = "File Modification"
                    Description = "File modified: $($file.Name)"
                    Source = $file.FullName
                    Details = "Size: $($file.Length) bytes"
                }
            }
        } catch {
            Write-Warning "Failed to process recent files for timeline: $($_.Exception.Message)"
        }
    }

    # Sort timeline by timestamp
    $timeline = $timeline | Sort-Object Timestamp -Descending

    try {
        $timeline | Export-Csv $OutputFile -NoTypeInformation
        Write-Host "Timeline created: $OutputFile" -ForegroundColor Green
        Write-Host "Total events: $($timeline.Count)" -ForegroundColor Cyan
        return $OutputFile
    } catch {
        Write-Error "Failed to save timeline: $($_.Exception.Message)"
        return $null
    }
}