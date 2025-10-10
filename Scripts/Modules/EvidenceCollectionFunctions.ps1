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

    # Helper function to convert data to visual HTML
    function Convert-DataToVisualHTML {
        param($data)

        if ($data -is [array]) {
            if ($data.Count -eq 0) {
                return "<div class='evidence-item'><em>No data available</em></div>"
            }

            # Check if array contains objects
            $firstItem = $data[0]
            if ($firstItem -is [PSCustomObject]) {
                # Create table for structured data
                $html = "<table><thead><tr>"
                $firstItem.PSObject.Properties.Name | ForEach-Object { $html += "<th>$_</th>" }
                $html += "</tr></thead><tbody>"

                foreach ($item in $data | Select-Object -First 50) {
                    # Limit to first 50 items
                    $html += "<tr>"
                    foreach ($prop in $firstItem.PSObject.Properties.Name) {
                        $value = $item.$prop
                        if ($value -is [DateTime]) {
                            $value = $value.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        elseif ($value -is [bool]) {
                            $value = $value ? "<span class='success'>✓</span>" : "<span class='warning'>✗</span>"
                        }
                        elseif ($null -eq $value -or $value -eq "") {
                            $value = "<em>N/A</em>"
                        }
                        elseif ($value -is [string] -and $value.Length -gt 50) {
                            $value = $value.Substring(0, [Math]::Min(47, $value.Length)) + "..."
                        }
                        $html += "<td>$value</td>"
                    }
                    $html += "</tr>"
                }
                $propCount = ($firstItem.PSObject.Properties | Measure-Object).Count
                if ($data.Count -gt 50) {
                    $html += "<tr><td colspan='$propCount'><em>... and $($data.Count - 50) more items</em></td></tr>"
                }
                $html += "</tbody></table>"
                return $html
            }
            else {
                # Simple array
                $html = "<div class='evidence-item'><ul>"
                foreach ($item in $data | Select-Object -First 20) {
                    $html += "<li>$item</li>"
                }
                if ($data.Count -gt 20) {
                    $html += "<li><em>... and $($data.Count - 20) more items</em></li>"
                }
                $html += "</ul></div>"
                return $html
            }
        }
        elseif ($data -is [PSCustomObject]) {
            # For objects, show properties
            $html = "<div class='evidence-item'>"
            $properties = $data.PSObject.Properties

            # Separate simple properties from arrays
            $simpleProps = @()
            $arrayProps = @()

            foreach ($prop in $properties) {
                if ($prop.Value -is [array]) {
                    $arrayProps += $prop
                }
                else {
                    $simpleProps += $prop
                }
            }

            # Show simple properties as metrics
            if ($simpleProps.Count -gt 0) {
                $html += "<div class='metric-grid'>"
                foreach ($prop in $simpleProps) {
                    $value = $prop.Value
                    if ($value -is [DateTime]) {
                        $value = $value.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                    elseif ($value -is [bool]) {
                        $value = $value ? "<span class='success'>True</span>" : "<span class='warning'>False</span>"
                    }
                    elseif ($null -eq $value -or $value -eq "") {
                        $value = "<em>N/A</em>"
                    }
                    $html += "<div class='metric'><strong>$($prop.Name)</strong><div>$value</div></div>"
                }
                $html += "</div>"
            }

            # Show array properties
            foreach ($arrayProp in $arrayProps) {
                $html += "<h3>$($arrayProp.Name) ($($arrayProp.Value.Count) items)</h3>"
                $html += Convert-DataToVisualHTML -data $arrayProp.Value
            }

            $html += "</div>"
            return $html
        }
        else {
            # Simple values
            return "<div class='evidence-item'><div class='metric'><strong>Value</strong><div>$data</div></div></div>"
        }
    }

    # Read evidence files
    $evidenceFiles = Get-ChildItem $EvidencePath -Filter "*.json" | Where-Object { $_.Name -ne "evidence_manifest.json" }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Analysis Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            text-align: center;
        }

        .header h1 {
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 20px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }

        .info-card {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 20px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }

        .info-card:hover {
            transform: translateY(-5px);
        }

        .info-card strong {
            display: block;
            font-size: 0.9em;
            opacity: 0.8;
            margin-bottom: 5px;
        }

        .info-card span {
            font-size: 1.2em;
            font-weight: 600;
        }

        .section {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            overflow: hidden;
            transition: transform 0.3s ease;
        }

        .section:hover {
            transform: translateY(-2px);
        }

        .section-header {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 25px 30px;
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .section-icon {
            width: 40px;
            height: 40px;
            background: rgba(255,255,255,0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2em;
        }

        .section h2 {
            font-size: 1.5em;
            font-weight: 600;
            margin: 0;
        }

        .section-content {
            padding: 30px;
        }

        .evidence-item {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
            border-left: 5px solid #667eea;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
        }

        .evidence-item:hover {
            transform: translateX(5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }

        .warning {
            color: #e74c3c;
            font-weight: 600;
            background: rgba(231, 76, 60, 0.1);
            padding: 5px 10px;
            border-radius: 5px;
            border: 1px solid rgba(231, 76, 60, 0.3);
        }

        .success {
            color: #27ae60;
            font-weight: 600;
            background: rgba(39, 174, 96, 0.1);
            padding: 5px 10px;
            border-radius: 5px;
            border: 1px solid rgba(39, 174, 96, 0.3);
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #e1e8ed;
        }

        th {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }

        tr:nth-child(even) {
            background: #f8f9fa;
        }

        tr:hover {
            background: rgba(102, 126, 234, 0.1);
            transition: background 0.3s ease;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .metric {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 20px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }

        .metric:hover {
            transform: translateY(-5px);
        }

        .metric strong {
            display: block;
            font-size: 0.9em;
            opacity: 0.8;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .metric div {
            font-size: 1.8em;
            font-weight: 700;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .header {
                padding: 20px;
            }

            .header h1 {
                font-size: 2em;
            }

            .section-content {
                padding: 20px;
            }

            .metric-grid {
                grid-template-columns: 1fr;
            }
        }

        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb {
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(135deg, #5a67d8, #6b46c1);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Forensic Analysis Report</h1>
            <div class="header-info">
                <div class="info-card">
                    <strong>Generated</strong>
                    <span>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
                </div>
                <div class="info-card">
                    <strong>Hostname</strong>
                    <span>$env:COMPUTERNAME</span>
                </div>
                <div class="info-card">
                    <strong>Analyst</strong>
                    <span>$env:USERNAME</span>
                </div>
                <div class="info-card">
                    <strong>Evidence Path</strong>
                    <span>$EvidencePath</span>
                </div>
            </div>
        </div>
"@

    # Icon mapping for sections
    $sectionIcons = @{
        "01 system status"       = "🖥️"
        "02 system analysis"     = "🔧"
        "03 network analysis"    = "🌐"
        "04 filesystem analysis" = "📁"
        "05 security analysis"   = "🔒"
        "workflow summary"       = "📊"
    }

    foreach ($file in $evidenceFiles) {
        try {
            $data = Get-Content $file.FullName | ConvertFrom-Json
            $sectionName = ($file.Name -replace '_', ' ' -replace '\.json$', '')
            $icon = $sectionIcons[$sectionName] ? $sectionIcons[$sectionName] : "📋"

            $html += @"
        <div class='section'>
            <div class='section-header'>
                <div class='section-icon'>$icon</div>
                <h2>$sectionName</h2>
            </div>
            <div class='section-content'>
"@

            $html += Convert-DataToVisualHTML -data $data

            $html += @"
            </div>
        </div>
"@
        }
        catch {
            Write-Warning "Failed to process $($file.Name): $($_.Exception.Message)"
        }
    }

    $html += @"
    </div>
</body>
</html>
"@

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