# AdvancedMemoryFunctions.ps1 - Advanced memory forensics and analysis

function Get-VolatilityPlugins {
    <#
    .SYNOPSIS
        Lists available Volatility 3 plugins and their descriptions.
    .DESCRIPTION
        Discovers all available Volatility 3 plugins and provides descriptions for forensic analysis.
    .EXAMPLE
        Get-VolatilityPlugins
    #>
    Write-Host "Discovering Volatility 3 plugins..." -ForegroundColor Cyan

    # Check if Python and volatility are available
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
    }

    if (-not $pythonCmd) {
        Write-Error "Python not found. Install Python 3.8+ from https://python.org"
        return
    }

    try {
        # Check for vol command
        $volCmd = Get-Command vol -ErrorAction SilentlyContinue
        if (-not $volCmd) {
            # Check common installation paths
            $volPaths = @(
                "$env:USERPROFILE\.local\bin\vol.exe",
                "$env:APPDATA\Python\Scripts\vol.exe",
                (Join-Path (Split-Path $pythonCmd.Source -Parent) "Scripts\vol.exe")
            )
            foreach ($path in $volPaths) {
                if (Test-Path $path) {
                    $volCmd = $path
                    break
                }
            }
        }
        if ($volCmd) {
            # Get list of plugins using vol command
            $plugins = & $volCmd --help 2>$null
        }
        else {
            # Fallback to python
            $plugins = & $pythonCmd -c "import sys; sys.argv = ['vol', '--help']; from volatility3.cli.vol import main; main()" 2>$null
        }
        if ($plugins) {
            Write-Host "Available Volatility 3 plugins:" -ForegroundColor Green
            $plugins | Where-Object { $_ -match "^\s*[a-zA-Z]" } | ForEach-Object {
                Write-Host "  $_" -ForegroundColor White
            }
        }
        else {
            Write-Warning "Could not retrieve plugin list. Volatility may not be properly installed."
        }
    }
    catch {
        Write-Error "Failed to get Volatility plugins: $($_.Exception.Message)"
    }
}

function Invoke-VolatilityAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive Volatility analysis on a memory dump.
    .DESCRIPTION
        Runs multiple Volatility plugins against a memory dump for thorough forensic analysis.
    .PARAMETER MemoryDump
        Path to the memory dump file.
    .PARAMETER AnalysisType
        Type of analysis: 'full', 'processes', 'network', 'filesystem', 'malware', 'timeline'.
    .PARAMETER OutputPath
        Directory to save analysis results.
    .EXAMPLE
        Invoke-VolatilityAnalysis -MemoryDump C:\Evidence\memory.dmp -AnalysisType full
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$MemoryDump,
        [ValidateSet('full', 'processes', 'network', 'filesystem', 'malware', 'timeline')]
        [string]$AnalysisType = 'processes',
        [string]$OutputPath = "."
    )

    if (-not (Test-Path $MemoryDump)) {
        Write-Error "Memory dump file not found: $MemoryDump"
        return
    }

    # Check Python and Volatility
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
    }

    if (-not $pythonCmd) {
        Write-Error "Python not found. Install Python 3.8+ from https://python.org"
        return
    }

    # Check for Volatility 3
    $volCmd = Get-Command vol -ErrorAction SilentlyContinue
    if (-not $volCmd) {
        # Check common installation paths
        $volPaths = @(
            "$env:USERPROFILE\.local\bin\vol.exe",
            "$env:APPDATA\Python\Scripts\vol.exe",
            (Join-Path (Split-Path $pythonCmd.Source -Parent) "Scripts\vol.exe")
        )
        foreach ($path in $volPaths) {
            if (Test-Path $path) {
                $volCmd = $path
                break
            }
        }
    }
    $volAvailable = $false
    if ($volCmd) {
        $volAvailable = $true
    }
    else {
        # Fallback check for python module
        $testVol = & $pythonCmd -c "import volatility3.cli; print('OK')" 2>$null
        if ($testVol -eq "OK") {
            $volAvailable = $true
        }
    }
    if (-not $volAvailable) {
        Write-Error "Volatility 3 not found. Install with: pip install volatility3"
        return
    }

    Write-Host "Starting Volatility analysis: $AnalysisType" -ForegroundColor Cyan

    # Create output directory
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "VolatilityAnalysis_$timestamp"
    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $results = @{
        Timestamp    = Get-Date
        MemoryDump   = $MemoryDump
        AnalysisType = $AnalysisType
        Results      = @{}
    }

    switch ($AnalysisType) {
        'full' {
            # Run comprehensive analysis
            $plugins = @(
                @{Name = "windows.pslist"; Description = "Process list" },
                @{Name = "windows.pstree"; Description = "Process tree" },
                @{Name = "windows.psscan"; Description = "Process scan" },
                @{Name = "windows.netscan"; Description = "Network connections" },
                @{Name = "windows.filescan"; Description = "File objects" },
                @{Name = "windows.dlllist"; Description = "DLLs loaded by processes" },
                @{Name = "windows.handles"; Description = "Handle table" },
                @{Name = "windows.registry.hivelist"; Description = "Registry hives" },
                @{Name = "windows.malfind"; Description = "Malware detection" },
                @{Name = "windows.modscan"; Description = "Module scan" },
                @{Name = "windows.cmdline"; Description = "Command line arguments" },
                @{Name = "windows.envars"; Description = "Environment variables" }
            )
        }
        'processes' {
            $plugins = @(
                @{Name = "windows.pslist"; Description = "Process list" },
                @{Name = "windows.pstree"; Description = "Process tree" },
                @{Name = "windows.psscan"; Description = "Process scan" },
                @{Name = "windows.thrdscan"; Description = "Thread scan" },
                @{Name = "windows.cmdline"; Description = "Command line arguments" },
                @{Name = "windows.envars"; Description = "Environment variables" }
            )
        }
        'network' {
            $plugins = @(
                @{Name = "windows.netscan"; Description = "Network connections" },
                @{Name = "windows.netstat"; Description = "Network statistics" },
                @{Name = "windows.sockets"; Description = "Socket information" },
                @{Name = "windows.udpnet"; Description = "UDP network connections" }
            )
        }
        'filesystem' {
            $plugins = @(
                @{Name = "windows.filescan"; Description = "File objects" },
                @{Name = "windows.dumpfiles"; Description = "Dump file contents" },
                @{Name = "windows.mftscan"; Description = "MFT entries" },
                @{Name = "windows.vadwalk"; Description = "VAD walk" }
            )
        }
        'malware' {
            $plugins = @(
                @{Name = "windows.malfind"; Description = "Malware detection" },
                @{Name = "windows.modscan"; Description = "Module scan" },
                @{Name = "windows.ssdt"; Description = "System service descriptor table" },
                @{Name = "windows.callbacks"; Description = "Callback functions" },
                @{Name = "windows.driverscan"; Description = "Driver scan" },
                @{Name = "windows.devicetree"; Description = "Device tree" }
            )
        }
        'timeline' {
            $plugins = @(
                @{Name = "windows.timeliner"; Description = "Timeline creation" },
                @{Name = "windows.shellbags"; Description = "Shell bags" },
                @{Name = "windows.userassist"; Description = "UserAssist registry" },
                @{Name = "windows.shimcache"; Description = "Shim cache" },
                @{Name = "windows.amcache"; Description = "Amcache" }
            )
        }
    }

    foreach ($plugin in $plugins) {
        Write-Host "Running $($plugin.Name) - $($plugin.Description)..." -ForegroundColor Yellow
        try {
            if ($volCmd) {
                $output = & $volCmd -f $MemoryDump $plugin.Name 2>&1
            }
            else {
                $output = & $pythonCmd -c "import sys; sys.argv = ['vol', '-f', '$MemoryDump', '$plugin.Name']; from volatility3.cli.vol import main; main()" 2>&1
            }
            $outputFile = Join-Path $analysisDir "$($plugin.Name -replace '\.', '_').txt"
            $output | Out-File $outputFile
            $results.Results[$plugin.Name] = @{
                Description = $plugin.Description
                OutputFile  = $outputFile
                Success     = $true
            }
            Write-Host "[OK] Completed $($plugin.Name)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to run $($plugin.Name): $($_.Exception.Message)"
            $results.Results[$plugin.Name] = @{
                Description = $plugin.Description
                Error       = $_.Exception.Message
                Success     = $false
            }
        }
    }

    # Save analysis summary
    $summaryFile = Join-Path $analysisDir "analysis_summary.json"
    $results | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "`nVolatility analysis complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan
    Write-Host "Summary: $summaryFile" -ForegroundColor Cyan

    return $results
}

function Get-ProcessMemoryDump {
    <#
    .SYNOPSIS
        Dumps memory of a specific process for analysis.
    .DESCRIPTION
        Extracts memory contents of a running process for forensic examination.
    .PARAMETER ProcessId
        ID of the process to dump.
    .PARAMETER ProcessName
        Name of the process to dump (alternative to ProcessId).
    .PARAMETER OutputPath
        Directory to save the process memory dump.
    .EXAMPLE
        Get-ProcessMemoryDump -ProcessId 1234
        Get-ProcessMemoryDump -ProcessName "notepad"
    #>
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$OutputPath = "."
    )

    if (-not $ProcessId -and -not $ProcessName) {
        Write-Error "Must specify either ProcessId or ProcessName"
        return
    }

    # Find the process
    if ($ProcessName) {
        $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $process) {
            Write-Error "Process '$ProcessName' not found"
            return
        }
        $ProcessId = $process.Id
    }
    else {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $process) {
            Write-Error "Process with ID $ProcessId not found"
            return
        }
    }

    Write-Host "Dumping memory for process: $($process.Name) (PID: $ProcessId)" -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = Join-Path $OutputPath "process_memory_$($process.Name)_${ProcessId}_$timestamp.dmp"

    try {
        # Use WinPMEM or DumpIt if available
        $tools = @(
            (Join-Path (Split-Path $PSScriptRoot -Parent) "Tools\winpmem.exe"),
            (Join-Path (Split-Path $PSScriptRoot -Parent) "Tools\DumpIt.exe")
        )

        $toolUsed = $null
        foreach ($tool in $tools) {
            if (Test-Path $tool) {
                $toolUsed = $tool
                break
            }
        }

        if ($toolUsed) {
            if ($toolUsed -match "winpmem") {
                & $toolUsed --pid $ProcessId $outputFile 2>&1 | Out-Null
            }
            elseif ($toolUsed -match "DumpIt") {
                # DumpIt doesn't support process-specific dumping
                Write-Warning "DumpIt doesn't support process-specific memory dumps. Use WinPMEM."
                return
            }

            if (Test-Path $outputFile) {
                Write-Host "Process memory dump saved: $outputFile" -ForegroundColor Green
                return $outputFile
            }
            else {
                Write-Error "Failed to create process memory dump"
            }
        }
        else {
            Write-Warning "No memory dumping tools found. Install WinPMEM for process memory dumps."
            Write-Host "Download from: https://github.com/Velocidex/WinPMEM/releases" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Failed to dump process memory: $($_.Exception.Message)"
    }

    return $null
}

function Get-MemoryTimeline {
    <#
    .SYNOPSIS
        Creates a timeline of memory artifacts and events.
    .DESCRIPTION
        Analyzes memory dump to create a chronological timeline of system events and artifacts.
    .PARAMETER MemoryDump
        Path to the memory dump file.
    .PARAMETER OutputPath
        Directory to save the timeline.
    .EXAMPLE
        Get-MemoryTimeline -MemoryDump C:\Evidence\memory.dmp
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$MemoryDump,
        [string]$OutputPath = "."
    )

    if (-not (Test-Path $MemoryDump)) {
        Write-Error "Memory dump file not found: $MemoryDump"
        return
    }

    Write-Host "Creating memory timeline..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $timelineFile = Join-Path $OutputPath "memory_timeline_$timestamp.csv"

    # Check Python and Volatility
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
    }

    if (-not $pythonCmd) {
        Write-Error "Python not found for timeline creation"
        return
    }

    # Check for Volatility 3
    $volCmd = Get-Command vol -ErrorAction SilentlyContinue
    if (-not $volCmd) {
        # Check common installation paths
        $volPaths = @(
            "$env:USERPROFILE\.local\bin\vol.exe",
            "$env:APPDATA\Python\Scripts\vol.exe",
            (Join-Path (Split-Path $pythonCmd.Source -Parent) "Scripts\vol.exe")
        )
        foreach ($path in $volPaths) {
            if (Test-Path $path) {
                $volCmd = $path
                break
            }
        }
    }

    try {
        # Run timeliner plugin
        Write-Host "Running Volatility timeliner..." -ForegroundColor Yellow
        if ($volCmd) {
            $timelineData = & $volCmd -f $MemoryDump windows.timeliner 2>&1
        }
        else {
            $timelineData = & $pythonCmd -c "import sys; sys.argv = ['vol', '-f', '$MemoryDump', 'windows.timeliner']; from volatility3.cli.vol import main; main()" 2>&1
        }

        # Parse and format timeline data
        $timeline = @()
        $timelineData | Where-Object { $_ -match "\d{4}-\d{2}-\d{2}" } | ForEach-Object {
            # Parse typical Volatility timeliner output
            if ($_ -match "(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\s+(\w+)\s+(.+)") {
                $timeline += [PSCustomObject]@{
                    Timestamp = $matches[1]
                    Plugin = $matches[2]
                    Description = $matches[3]
                }
            }
        }

        # Sort by timestamp
        $timeline = $timeline | Sort-Object Timestamp

        # Export to CSV
        $timeline | Export-Csv $timelineFile -NoTypeInformation

        Write-Host "Memory timeline created: $timelineFile" -ForegroundColor Green
        Write-Host "Total events: $($timeline.Count)" -ForegroundColor Cyan

        return $timelineFile

    } catch {
        Write-Error "Failed to create memory timeline: $($_.Exception.Message)"
    }

    return $null
}

function Get-MemoryStrings {
    <#
    .SYNOPSIS
        Extracts strings from memory dump for analysis.
    .DESCRIPTION
        Uses strings-like functionality to extract readable strings from memory dumps.
    .PARAMETER MemoryDump
        Path to the memory dump file.
    .PARAMETER MinLength
        Minimum string length to extract.
    .PARAMETER OutputPath
        Directory to save the strings file.
    .EXAMPLE
        Get-MemoryStrings -MemoryDump C:\Evidence\memory.dmp -MinLength 8
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$MemoryDump,
        [int]$MinLength = 4,
        [string]$OutputPath = "."
    )

    if (-not (Test-Path $MemoryDump)) {
        Write-Error "Memory dump file not found: $MemoryDump"
        return
    }

    Write-Host "Extracting strings from memory dump (min length: $MinLength)..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $stringsFile = Join-Path $OutputPath "memory_strings_$timestamp.txt"

    try {
        # Use PowerShell to extract strings (basic implementation)
        $bytes = [System.IO.File]::ReadAllBytes($MemoryDump)
        $strings = New-Object System.Collections.Generic.List[string]

        $currentString = ""
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $byte = $bytes[$i]
            if ($byte -ge 32 -and $byte -le 126) {
                # Printable ASCII character
                $currentString += [char]$byte
            } else {
                # Non-printable character
                if ($currentString.Length -ge $MinLength) {
                    $strings.Add($currentString)
                }
                $currentString = ""
            }
        }

        # Write strings to file
        $strings | Out-File $stringsFile

        Write-Host "Memory strings extracted: $stringsFile" -ForegroundColor Green
        Write-Host "Total strings found: $($strings.Count)" -ForegroundColor Cyan

        return $stringsFile

    } catch {
        Write-Error "Failed to extract memory strings: $($_.Exception.Message)"
    }

    return $null
}

function Get-MemoryArtifacts {
    <#
    .SYNOPSIS
        Extracts common memory artifacts for forensic analysis.
    .DESCRIPTION
        Gathers various memory-resident artifacts like clipboard contents, keystrokes, etc.
    .PARAMETER OutputPath
        Directory to save the artifacts.
    .EXAMPLE
        Get-MemoryArtifacts -OutputPath C:\Evidence
    #>
    param(
        [string]$OutputPath = "."
    )

    Write-Host "Collecting memory artifacts..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $artifactsDir = Join-Path $OutputPath "MemoryArtifacts_$timestamp"

    if (-not (Test-Path $artifactsDir)) {
        New-Item -ItemType Directory -Path $artifactsDir -Force | Out-Null
    }

    $artifacts = @{
        Timestamp = Get-Date
        Artifacts = @{}
    }

    # Clipboard contents
    Write-Host "Collecting clipboard contents..." -ForegroundColor Yellow
    try {
        $clipboard = Get-Clipboard -TextFormatType Text -ErrorAction SilentlyContinue
        if ($clipboard) {
            $clipboard | Out-File (Join-Path $artifactsDir "clipboard.txt")
            $artifacts.Artifacts.Clipboard = "Collected"
        } else {
            $artifacts.Artifacts.Clipboard = "No text content"
        }
        Write-Host "[OK] Clipboard collected" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect clipboard: $($_.Exception.Message)"
        $artifacts.Artifacts.Clipboard = "Error: $($_.Exception.Message)"
    }

    # Environment variables
    Write-Host "Collecting environment variables..." -ForegroundColor Yellow
    try {
        $envVars = Get-ChildItem Env: | Select-Object Name, Value
        $envVars | Export-Csv (Join-Path $artifactsDir "environment_variables.csv") -NoTypeInformation
        $artifacts.Artifacts.EnvironmentVariables = "Collected"
        Write-Host "[OK] Environment variables collected" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect environment variables: $($_.Exception.Message)"
        $artifacts.Artifacts.EnvironmentVariables = "Error: $($_.Exception.Message)"
    }

    # Recent commands (if available)
    Write-Host "Collecting command history..." -ForegroundColor Yellow
    try {
        $history = Get-History -Count 50 | Select-Object CommandLine, StartExecutionTime, EndExecutionTime
        $history | Export-Csv (Join-Path $artifactsDir "command_history.csv") -NoTypeInformation
        $artifacts.Artifacts.CommandHistory = "Collected"
        Write-Host "[OK] Command history collected" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect command history: $($_.Exception.Message)"
        $artifacts.Artifacts.CommandHistory = "Error: $($_.Exception.Message)"
    }

    # Save artifacts manifest
    $manifestFile = Join-Path $artifactsDir "artifacts_manifest.json"
    $artifacts | ConvertTo-Json -Depth 3 | Out-File $manifestFile

    Write-Host "Memory artifacts collection complete!" -ForegroundColor Green
    Write-Host "Artifacts saved to: $artifactsDir" -ForegroundColor Cyan

    return $artifactsDir
}

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
        Steps = @()
        Results = @{}
    }

    # Step 1: Memory Dump
    Write-Host "`nStep 1: Acquiring Memory Dump" -ForegroundColor Yellow
    try {
        $memoryDump = Get-MemoryDump -OutputPath $analysisDir
        if ($memoryDump) {
            $workflow.Results.MemoryDump = $memoryDump
            $workflow.Steps += "Memory Dump: Success - $memoryDump"
            Write-Host "[OK] Memory dump acquired" -ForegroundColor Green
        } else {
            $workflow.Steps += "Memory Dump: Failed - No dump tool available"
            Write-Warning "Memory dump failed"
        }
    } catch {
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
        } catch {
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
            } else {
                $workflow.Steps += "Memory Timeline: Failed"
                Write-Warning "Memory timeline creation failed"
            }
        } catch {
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
    } catch {
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
        } catch {
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