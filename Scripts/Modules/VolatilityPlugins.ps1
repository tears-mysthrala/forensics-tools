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
                @{Name = "windows.malware.malfind"; Description = "Malware detection" },
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
                @{Name = "windows.malware.malfind"; Description = "Malware detection" },
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