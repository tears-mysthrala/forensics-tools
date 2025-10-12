# MemoryFunctions.ps1 - Memory analysis functions

function Get-MemoryDump {
    <#
    .SYNOPSIS
        Captures a live memory dump of the system.
    .DESCRIPTION
        Attempts to capture RAM contents using available tools (WinPMEM, DumpIt, or PowerShell alternatives).
    .PARAMETER OutputPath
        Path where to save the memory dump (default: current directory).
    .PARAMETER Method
        Method to use: 'WinPMEM', 'DumpIt', or 'PowerShell'. Auto-fallback to PowerShell if tools unavailable.
    .EXAMPLE
        Get-MemoryDump -OutputPath C:\Evidence
        Get-MemoryDump -OutputPath C:\Evidence\memory.dmp
    #>
    param(
        [string]$OutputPath = ".",
        [ValidateSet('WinPMEM', 'DumpIt', 'PowerShell')]
        [string]$Method = 'PowerShell'
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # Determine if OutputPath is a directory or file
    if (Test-Path $OutputPath -PathType Container) {
        # It's a directory, create filename inside it
        $outputFile = Join-Path $OutputPath "memory_dump_$timestamp.dmp"
    } else {
        # It's a file path, use it directly (but ensure .dmp extension for tools)
        if ($OutputPath -notmatch '\.dmp$') {
            $outputFile = $OutputPath + ".dmp"
        } else {
            $outputFile = $OutputPath
        }
    }

    Write-Host "Attempting memory acquisition using method: $Method" -ForegroundColor Cyan

    switch ($Method) {
        'WinPMEM' {
            # Try WinPMEM first (most reliable)
            # Check multiple locations for portability
            $winpmemPaths = @(
                (Join-Path (Split-Path $PSScriptRoot -Parent) "Tools\winpmem.exe"),  # Profile directory
                "C:\Tools\WinPMEM\winpmem.exe",  # Standard install location
                "$PSScriptRoot\..\Tools\winpmem.exe"  # Relative to script
            )

            $winpmemPath = $null
            foreach ($path in $winpmemPaths) {
                if (Test-Path $path) {
                    $winpmemPath = $path
                    break
                }
            }

            if ($winpmemPath) {
                Write-Host "Using WinPMEM for memory acquisition..." -ForegroundColor Green
                try {
                    & $winpmemPath $outputFile 2>&1
                    if ($LASTEXITCODE -eq 0 -and (Test-Path $outputFile)) {
                        Write-Host "Memory dump saved to: $outputFile" -ForegroundColor Green
                        return $outputFile
                    } else {
                        Write-Error "WinPMEM failed to create memory dump"
                    }
                } catch {
                    Write-Error "WinPMEM execution failed: $($_.Exception.Message)"
                }
            } else {
                Write-Warning "WinPMEM not found. Attempting to install..."
                try {
                    Install-ForensicTools
                    # Check again after installation
                    $profileToolsPath = Join-Path (Split-Path $PSScriptRoot -Parent) "Tools\winpmem.exe"
                    if (Test-Path $profileToolsPath) {
                        Write-Host "Retrying with newly installed WinPMEM..." -ForegroundColor Green
                        & $profileToolsPath $outputFile 2>&1
                        if ($LASTEXITCODE -eq 0 -and (Test-Path $outputFile)) {
                            Write-Host "Memory dump saved to: $outputFile" -ForegroundColor Green
                            return $outputFile
                        }
                    }
                } catch {
                    Write-Warning "Could not install WinPMEM automatically"
                }
                Write-Warning "Install WinPMEM manually or use alternative method."
            }
        }
        'DumpIt' {
            # Try DumpIt as alternative
            # Check multiple locations for portability
            $dumpitPaths = @(
                (Join-Path (Split-Path $PSScriptRoot -Parent) "Tools\DumpIt.exe"),  # Profile directory
                "C:\Tools\DumpIt\DumpIt.exe",  # Standard install location
                "$PSScriptRoot\..\Tools\DumpIt.exe"  # Relative to script
            )

            $dumpitPath = $null
            foreach ($path in $dumpitPaths) {
                if (Test-Path $path) {
                    $dumpitPath = $path
                    break
                }
            }

            if ($dumpitPath) {
                Write-Host "Using DumpIt for memory acquisition..." -ForegroundColor Green
                try {
                    & $dumpitPath /Q /O $outputFile 2>&1
                    if (Test-Path $outputFile) {
                        Write-Host "Memory dump saved to: $outputFile" -ForegroundColor Green
                        return $outputFile
                    } else {
                        Write-Error "DumpIt failed to create memory dump"
                    }
                } catch {
                    Write-Error "DumpIt execution failed: $($_.Exception.Message)"
                }
            } else {
                Write-Warning "DumpIt not found. Install DumpIt manually."
                Write-Host "Download from: https://www.moonsols.com/windows-memory-toolkit/" -ForegroundColor Yellow
                Write-Host "Place in: $(Join-Path (Split-Path $PSScriptRoot -Parent) "Tools")" -ForegroundColor Yellow
            }
        }
        'PowerShell' {
            # PowerShell-based memory acquisition (limited but works)
            Write-Host "Using PowerShell for basic memory information..." -ForegroundColor Yellow
            Write-Warning "PowerShell method provides limited memory data. Use WinPMEM/DumpIt for full acquisition."

            try {
                $memoryInfo = Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory
                $processMemory = Get-Process | Select-Object Name, Id, @{Name="MemoryMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}}
            } catch {
                Write-Error "Failed to collect memory information: $($_.Exception.Message)"
                return $null
            }

            $evidence = @{
                Timestamp = Get-Date
                SystemMemory = $memoryInfo
                ProcessMemory = $processMemory
            }

            # Create JSON file alongside the DMP file
            $jsonFile = $outputFile -replace '\.dmp$', '.json'
            try {
                $evidence | ConvertTo-Json -Depth 3 | Out-File $jsonFile
                Write-Host "Memory information saved to: $jsonFile" -ForegroundColor Green
                return $jsonFile
            } catch {
                Write-Error "Failed to save memory information: $($_.Exception.Message)"
                return $null
            }
        }
    }

    Write-Error "Memory acquisition failed. Install WinPMEM or DumpIt for proper memory dumping."
    return $null
}

function Get-VolatilityAnalysis {
    <#
    .SYNOPSIS
        Performs basic Volatility analysis on a memory dump.
    .DESCRIPTION
        Uses Volatility 3 (Python-based) to analyze memory dumps.
    .PARAMETER MemoryDump
        Path to the memory dump file.
    .PARAMETER AnalysisType
        Type of analysis: 'pslist', 'netscan', 'malfind', 'handles'.
    .EXAMPLE
        Get-VolatilityAnalysis -MemoryDump C:\Evidence\memory.dmp -AnalysisType windows.pslist
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$MemoryDump,
        [ValidateSet('windows.pslist', 'windows.netscan', 'windows.malfind', 'windows.handles', 'windows.dlllist')]
        [string]$AnalysisType = 'windows.pslist'
    )

    # Check if Python and volatility are available
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
    }

    if (-not $pythonCmd) {
        Write-Error "Python not found. Install Python 3.8+ from https://python.org"
        return
    }

    $volCmd = Get-Command vol -ErrorAction SilentlyContinue
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
        Write-Host "Alternative: Download from https://github.com/volatilityfoundation/volatility3" -ForegroundColor Yellow
        return
    }

    Write-Host "Running Volatility analysis: $AnalysisType" -ForegroundColor Cyan

    try {
        $output = if ($volCmd) { & vol -f $MemoryDump $AnalysisType 2>&1 } else { & $pythonCmd -m volatility3.cli -f $MemoryDump $AnalysisType 2>&1 }
        $output
    } catch {
        Write-Error "Volatility analysis failed: $_"
    }
}

function Install-ForensicTools {
    <#
    .SYNOPSIS
        Downloads and installs required forensic tools.
    .DESCRIPTION
        Automatically downloads and installs all required forensic tools including WinPMEM, Python, Volatility3, YARA, Azure CLI, and Wireshark.
    .PARAMETER ToolsPath
        Directory where to install tools (defaults to profile directory for USB compatibility).
    .EXAMPLE
        Install-ForensicTools
        Install-ForensicTools -ToolsPath "C:\Tools"
    #>
    param(
        [string]$ToolsPath = $null
    )

    # Default to profile directory for USB compatibility
    if (-not $ToolsPath) {
        $ToolsPath = Split-Path $PSScriptRoot -Parent
        if (-not $ToolsPath) {
            $ToolsPath = $PWD.Path
        }
    }

    Write-Host "Installing forensic tools to: $ToolsPath" -ForegroundColor Cyan

    # Create tools directory
    if (-not (Test-Path $ToolsPath)) {
        New-Item -ItemType Directory -Path $ToolsPath -Force | Out-Null
    }

    # Install WinPMEM
    $winpmemDir = Join-Path $ToolsPath "Tools"
    if (-not (Test-Path $winpmemDir)) {
        New-Item -ItemType Directory -Path $winpmemDir -Force | Out-Null
    }

    $winpmemPath = Join-Path $winpmemDir "winpmem.exe"
    if (-not (Test-Path $winpmemPath)) {
        Write-Host "Downloading WinPMEM..." -ForegroundColor Yellow
        try {
            # Try multiple sources for WinPMEM
            $urls = @(
                "https://github.com/Velocidex/WinPMEM/releases/download/v4.0.rc1/WinPMEM.exe",
                "https://winpmem.velocidex.com/WinPMEM.exe"
            )

            $downloaded = $false
            foreach ($url in $urls) {
                try {
                    Write-Host "Trying to download from: $url" -ForegroundColor Gray
                    # Use .NET WebClient for better compatibility
                    $webClient = New-Object System.Net.WebClient
                    $webClient.DownloadFile($url, $winpmemPath)
                    $downloaded = $true
                    break
                } catch {
                    Write-Warning "Failed to download from $url : $($_.Exception.Message)"
                }
            }

            if (-not $downloaded) {
                Write-Warning "Could not download WinPMEM automatically."
                Write-Host "Manual installation required:" -ForegroundColor Yellow
                Write-Host "1. Download WinPMEM from: https://github.com/Velocidex/WinPMEM/releases" -ForegroundColor Yellow
                Write-Host "2. Extract winpmem.exe to: $winpmemDir" -ForegroundColor Yellow
                Write-Host "3. The profile will detect it automatically on next run" -ForegroundColor Yellow
            } else {
                Write-Host "WinPMEM installed successfully: $winpmemPath" -ForegroundColor Green
            }
        } catch {
            Write-Error "Failed to install WinPMEM: $($_.Exception.Message)"
        }
    } else {
        Write-Host "WinPMEM already available: $winpmemPath" -ForegroundColor Green
    }

    # Install DumpIt as alternative
    $dumpitPath = Join-Path $winpmemDir "DumpIt.exe"
    if (-not (Test-Path $dumpitPath)) {
        Write-Host "DumpIt requires manual installation. Please download from:" -ForegroundColor Yellow
        Write-Host "https://www.moonsols.com/windows-memory-toolkit/" -ForegroundColor Yellow
        Write-Host "Place DumpIt.exe in: $winpmemDir" -ForegroundColor Yellow
    } else {
        Write-Host "DumpIt already available: $dumpitPath" -ForegroundColor Green
    }

    # Install Python if not present
    Write-Host "Checking for Python..." -ForegroundColor Cyan
    $pythonInstalled = $false
    try {
        $pythonVersion = python --version 2>$null
        if ($pythonVersion -match "Python 3\.[89]\d*") {
            Write-Host "Python found: $pythonVersion" -ForegroundColor Green
            $pythonInstalled = $true
        } else {
            Write-Warning "Python version too old or not found. Installing Python 3.11..."
        }
    } catch {
        Write-Host "Python not found. Installing Python 3.11..." -ForegroundColor Yellow
    }

    if (-not $pythonInstalled) {
        try {
            Write-Host "Installing Python via winget..." -ForegroundColor Yellow
            winget install Python.Python.3.11 --accept-source-agreements --accept-package-agreements
            Write-Host "Python installed successfully. Please restart PowerShell and run this function again." -ForegroundColor Green
        } catch {
            Write-Error "Failed to install Python automatically. Please install manually from https://python.org"
        }
    }

    # Install Azure CLI if not present
    Write-Host "Checking for Azure CLI..." -ForegroundColor Cyan
    try {
        $azVersion = az --version 2>$null | Select-Object -First 1
        if ($azVersion) {
            Write-Host "Azure CLI found: $azVersion" -ForegroundColor Green
        } else {
            throw "Not found"
        }
    } catch {
        Write-Host "Azure CLI not found. Installing..." -ForegroundColor Yellow
        try {
            winget install Microsoft.AzureCLI --accept-source-agreements --accept-package-agreements
            Write-Host "Azure CLI installed successfully." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to install Azure CLI automatically. Please install manually."
        }
    }

    # Install Wireshark if not present
    Write-Host "Checking for Wireshark..." -ForegroundColor Cyan
    try {
        $wiresharkVersion = & "C:\Program Files\Wireshark\tshark.exe" --version 2>$null | Select-Object -First 1
        if ($wiresharkVersion) {
            Write-Host "Wireshark found: $wiresharkVersion" -ForegroundColor Green
        } else {
            throw "Not found"
        }
    } catch {
        Write-Host "Wireshark not found. Installing..." -ForegroundColor Yellow
        try {
            winget install WiresharkFoundation.Wireshark --accept-source-agreements --accept-package-agreements
            Write-Host "Wireshark installed successfully." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to install Wireshark automatically. Please install manually."
        }
    }

    # Install YARA
    Write-Host "Checking for YARA..." -ForegroundColor Cyan
    $yaraPath = Join-Path $winpmemDir "yara.exe"
    if (-not (Test-Path $yaraPath)) {
        Write-Host "Downloading YARA..." -ForegroundColor Yellow
        try {
            # Get latest YARA release
            $apiUrl = "https://api.github.com/repos/VirusTotal/yara/releases/latest"
            $release = Invoke-RestMethod -Uri $apiUrl
            $asset = $release.assets | Where-Object { $_.name -match "yara-.*-win64\.zip" } | Select-Object -First 1
            
            if ($asset) {
                $yaraZip = Join-Path $winpmemDir "yara.zip"
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $yaraZip
                
                # Extract YARA
                Expand-Archive -Path $yaraZip -DestinationPath $winpmemDir -Force
                Remove-Item $yaraZip
                
                # Find yara.exe in extracted folder
                $yaraExtracted = Get-ChildItem -Path $winpmemDir -Directory | Where-Object { $_.Name -match "yara-" } | Select-Object -First 1
                if ($yaraExtracted) {
                    $yaraExe = Get-ChildItem -Path $yaraExtracted.FullName -Recurse -Filter "yara.exe" | Select-Object -First 1
                    if ($yaraExe) {
                        Move-Item -Path $yaraExe.FullName -Destination $yaraPath -Force
                        Remove-Item $yaraExtracted.FullName -Recurse -Force
                        Write-Host "YARA installed successfully: $yaraPath" -ForegroundColor Green
                    }
                }
            } else {
                Write-Warning "Could not find YARA download. Please install manually from https://github.com/VirusTotal/yara/releases"
            }
        } catch {
            Write-Warning "Failed to install YARA automatically: $($_.Exception.Message)"
        }
    } else {
        Write-Host "YARA already available: $yaraPath" -ForegroundColor Green
    }

    # Install Python packages if Python is available
    if ($pythonInstalled -or (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Python forensics packages..." -ForegroundColor Cyan
        Get-PythonForensicsTools
    } else {
        Write-Warning "Python not available. Run this function again after installing Python."
    }

    Write-Host "Forensic tools installation complete!" -ForegroundColor Green
    Write-Host "Tools location: $winpmemDir" -ForegroundColor Cyan
}

function Get-PythonForensicsTools {
    <#
    .SYNOPSIS
        Checks and installs Python forensics tools.
    .DESCRIPTION
        Ensures Python 3.8+ and required packages (volatility3, pefile, yara-python) are installed.
    .EXAMPLE
        Get-PythonForensicsTools
    #>
    Write-Host "Checking Python forensics tools..." -ForegroundColor Cyan

    # Check Python
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
    }

    if (-not $pythonCmd) {
        Write-Error "Python not found. Install Python 3.8+ from https://python.org"
        return $false
    }

    Write-Host "Python found: $($pythonCmd.Source)" -ForegroundColor Green

    # Check pip
    try {
        $pipVersion = & $pythonCmd -m pip --version 2>$null
        Write-Host "Pip found: $($pipVersion.Split()[1])" -ForegroundColor Green
    } catch {
        Write-Error "Pip not found. Install pip or ensure Python installation includes pip."
        return $false
    }

    # Required packages
    $packages = @(
        @{Name = "volatility3"; Command = "import volatility3.cli"},
        @{Name = "pefile"; Command = "import pefile"},
        @{Name = "yara-python"; Command = "import yara"},
        @{Name = "construct"; Command = "import construct"}
    )

    foreach ($package in $packages) {
        Write-Host "Checking $($package.Name)..." -ForegroundColor Gray
        $result = & $pythonCmd -c "try: $($package.Command); print('OK') except: print('MISSING')" 2>$null

        if ($result -eq "OK") {
            Write-Host "$($package.Name) is available" -ForegroundColor Green
        } else {
            Write-Host "Installing $($package.Name)..." -ForegroundColor Yellow
            try {
                & $pythonCmd -m pip install $package.Name --quiet 2>$null
                Write-Host "$($package.Name) installed successfully" -ForegroundColor Green
            } catch {
                Write-Error "Failed to install $($package.Name): $($_.Exception.Message)"
                return $false
            }
        }
    }

    Write-Host "Python forensics tools setup complete!" -ForegroundColor Green
    return $true
}