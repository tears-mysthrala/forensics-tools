# ForensicToolsInstallation.ps1 - Forensic tools installation functions

<#
.SYNOPSIS
    Forensic Tools Installation Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for installing and setting up forensic analysis tools.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

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
        # Try to use the profile directory first
        if ($ProfileDir -and (Test-Path $ProfileDir)) {
            $ToolsPath = $ProfileDir
        }
        else {
            $ToolsPath = Split-Path $PSScriptRoot -Parent
            if (-not $ToolsPath) {
                $ToolsPath = $PWD.Path
            }
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
                }
                catch {
                    Write-Warning "Failed to download from $url : $($_.Exception.Message)"
                }
            }

            if (-not $downloaded) {
                Write-Warning "Could not download WinPMEM automatically."
                Write-Host "Manual installation required:" -ForegroundColor Yellow
                Write-Host "1. Download WinPMEM from: https://github.com/Velocidex/WinPMEM/releases" -ForegroundColor Yellow
                Write-Host "2. Extract winpmem.exe to: $winpmemDir" -ForegroundColor Yellow
                Write-Host "3. The profile will detect it automatically on next run" -ForegroundColor Yellow
            }
            else {
                Write-Host "WinPMEM installed successfully: $winpmemPath" -ForegroundColor Green
            }
        }
        catch {
            Write-Error "Failed to install WinPMEM: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "WinPMEM already available: $winpmemPath" -ForegroundColor Green
    }

    # Install DumpIt as alternative
    $dumpitPath = Join-Path $winpmemDir "DumpIt.exe"
    if (-not (Test-Path $dumpitPath)) {
        Write-Host "DumpIt requires manual installation. Please download from:" -ForegroundColor Yellow
        Write-Host "https://www.moonsols.com/windows-memory-toolkit/" -ForegroundColor Yellow
        Write-Host "Place DumpIt.exe in: $winpmemDir" -ForegroundColor Yellow
    }
    else {
        Write-Host "DumpIt already available: $dumpitPath" -ForegroundColor Green
    }

    # Install Python if not present
    Write-Host "Checking for Python..." -ForegroundColor Cyan
    $pythonInstalled = $false
    try {
        $pythonVersion = python --version 2>$null
        if ($pythonVersion -match "Python 3\.\d+") {
            Write-Host "Python found: $pythonVersion" -ForegroundColor Green
            $pythonInstalled = $true
        }
        else {
            Write-Warning "Python version too old or not found. Installing latest Python..."
        }
    }
    catch {
        Write-Host "Python not found. Installing latest Python..." -ForegroundColor Yellow
    }

    if (-not $pythonInstalled) {
        try {
            Write-Host "Installing Python via winget..." -ForegroundColor Yellow
            winget install Python.Python.3.14 --accept-source-agreements --accept-package-agreements
            Write-Host "Python installed successfully. Please restart PowerShell and run this function again." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install Python automatically. Please install manually from https://python.org"
        }
    }

    # Install Azure CLI if not present
    Write-Host "Checking for Azure CLI..." -ForegroundColor Cyan
    try {
        $azVersion = az --version 2>$null | Select-Object -First 1
        if ($azVersion) {
            Write-Host "Azure CLI found: $azVersion" -ForegroundColor Green
        }
        else {
            throw "Not found"
        }
    }
    catch {
        Write-Host "Azure CLI not found. Installing..." -ForegroundColor Yellow
        try {
            winget install Microsoft.AzureCLI --accept-source-agreements --accept-package-agreements
            Write-Host "Azure CLI installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to install Azure CLI automatically. Please install manually."
        }
    }

    # Install Wireshark if not present
    Write-Host "Checking for Wireshark..." -ForegroundColor Cyan
    try {
        $wiresharkVersion = & "C:\Program Files\Wireshark\tshark.exe" --version 2>$null | Select-Object -First 1
        if ($wiresharkVersion) {
            Write-Host "Wireshark found: $wiresharkVersion" -ForegroundColor Green
        }
        else {
            throw "Not found"
        }
    }
    catch {
        Write-Host "Wireshark not found. Installing..." -ForegroundColor Yellow
        try {
            winget install WiresharkFoundation.Wireshark --accept-source-agreements --accept-package-agreements
            Write-Host "Wireshark installed successfully." -ForegroundColor Green
        }
        catch {
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
            }
            else {
                Write-Warning "Could not find YARA download. Please install manually from https://github.com/VirusTotal/yara/releases"
            }
        }
        catch {
            Write-Warning "Failed to install YARA automatically: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "YARA already available: $yaraPath" -ForegroundColor Green
    }

    # Install Python packages if Python is available
    if ($pythonInstalled -or (Get-Command python -ErrorAction SilentlyContinue)) {
        # Install uv for fast package management
        Write-Host "Checking for uv..." -ForegroundColor Cyan
        try {
            $uvVersion = uv --version 2>$null
            if ($uvVersion) {
                Write-Host "uv found: $uvVersion" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Installing uv for fast Python package management..." -ForegroundColor Yellow
            try {
                winget install astral-sh.uv --accept-source-agreements --accept-package-agreements
                Write-Host "uv installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to install uv automatically. Will use pip."
            }
        }

        Write-Host "Installing Python forensics packages..." -ForegroundColor Cyan
        Get-PythonForensicsTools
    }
    else {
        Write-Warning "Python not available. Run this function again after installing Python."
    }

    Write-Host "Forensic tools installation complete!" -ForegroundColor Green
    Write-Host "Tools location: $winpmemDir" -ForegroundColor Cyan
}