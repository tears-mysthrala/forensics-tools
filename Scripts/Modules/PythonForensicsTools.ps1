# PythonForensicsTools.ps1 - Python forensics tools setup functions

<#
.SYNOPSIS
    Python Forensics Tools Setup Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for setting up Python-based forensic analysis tools.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

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

    # Check for package manager (uv preferred)
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        Write-Host "uv found for fast package management" -ForegroundColor Green
    }
    else {
        # Check pip
        try {
            $pipVersion = & $pythonCmd -m pip --version 2>$null
            Write-Host "Pip found: $($pipVersion.Split()[1])" -ForegroundColor Green
        }
        catch {
            Write-Error "Pip not found. Install pip or ensure Python installation includes pip."
            return $false
        }
    }

    # Required packages
    $packages = @(
        @{Name = "volatility3"; Command = "import volatility3.cli" },
        @{Name = "pefile"; Command = "import pefile" },
        @{Name = "yara-python"; Command = "import yara" },
        @{Name = "construct"; Command = "import construct" }
    )

    foreach ($package in $packages) {
        Write-Host "Checking $($package.Name)..." -ForegroundColor Gray
        $result = & $pythonCmd -c "try: $($package.Command); print('OK') except: print('MISSING')" 2>$null

        if ($result -eq "OK") {
            Write-Host "$($package.Name) is available" -ForegroundColor Green
        }
        else {
            Write-Host "Installing $($package.Name)..." -ForegroundColor Yellow
            try {
                if (Get-Command uv -ErrorAction SilentlyContinue) {
                    $installArgs = ""
                    if ($package.InstallArgs) {
                        $installArgs = $package.InstallArgs
                    }
                    & uv pip install $package.Name $installArgs --quiet 2>$null
                }
                else {
                    $installCmd = "pip install $($package.Name)"
                    if ($package.InstallArgs) {
                        $installCmd += " $($package.InstallArgs)"
                    }
                    & $pythonCmd -m $installCmd --quiet 2>$null
                }
                Write-Host "$($package.Name) installed successfully" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install $($package.Name): $($_.Exception.Message)"
                return $false
            }
        }
    }

    # Verify vol command is available
    Write-Host "Verifying vol command..." -ForegroundColor Gray
    $volCmd = Get-Command vol -ErrorAction SilentlyContinue
    if (-not $volCmd) {
        # Check common paths
        $volPaths = @(
            "$env:USERPROFILE\.local\bin\vol.exe",
            "$env:APPDATA\Python\Scripts\vol.exe",
            (Join-Path (Split-Path $pythonCmd.Source -Parent) "Scripts\vol.exe")
        )
        $volFound = $false
        foreach ($path in $volPaths) {
            if (Test-Path $path) {
                Write-Host "vol.exe found at: $path" -ForegroundColor Green
                Write-Host "Consider adding $(Split-Path $path -Parent) to your PATH for easier access." -ForegroundColor Yellow
                $volFound = $true
                break
            }
        }
        if (-not $volFound) {
            Write-Warning "vol.exe not found in expected locations. You may need to restart PowerShell or add the Python Scripts directory to PATH."
        }
    }
    else {
        Write-Host "vol command available: $($volCmd.Source)" -ForegroundColor Green
    }

    Write-Host "Python forensics tools setup complete!" -ForegroundColor Green
    return $true
}