# SystemVolatilityAnalysis.ps1 - System volatility analysis functions

<#
.SYNOPSIS
    System Volatility Analysis Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for analyzing memory dumps using Volatility framework.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Get-VolatilityAnalysis {
    <#
    .SYNOPSIS
        Performs basic Volatility analysis on a memory dump.
    .DESCRIPTION
        Uses Volatility 3 (Python-based) to analyze memory dumps.
    .PARAMETER MemoryDump
        Path to the memory dump file.
    .PARAMETER AnalysisType
        Type of analysis: 'pslist', 'netscan', 'malware.malfind', 'handles'.
    .EXAMPLE
        Get-VolatilityAnalysis -MemoryDump C:\Evidence\memory.dmp -AnalysisType windows.pslist
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$MemoryDump,
        [ValidateSet('windows.pslist', 'windows.netscan', 'windows.malware.malfind', 'windows.handles', 'windows.dlllist')]
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
        Write-Host "Alternative: Download from https://github.com/volatilityfoundation/volatility3" -ForegroundColor Yellow
        return
    }

    Write-Host "Running Volatility analysis: $AnalysisType" -ForegroundColor Cyan

    try {
        $output = if ($volCmd) { & $volCmd -f $MemoryDump $AnalysisType 2>&1 } else { & $pythonCmd -c "import sys; sys.argv = ['vol', '-f', '$MemoryDump', '$AnalysisType']; from volatility3.cli.vol import main; main()" 2>&1 }
        $output
    }
    catch {
        Write-Error "Volatility analysis failed: $_"
    }
}