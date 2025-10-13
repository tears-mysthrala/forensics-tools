# SystemMemoryDump.ps1 - System memory dump acquisition functions

<#
.SYNOPSIS
    System Memory Dump Acquisition Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for capturing live memory dumps of entire systems.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

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
    }
    else {
        # It's a file path, use it directly (but ensure .dmp extension for tools)
        if ($OutputPath -notmatch '\.dmp$') {
            $outputFile = $OutputPath + ".dmp"
        }
        else {
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
                    }
                    else {
                        Write-Error "WinPMEM failed to create memory dump"
                    }
                }
                catch {
                    Write-Error "WinPMEM execution failed: $($_.Exception.Message)"
                }
            }
            else {
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
                }
                catch {
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
                    }
                    else {
                        Write-Error "DumpIt failed to create memory dump"
                    }
                }
                catch {
                    Write-Error "DumpIt execution failed: $($_.Exception.Message)"
                }
            }
            else {
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
                $processMemory = Get-Process | Select-Object Name, Id, @{Name = "MemoryMB"; Expression = { [math]::Round($_.WorkingSet / 1MB, 2) } }
            }
            catch {
                Write-Error "Failed to collect memory information: $($_.Exception.Message)"
                return $null
            }

            $evidence = @{
                Timestamp     = Get-Date
                SystemMemory  = $memoryInfo
                ProcessMemory = $processMemory
            }

            # Create JSON file alongside the DMP file
            $jsonFile = $outputFile -replace '\.dmp$', '.json'
            try {
                $evidence | ConvertTo-Json -Depth 3 | Out-File $jsonFile
                Write-Host "Memory information saved to: $jsonFile" -ForegroundColor Green
                return $jsonFile
            }
            catch {
                Write-Error "Failed to save memory information: $($_.Exception.Message)"
                return $null
            }
        }
    }

    Write-Error "Memory acquisition failed. Install WinPMEM or DumpIt for proper memory dumping."
    return $null
}