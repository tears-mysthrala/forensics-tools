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