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
                    Timestamp   = $matches[1]
                    Plugin      = $matches[2]
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

    }
    catch {
        Write-Error "Failed to create memory timeline: $($_.Exception.Message)"
    }

    return $null
}