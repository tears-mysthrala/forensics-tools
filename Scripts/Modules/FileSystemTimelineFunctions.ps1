# FileSystemTimelineFunctions.ps1 - File system timeline creation and analysis

function Get-FileSystemTimeline {
    <#
    .SYNOPSIS
        Creates a comprehensive file system timeline.
    .DESCRIPTION
        Analyzes file system metadata to create chronological timelines of file activity.
    .PARAMETER Path
        Directory path to analyze.
    .PARAMETER OutputPath
        Directory to save timeline results.
    .PARAMETER Days
        Number of days to look back (default: 30).
    .EXAMPLE
        Get-FileSystemTimeline -Path C:\ -OutputPath C:\Timeline
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$OutputPath = ".",
        [int]$Days = 30
    )

    Write-Host "Creating file system timeline..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $timelineDir = Join-Path $OutputPath "FileSystemTimeline_$timestamp"

    if (-not (Test-Path $timelineDir)) {
        New-Item -ItemType Directory -Path $timelineDir -Force | Out-Null
    }

    $timelineData = @{
        Timestamp = Get-Date
        Path = $Path
        DaysAnalyzed = $Days
        Timeline = @()
    }

    $cutoffDate = (Get-Date).AddDays(-$Days)

    Write-Host "Scanning file system for timeline data (last $Days days)..." -ForegroundColor Yellow

    try {
        # Get all files and directories
        $items = Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoffDate } |
            Select-Object FullName, Name, Length, CreationTime, LastWriteTime, LastAccessTime, Attributes

        $timeline = @()

        foreach ($item in $items) {
            # Creation event
            if ($item.CreationTime -gt $cutoffDate) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $item.CreationTime
                    EventType = "File Created"
                    Path = $item.FullName
                    Size = $item.Length
                    Attributes = $item.Attributes
                }
            }

            # Last write event
            if ($item.LastWriteTime -gt $cutoffDate) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $item.LastWriteTime
                    EventType = "File Modified"
                    Path = $item.FullName
                    Size = $item.Length
                    Attributes = $item.Attributes
                }
            }

            # Last access event (if different from write)
            if ($item.LastAccessTime -gt $cutoffDate -and
                [math]::Abs(($item.LastAccessTime - $item.LastWriteTime).TotalMinutes) -gt 1) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $item.LastAccessTime
                    EventType = "File Accessed"
                    Path = $item.FullName
                    Size = $item.Length
                    Attributes = $item.Attributes
                }
            }
        }

        # Sort timeline by timestamp
        $timeline = $timeline | Sort-Object Timestamp

        # Export timeline
        $timeline | Export-Csv (Join-Path $timelineDir "filesystem_timeline.csv") -NoTypeInformation

        # Create summary by event type
        $eventSummary = $timeline | Group-Object EventType | Sort-Object Count -Descending
        $eventSummary | Export-Csv (Join-Path $timelineDir "timeline_summary.csv") -NoTypeInformation

        # Create hourly activity chart
        $hourlyActivity = $timeline | Group-Object { $_.Timestamp.Hour } |
            Sort-Object Name |
            Select-Object @{Name="Hour";Expression={$_.Name}}, Count
        $hourlyActivity | Export-Csv (Join-Path $timelineDir "hourly_activity.csv") -NoTypeInformation

        $timelineData.Timeline = $timeline
        $timelineData.TotalEvents = $timeline.Count
        $timelineData.EventSummary = $eventSummary

        Write-Host "[OK] Created timeline with $($timeline.Count) events" -ForegroundColor Green
        Write-Host "  Date range: $cutoffDate to $(Get-Date)" -ForegroundColor Cyan

    } catch {
        Write-Warning "Failed to create file system timeline: $($_.Exception.Message)"
        $timelineData.Error = $_.Exception.Message
    }

    # Save timeline metadata
    $metadataFile = Join-Path $timelineDir "timeline_metadata.json"
    $timelineData | ConvertTo-Json -Depth 3 | Out-File $metadataFile

    Write-Host "File system timeline complete!" -ForegroundColor Green
    Write-Host "Results saved to: $timelineDir" -ForegroundColor Cyan

    return $timelineDir
}