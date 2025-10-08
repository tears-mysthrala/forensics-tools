# TimelineVisualizationFunctions.ps1 - Timeline visualization

function New-ForensicTimelineVisualization {
    <#
    .SYNOPSIS
        Creates an interactive timeline visualization.
    .DESCRIPTION
        Generates an HTML timeline visualization of forensic events and activities.
    .PARAMETER TimelineData
        Array of timeline events with timestamps.
    .PARAMETER OutputPath
        Directory to save the timeline visualization.
    .PARAMETER Title
        Title of the timeline.
    .EXAMPLE
        New-ForensicTimelineVisualization -TimelineData $events -OutputPath C:\Reports -Title "Incident Timeline"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$TimelineData,
        [string]$OutputPath = ".",
        [string]$Title = "Forensic Timeline"
    )

    Write-Host "Creating timeline visualization..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $timelineFile = Join-Path $OutputPath "Timeline_$timestamp.html"

    # Sort timeline data by timestamp
    $sortedTimeline = $TimelineData | Sort-Object { [DateTime]::Parse($_.Timestamp) }

    # HTML timeline template
    $timelineHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 2px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #007acc;
            margin: 0;
        }
        .timeline {
            position: relative;
            max-width: 800px;
            margin: 0 auto;
        }
        .timeline::after {
            content: '';
            position: absolute;
            width: 6px;
            background-color: #007acc;
            top: 0;
            bottom: 0;
            left: 50%;
            margin-left: -3px;
        }
        .timeline-item {
            padding: 10px 40px;
            position: relative;
            background-color: inherit;
            width: 50%;
        }
        .timeline-item::after {
            content: '';
            position: absolute;
            width: 25px;
            height: 25px;
            right: -17px;
            background-color: white;
            border: 4px solid #007acc;
            top: 15px;
            border-radius: 50%;
            z-index: 1;
        }
        .left {
            left: 0;
        }
        .right {
            left: 50%;
        }
        .right::after {
            left: -16px;
        }
        .content {
            padding: 20px 30px;
            background-color: white;
            position: relative;
            border-radius: 6px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .content .timestamp {
            color: #007acc;
            font-weight: bold;
            font-size: 1.1em;
        }
        .content .event-type {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        .content .description {
            margin: 10px 0;
        }
        .content .details {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-family: monospace;
            font-size: 0.9em;
        }
        .filter-controls {
            margin-bottom: 20px;
            text-align: center;
        }
        .filter-controls select {
            padding: 5px 10px;
            margin: 0 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .legend {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin: 5px 15px;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 8px;
            border: 2px solid #fff;
            box-shadow: 0 0 0 1px #ddd;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$Title</h1>
            <div>Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
        </div>

        <div class="filter-controls">
            <label>Filter by Event Type:</label>
            <select id="eventFilter">
                <option value="all">All Events</option>
                <!-- Event type options will be populated by JavaScript -->
            </select>
        </div>

        <div class="legend" id="legend">
            <!-- Legend will be populated by JavaScript -->
        </div>

        <div class="timeline" id="timeline">
            <!-- Timeline items will be populated by JavaScript -->
        </div>
    </div>

    <script>
        const timelineData = TIMELINE_DATA_PLACEHOLDER;

        // Color mapping for event types
        const eventColors = {
            'File Created': '#28a745',
            'File Modified': '#ffc107',
            'File Accessed': '#17a2b8',
            'File Deleted': '#dc3545',
            'Process Started': '#6f42c1',
            'Network Connection': '#e83e8c',
            'Registry Modified': '#fd7e14',
            'Log Entry': '#20c997',
            'default': '#007acc'
        };

        // Populate filter options
        function populateFilters() {
            const eventTypes = [...new Set(timelineData.map(item => item.EventType))];
            const filterSelect = document.getElementById('eventFilter');

            eventTypes.forEach(type => {
                const option = document.createElement('option');
                option.value = type;
                option.textContent = type;
                filterSelect.appendChild(option);
            });
        }

        // Create legend
        function createLegend() {
            const legendContainer = document.getElementById('legend');
            const eventTypes = [...new Set(timelineData.map(item => item.EventType))];

            eventTypes.forEach(type => {
                const legendItem = document.createElement('div');
                legendItem.className = 'legend-item';

                const colorBox = document.createElement('div');
                colorBox.className = 'legend-color';
                colorBox.style.backgroundColor = eventColors[type] || eventColors.default;

                const label = document.createElement('span');
                label.textContent = type;

                legendItem.appendChild(colorBox);
                legendItem.appendChild(label);
                legendContainer.appendChild(legendItem);
            });
        }

        // Render timeline
        function renderTimeline(filterType = 'all') {
            const timelineContainer = document.getElementById('timeline');
            timelineContainer.innerHTML = '';

            const filteredData = filterType === 'all' ?
                timelineData :
                timelineData.filter(item => item.EventType === filterType);

            filteredData.forEach((item, index) => {
                const timelineItem = document.createElement('div');
                timelineItem.className = `timeline-item \${index % 2 === 0 ? 'left' : 'right'}`;

                const content = document.createElement('div');
                content.className = 'content';
                content.style.borderLeft = `4px solid \${eventColors[item.EventType] || eventColors.default}`;

                content.innerHTML = `
                    <div class="timestamp">`${new Date(item.Timestamp).toLocaleString()}</div>
                    <div class="event-type">`${item.EventType}</div>
                    <div class="description">`${item.Description || item.Path || 'No description available'}</div>
                    `${item.Details ? `<div class="details">`${item.Details}</div>` : ''}
                `;

                timelineItem.appendChild(content);
                timelineContainer.appendChild(timelineItem);
            });
        }

        // Event listeners
        document.getElementById('eventFilter').addEventListener('change', function(e) {
            renderTimeline(e.target.value);
        });

        // Initialize timeline
        document.addEventListener('DOMContentLoaded', function() {
            populateFilters();
            createLegend();
            renderTimeline();
        });
    </script>
</body>
</html>
"@

    # Convert timeline data to JSON and embed in HTML
    $timelineJson = $sortedTimeline | ConvertTo-Json -Depth 4 -Compress
    $htmlContent = $timelineHtml -replace "TIMELINE_DATA_PLACEHOLDER", $timelineJson

    # Write the timeline visualization
    $htmlContent | Out-File $timelineFile -Encoding UTF8

    Write-Host "✓ Timeline visualization created: $timelineFile" -ForegroundColor Green

    # Try to open the timeline in default browser
    try {
        Start-Process $timelineFile
        Write-Host "✓ Timeline opened in default browser" -ForegroundColor Green
    } catch {
        Write-Host "Note: Could not automatically open timeline. Please open manually: $timelineFile" -ForegroundColor Yellow
    }

    return $timelineFile
}