# ReportingFunctions.ps1 - Forensic reporting and visualization

function New-ForensicHTMLReport {
    <#
    .SYNOPSIS
        Creates an interactive HTML forensic report.
    .DESCRIPTION
        Generates a comprehensive HTML report with interactive charts, timelines, and evidence correlation.
    .PARAMETER AnalysisData
        Forensic analysis data to include in the report.
    .PARAMETER OutputPath
        Directory to save the HTML report.
    .PARAMETER Title
        Title of the report.
    .EXAMPLE
        New-ForensicHTMLReport -AnalysisData $forensicData -OutputPath C:\Reports -Title "Incident Response Report"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisData,
        [string]$OutputPath = ".",
        [string]$Title = "Forensic Analysis Report"
    )

    Write-Host "Creating HTML forensic report..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $OutputPath "ForensicReport_$timestamp.html"

    # HTML template with embedded CSS and JavaScript
    $htmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/moment@2.29.4/moment.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-moment@1.0.1/dist/chartjs-adapter-moment.min.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
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
        .header .timestamp {
            color: #666;
            font-size: 0.9em;
        }
        .section {
            margin-bottom: 40px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
        }
        .section h2 {
            color: #333;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            margin-top: 0;
        }
        .chart-container {
            position: relative;
            height: 400px;
            margin: 20px 0;
        }
        .evidence-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .evidence-table th, .evidence-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .evidence-table th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        .evidence-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .timeline-item {
            margin: 10px 0;
            padding: 10px;
            border-left: 4px solid #007acc;
            background: #f8f9fa;
        }
        .timeline-timestamp {
            font-weight: bold;
            color: #007acc;
        }
        .timeline-description {
            margin-top: 5px;
            color: #666;
        }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
        .tabs {
            display: flex;
            border-bottom: 1px solid #ddd;
            margin-bottom: 20px;
        }
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-bottom: none;
            margin-right: 5px;
        }
        .tab.active {
            background: white;
            border-bottom: 1px solid white;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            border: 1px solid #ddd;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #007acc;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$Title</h1>
            <div class="timestamp">Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
        </div>

        <div class="summary-stats" id="summaryStats">
            <!-- Summary statistics will be populated by JavaScript -->
        </div>

        <div class="tabs">
            <div class="tab active" onclick="showTab('overview')">Overview</div>
            <div class="tab" onclick="showTab('timeline')">Timeline</div>
            <div class="tab" onclick="showTab('evidence')">Evidence</div>
            <div class="tab" onclick="showTab('analysis')">Analysis</div>
            <div class="tab" onclick="showTab('charts')">Charts</div>
        </div>

        <div id="overview" class="tab-content active">
            <div class="section">
                <h2>Executive Summary</h2>
                <div id="executiveSummary">
                    <!-- Executive summary will be populated by JavaScript -->
                </div>
            </div>
        </div>

        <div id="timeline" class="tab-content">
            <div class="section">
                <h2>Forensic Timeline</h2>
                <div id="timelineContainer">
                    <!-- Timeline will be populated by JavaScript -->
                </div>
            </div>
        </div>

        <div id="evidence" class="tab-content">
            <div class="section">
                <h2>Evidence Collection</h2>
                <div id="evidenceContainer">
                    <!-- Evidence table will be populated by JavaScript -->
                </div>
            </div>
        </div>

        <div id="analysis" class="tab-content">
            <div class="section">
                <h2>Detailed Analysis</h2>
                <div id="analysisContainer">
                    <!-- Analysis details will be populated by JavaScript -->
                </div>
            </div>
        </div>

        <div id="charts" class="tab-content">
            <div class="section">
                <h2>Visual Analytics</h2>
                <div class="chart-container">
                    <canvas id="riskChart"></canvas>
                </div>
                <div class="chart-container">
                    <canvas id="activityChart"></canvas>
                </div>
                <div class="chart-container">
                    <canvas id="fileTypeChart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Analysis data embedded as JSON
        const analysisData = ANALYSIS_DATA_PLACEHOLDER;

        // Tab switching functionality
        function showTab(tabName) {
            const tabs = document.querySelectorAll('.tab');
            const contents = document.querySelectorAll('.tab-content');

            tabs.forEach(tab => tab.classList.remove('active'));
            contents.forEach(content => content.classList.remove('active'));

            document.querySelector(`.tab[onclick="showTab('\${tabName}')"]`).classList.add('active');
            document.getElementById(tabName).classList.add('active');
        }

        // Populate summary statistics
        function populateSummaryStats() {
            const statsContainer = document.getElementById('summaryStats');
            let totalFiles = 0;
            let highRiskItems = 0;
            let suspiciousActivities = 0;

            // Calculate statistics from analysis data
            if (analysisData.FileAnalysis) {
                totalFiles = analysisData.FileAnalysis.length || 0;
                highRiskItems = analysisData.FileAnalysis.filter(f => f.RiskLevel === 'High').length || 0;
            }

            if (analysisData.NetworkAnalysis) {
                suspiciousActivities += analysisData.NetworkAnalysis.SuspiciousConnections || 0;
            }

            statsContainer.innerHTML = `
                <div class="stat-card">
                    <div class="stat-value">\${totalFiles}</div>
                    <div class="stat-label">Files Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">\${highRiskItems}</div>
                    <div class="stat-label">High Risk Items</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">\${suspiciousActivities}</div>
                    <div class="stat-label">Suspicious Activities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">\${analysisData.Timestamp ? new Date(analysisData.Timestamp).toLocaleDateString() : 'N/A'}</div>
                    <div class="stat-label">Analysis Date</div>
                </div>
            `;
        }

        // Populate executive summary
        function populateExecutiveSummary() {
            const summaryContainer = document.getElementById('executiveSummary');
            let summary = '<p>This forensic analysis report contains findings from a comprehensive digital investigation.</p>';

            if (analysisData.SystemInfo) {
                summary += `<p><strong>System Analyzed:</strong> \${analysisData.SystemInfo.Hostname || 'Unknown'} (\${analysisData.SystemInfo.OS || 'Unknown OS'})</p>`;
            }

            if (analysisData.FileAnalysis) {
                const highRisk = analysisData.FileAnalysis.filter(f => f.RiskLevel === 'High').length;
                const mediumRisk = analysisData.FileAnalysis.filter(f => f.RiskLevel === 'Medium').length;
                summary += `<p><strong>Risk Assessment:</strong> \${highRisk} high-risk, \${mediumRisk} medium-risk items identified.</p>`;
            }

            summaryContainer.innerHTML = summary;
        }

        // Populate timeline
        function populateTimeline() {
            const timelineContainer = document.getElementById('timelineContainer');

            if (!analysisData.Timeline) {
                timelineContainer.innerHTML = '<p>No timeline data available.</p>';
                return;
            }

            let timelineHTML = '';
            analysisData.Timeline.forEach(item => {
                timelineHTML += `
                    <div class="timeline-item">
                        <div class="timeline-timestamp">\${new Date(item.Timestamp).toLocaleString()}</div>
                        <div class="timeline-description">\${item.EventType}: \${item.Description || item.Path || 'Unknown event'}</div>
                    </div>
                `;
            });

            timelineContainer.innerHTML = timelineHTML;
        }

        // Populate evidence table
        function populateEvidence() {
            const evidenceContainer = document.getElementById('evidenceContainer');

            if (!analysisData.Evidence) {
                evidenceContainer.innerHTML = '<p>No evidence data available.</p>';
                return;
            }

            let tableHTML = `
                <table class="evidence-table">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Description</th>
                            <th>Path/Location</th>
                            <th>Risk Level</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            analysisData.Evidence.forEach(item => {
                const riskClass = item.RiskLevel ? `risk-\${item.RiskLevel.toLowerCase()}` : '';
                tableHTML += `
                    <tr>
                        <td>\${item.Type || 'Unknown'}</td>
                        <td>\${item.Description || 'N/A'}</td>
                        <td>\${item.Path || item.Location || 'N/A'}</td>
                        <td class="\${riskClass}">\${item.RiskLevel || 'Unknown'}</td>
                        <td>\${item.Timestamp ? new Date(item.Timestamp).toLocaleString() : 'N/A'}</td>
                    </tr>
                `;
            });

            tableHTML += '</tbody></table>';
            evidenceContainer.innerHTML = tableHTML;
        }

        // Populate analysis details
        function populateAnalysis() {
            const analysisContainer = document.getElementById('analysisContainer');
            let analysisHTML = '<h3>Analysis Details</h3>';

            if (analysisData.NetworkAnalysis) {
                analysisHTML += '<h4>Network Analysis</h4>';
                analysisHTML += `<p>Connections analyzed: \${analysisData.NetworkAnalysis.TotalConnections || 0}</p>`;
                analysisHTML += `<p>Suspicious connections: \${analysisData.NetworkAnalysis.SuspiciousConnections || 0}</p>`;
            }

            if (analysisData.MemoryAnalysis) {
                analysisHTML += '<h4>Memory Analysis</h4>';
                analysisHTML += `<p>Processes found: \${analysisData.MemoryAnalysis.ProcessCount || 0}</p>`;
                analysisHTML += `<p>Memory artifacts: \${analysisData.MemoryAnalysis.ArtifactCount || 0}</p>`;
            }

            analysisContainer.innerHTML = analysisHTML;
        }

        // Create charts
        function createCharts() {
            // Risk distribution chart
            const riskCtx = document.getElementById('riskChart').getContext('2d');
            const riskData = {
                labels: ['Low Risk', 'Medium Risk', 'High Risk'],
                datasets: [{
                    label: 'Risk Distribution',
                    data: [
                        analysisData.FileAnalysis ? analysisData.FileAnalysis.filter(f => f.RiskLevel === 'Low').length : 0,
                        analysisData.FileAnalysis ? analysisData.FileAnalysis.filter(f => f.RiskLevel === 'Medium').length : 0,
                        analysisData.FileAnalysis ? analysisData.FileAnalysis.filter(f => f.RiskLevel === 'High').length : 0
                    ],
                    backgroundColor: ['#28a745', '#ffc107', '#dc3545'],
                    borderWidth: 1
                }]
            };

            new Chart(riskCtx, {
                type: 'pie',
                data: riskData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });

            // Activity timeline chart
            const activityCtx = document.getElementById('activityChart').getContext('2d');
            if (analysisData.Timeline) {
                const timelineData = analysisData.Timeline.reduce((acc, item) => {
                    const date = new Date(item.Timestamp).toDateString();
                    acc[date] = (acc[date] || 0) + 1;
                    return acc;
                }, {});

                const activityData = {
                    labels: Object.keys(timelineData),
                    datasets: [{
                        label: 'Activity Count',
                        data: Object.values(timelineData),
                        borderColor: '#007acc',
                        backgroundColor: 'rgba(0, 122, 204, 0.1)',
                        fill: true
                    }]
                };

                new Chart(activityCtx, {
                    type: 'line',
                    data: activityData,
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            x: {
                                type: 'time',
                                time: {
                                    unit: 'day'
                                }
                            }
                        }
                    }
                });
            }

            // File type distribution chart
            const fileTypeCtx = document.getElementById('fileTypeChart').getContext('2d');
            if (analysisData.FileAnalysis) {
                const fileTypes = analysisData.FileAnalysis.reduce((acc, file) => {
                    const ext = file.Extension || 'Unknown';
                    acc[ext] = (acc[ext] || 0) + 1;
                    return acc;
                }, {});

                const fileTypeData = {
                    labels: Object.keys(fileTypes),
                    datasets: [{
                        label: 'File Count',
                        data: Object.values(fileTypes),
                        backgroundColor: 'rgba(0, 122, 204, 0.8)',
                        borderWidth: 1
                    }]
                };

                new Chart(fileTypeCtx, {
                    type: 'bar',
                    data: fileTypeData,
                    options: {
                        responsive: true,
                        maintainAspectRatio: false
                    }
                });
            }
        }

        // Initialize the report
        document.addEventListener('DOMContentLoaded', function() {
            populateSummaryStats();
            populateExecutiveSummary();
            populateTimeline();
            populateEvidence();
            populateAnalysis();
            createCharts();
        });
    </script>
</body>
</html>
"@

    # Convert analysis data to JSON and embed in HTML
    $analysisJson = $AnalysisData | ConvertTo-Json -Depth 4 -Compress
    $htmlContent = $htmlTemplate -replace "ANALYSIS_DATA_PLACEHOLDER", $analysisJson

    # Write the HTML report
    $htmlContent | Out-File $reportFile -Encoding UTF8

    Write-Host "✓ HTML report created: $reportFile" -ForegroundColor Green

    # Try to open the report in default browser
    try {
        Start-Process $reportFile
        Write-Host "✓ Report opened in default browser" -ForegroundColor Green
    } catch {
        Write-Host "Note: Could not automatically open report. Please open manually: $reportFile" -ForegroundColor Yellow
    }

    return $reportFile
}

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
                    <div class="timestamp">\${new Date(item.Timestamp).toLocaleString()}</div>
                    <div class="event-type">\${item.EventType}</div>
                    <div class="description">\${item.Description || item.Path || 'No description available'}</div>
                    \${item.Details ? `<div class="details">\${item.Details}</div>` : ''}
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

function New-EvidenceCorrelationDashboard {
    <#
    .SYNOPSIS
        Creates an evidence correlation dashboard.
    .DESCRIPTION
        Generates an interactive dashboard showing correlations between different types of evidence.
    .PARAMETER EvidenceData
        Collection of evidence data from various sources.
    .PARAMETER OutputPath
        Directory to save the correlation dashboard.
    .PARAMETER Title
        Title of the dashboard.
    .EXAMPLE
        New-EvidenceCorrelationDashboard -EvidenceData $evidence -OutputPath C:\Reports -Title "Evidence Correlation"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$EvidenceData,
        [string]$OutputPath = ".",
        [string]$Title = "Evidence Correlation Dashboard"
    )

    Write-Host "Creating evidence correlation dashboard..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $dashboardFile = Join-Path $OutputPath "CorrelationDashboard_$timestamp.html"

    # HTML dashboard template
    $dashboardHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/d3@7.8.5/dist/d3.min.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
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
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .dashboard-card {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .card-title {
            font-size: 1.2em;
            font-weight: bold;
            color: #333;
            margin-bottom: 15px;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .correlation-matrix {
            margin: 20px 0;
        }
        .correlation-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            border: 1px solid #ddd;
            margin: 5px 0;
            border-radius: 4px;
            background: #f9f9fa;
        }
        .correlation-strength {
            font-weight: bold;
        }
        .strength-high { color: #dc3545; }
        .strength-medium { color: #ffc107; }
        .strength-low { color: #28a745; }
        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }
        .evidence-network {
            width: 100%;
            height: 500px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .evidence-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .evidence-table th, .evidence-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .evidence-table th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        .evidence-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .filter-section {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .filter-controls {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .filter-controls select, .filter-controls input {
            padding: 5px 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .risk-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .risk-high { background-color: #dc3545; color: white; }
        .risk-medium { background-color: #ffc107; color: black; }
        .risk-low { background-color: #28a745; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$Title</h1>
            <div>Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
        </div>

        <div class="filter-section">
            <div class="filter-controls">
                <label>Risk Level Filter:</label>
                <select id="riskFilter">
                    <option value="all">All Risk Levels</option>
                    <option value="high">High Risk</option>
                    <option value="medium">Medium Risk</option>
                    <option value="low">Low Risk</option>
                </select>

                <label>Evidence Type Filter:</label>
                <select id="typeFilter">
                    <option value="all">All Types</option>
                    <!-- Type options will be populated by JavaScript -->
                </select>

                <label>Time Range:</label>
                <input type="date" id="startDate">
                <input type="date" id="endDate">
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="dashboard-card">
                <div class="card-title">Evidence Overview</div>
                <div class="chart-container">
                    <canvas id="evidenceOverviewChart"></canvas>
                </div>
            </div>

            <div class="dashboard-card">
                <div class="card-title">Risk Distribution</div>
                <div class="chart-container">
                    <canvas id="riskDistributionChart"></canvas>
                </div>
            </div>

            <div class="dashboard-card">
                <div class="card-title">Evidence Correlations</div>
                <div id="correlationMatrix">
                    <!-- Correlation matrix will be populated by JavaScript -->
                </div>
            </div>

            <div class="dashboard-card">
                <div class="card-title">Evidence Network</div>
                <div class="evidence-network" id="evidenceNetwork"></div>
            </div>
        </div>

        <div class="dashboard-card">
            <div class="card-title">Detailed Evidence Table</div>
            <div id="evidenceTableContainer">
                <!-- Evidence table will be populated by JavaScript -->
            </div>
        </div>
    </div>

    <script>
        const evidenceData = EVIDENCE_DATA_PLACEHOLDER;

        // Flatten evidence data for processing
        let allEvidence = [];
        if (evidenceData.Files) allEvidence = allEvidence.concat(evidenceData.Files.map(f => ({...f, Type: 'File'})));
        if (evidenceData.Network) allEvidence = allEvidence.concat(evidenceData.Network.map(n => ({...n, Type: 'Network'})));
        if (evidenceData.Processes) allEvidence = allEvidence.concat(evidenceData.Processes.map(p => ({...p, Type: 'Process'})));
        if (evidenceData.Registry) allEvidence = allEvidence.concat(evidenceData.Registry.map(r => ({...r, Type: 'Registry'})));

        // Populate type filter
        function populateTypeFilter() {
            const types = [...new Set(allEvidence.map(item => item.Type))];
            const typeFilter = document.getElementById('typeFilter');

            types.forEach(type => {
                const option = document.createElement('option');
                option.value = type;
                option.textContent = type;
                typeFilter.appendChild(option);
            });
        }

        // Filter evidence based on current filters
        function getFilteredEvidence() {
            let filtered = allEvidence;

            const riskFilter = document.getElementById('riskFilter').value;
            if (riskFilter !== 'all') {
                filtered = filtered.filter(item => (item.RiskLevel || 'Unknown').toLowerCase() === riskFilter);
            }

            const typeFilter = document.getElementById('typeFilter').value;
            if (typeFilter !== 'all') {
                filtered = filtered.filter(item => item.Type === typeFilter);
            }

            const startDate = document.getElementById('startDate').value;
            const endDate = document.getElementById('endDate').value;

            if (startDate) {
                const start = new Date(startDate);
                filtered = filtered.filter(item => new Date(item.Timestamp) >= start);
            }

            if (endDate) {
                const end = new Date(endDate);
                filtered = filtered.filter(item => new Date(item.Timestamp) <= end);
            }

            return filtered;
        }

        // Create evidence overview chart
        function createEvidenceOverviewChart() {
            const ctx = document.getElementById('evidenceOverviewChart').getContext('2d');
            const filteredEvidence = getFilteredEvidence();

            const typeCounts = filteredEvidence.reduce((acc, item) => {
                acc[item.Type] = (acc[item.Type] || 0) + 1;
                return acc;
            }, {});

            const data = {
                labels: Object.keys(typeCounts),
                datasets: [{
                    label: 'Evidence Count',
                    data: Object.values(typeCounts),
                    backgroundColor: ['#007acc', '#28a745', '#ffc107', '#dc3545', '#6f42c1'],
                    borderWidth: 1
                }]
            };

            new Chart(ctx, {
                type: 'doughnut',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }

        // Create risk distribution chart
        function createRiskDistributionChart() {
            const ctx = document.getElementById('riskDistributionChart').getContext('2d');
            const filteredEvidence = getFilteredEvidence();

            const riskCounts = filteredEvidence.reduce((acc, item) => {
                const risk = item.RiskLevel || 'Unknown';
                acc[risk] = (acc[risk] || 0) + 1;
                return acc;
            }, {});

            const data = {
                labels: Object.keys(riskCounts),
                datasets: [{
                    label: 'Risk Count',
                    data: Object.values(riskCounts),
                    backgroundColor: ['#dc3545', '#ffc107', '#28a745', '#6c757d'],
                    borderWidth: 1
                }]
            };

            new Chart(ctx, {
                type: 'bar',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }

        // Create correlation matrix
        function createCorrelationMatrix() {
            const correlationContainer = document.getElementById('correlationMatrix');
            const filteredEvidence = getFilteredEvidence();

            // Simple correlation based on timestamps (items close in time are correlated)
            const correlations = [];

            for (let i = 0; i < filteredEvidence.length; i++) {
                for (let j = i + 1; j < filteredEvidence.length; j++) {
                    const item1 = filteredEvidence[i];
                    const item2 = filteredEvidence[j];

                    if (item1.Timestamp && item2.Timestamp) {
                        const time1 = new Date(item1.Timestamp);
                        const time2 = new Date(item2.Timestamp);
                        const timeDiff = Math.abs(time1 - time2) / (1000 * 60); // minutes

                        if (timeDiff < 60) { // Within 1 hour
                            let strength = 'low';
                            if (timeDiff < 5) strength = 'high';
                            else if (timeDiff < 30) strength = 'medium';

                            correlations.push({
                                item1: `\${item1.Type}: \${item1.Name || item1.Path || 'Unknown'}`,
                                item2: `\${item2.Type}: \${item2.Name || item2.Path || 'Unknown'}`,
                                strength: strength,
                                timeDiff: Math.round(timeDiff)
                            });
                        }
                    }
                }
            }

            // Display top correlations
            const topCorrelations = correlations.slice(0, 10);
            let html = '';

            topCorrelations.forEach(corr => {
                html += `
                    <div class="correlation-item">
                        <div>
                            <strong>\${corr.item1}</strong> ↔ <strong>\${corr.item2}</strong>
                            <br><small>\${corr.timeDiff} minutes apart</small>
                        </div>
                        <div class="correlation-strength strength-\${corr.strength}">
                            \${corr.strength.toUpperCase()}
                        </div>
                    </div>
                `;
            });

            correlationContainer.innerHTML = html || '<p>No significant correlations found.</p>';
        }

        // Create evidence table
        function createEvidenceTable() {
            const tableContainer = document.getElementById('evidenceTableContainer');
            const filteredEvidence = getFilteredEvidence();

            let tableHtml = `
                <table class="evidence-table">
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Name/Path</th>
                            <th>Risk Level</th>
                            <th>Timestamp</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            filteredEvidence.forEach(item => {
                const riskClass = item.RiskLevel ? `risk-\${item.RiskLevel.toLowerCase()}` : '';
                tableHtml += `
                    <tr>
                        <td>\${item.Type}</td>
                        <td>\${item.Name || item.Path || 'N/A'}</td>
                        <td><span class="risk-badge \${riskClass}">\${item.RiskLevel || 'Unknown'}</span></td>
                        <td>\${item.Timestamp ? new Date(item.Timestamp).toLocaleString() : 'N/A'}</td>
                        <td>\${item.Description || 'N/A'}</td>
                    </tr>
                `;
            });

            tableHtml += '</tbody></table>';
            tableContainer.innerHTML = tableHtml;
        }

        // Create evidence network visualization
        function createEvidenceNetwork() {
            const networkContainer = document.getElementById('evidenceNetwork');
            const filteredEvidence = getFilteredEvidence();

            // Create nodes and links for D3 visualization
            const nodes = filteredEvidence.map((item, index) => ({
                id: index,
                name: item.Name || item.Path || `Item \${index}`,
                type: item.Type,
                risk: item.RiskLevel || 'Unknown',
                group: item.Type
            }));

            const links = [];
            // Create links based on correlations (simplified)
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    if (nodes[i].type !== nodes[j].type) { // Link different types
                        links.push({
                            source: i,
                            target: j,
                            value: 1
                        });
                    }
                }
            }

            // D3 force-directed graph
            const svg = d3.select('#evidenceNetwork')
                .append('svg')
                .attr('width', '100%')
                .attr('height', '100%');

            const simulation = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id))
                .force('charge', d3.forceManyBody().strength(-100))
                .force('center', d3.forceCenter(networkContainer.clientWidth / 2, 250));

            const link = svg.append('g')
                .selectAll('line')
                .data(links)
                .enter().append('line')
                .attr('stroke', '#999')
                .attr('stroke-opacity', 0.6)
                .attr('stroke-width', d => Math.sqrt(d.value));

            const node = svg.append('g')
                .selectAll('circle')
                .data(nodes)
                .enter().append('circle')
                .attr('r', 8)
                .attr('fill', d => {
                    const colors = { File: '#007acc', Network: '#28a745', Process: '#ffc107', Registry: '#dc3545' };
                    return colors[d.type] || '#6c757d';
                })
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended));

            node.append('title')
                .text(d => `\${d.name} (\${d.type})`);

            simulation.on('tick', () => {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);

                node
                    .attr('cx', d => d.x)
                    .attr('cy', d => d.y);
            });

            function dragstarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }

            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }

            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }
        }

        // Update all visualizations when filters change
        function updateVisualizations() {
            createEvidenceOverviewChart();
            createRiskDistributionChart();
            createCorrelationMatrix();
            createEvidenceTable();
        }

        // Event listeners for filters
        document.getElementById('riskFilter').addEventListener('change', updateVisualizations);
        document.getElementById('typeFilter').addEventListener('change', updateVisualizations);
        document.getElementById('startDate').addEventListener('change', updateVisualizations);
        document.getElementById('endDate').addEventListener('change', updateVisualizations);

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            populateTypeFilter();
            updateVisualizations();
            createEvidenceNetwork();
        });
    </script>
</body>
</html>
"@

    # Convert evidence data to JSON and embed in HTML
    $evidenceJson = $EvidenceData | ConvertTo-Json -Depth 4 -Compress
    $htmlContent = $dashboardHtml -replace "EVIDENCE_DATA_PLACEHOLDER", $evidenceJson

    # Write the correlation dashboard
    $htmlContent | Out-File $dashboardFile -Encoding UTF8

    Write-Host "✓ Evidence correlation dashboard created: $dashboardFile" -ForegroundColor Green

    # Try to open the dashboard in default browser
    try {
        Start-Process $dashboardFile
        Write-Host "✓ Dashboard opened in default browser" -ForegroundColor Green
    } catch {
        Write-Host "Note: Could not automatically open dashboard. Please open manually: $dashboardFile" -ForegroundColor Yellow
    }

    return $dashboardFile
}

function Export-ForensicReport {
    <#
    .SYNOPSIS
        Exports a comprehensive forensic report in multiple formats.
    .DESCRIPTION
        Generates forensic reports in JSON, CSV, and HTML formats with evidence correlation.
    .PARAMETER AnalysisResults
        Results from forensic analysis functions.
    .PARAMETER OutputPath
        Directory to save the reports.
    .PARAMETER Formats
        Report formats to generate (JSON, CSV, HTML).
    .EXAMPLE
        Export-ForensicReport -AnalysisResults $results -OutputPath C:\Reports -Formats @("JSON", "HTML")
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisResults,
        [string]$OutputPath = ".",
        [string[]]$Formats = @("JSON", "HTML")
    )

    Write-Host "Exporting comprehensive forensic report..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportDir = Join-Path $OutputPath "ForensicReport_$timestamp"

    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }

    $exportedFiles = @()

    # Export JSON format
    if ($Formats -contains "JSON") {
        Write-Host "Exporting JSON report..." -ForegroundColor Yellow
        $jsonFile = Join-Path $reportDir "forensic_report.json"
        $AnalysisResults | ConvertTo-Json -Depth 4 | Out-File $jsonFile
        $exportedFiles += $jsonFile
        Write-Host "✓ JSON report exported" -ForegroundColor Green
    }

    # Export CSV format
    if ($Formats -contains "CSV") {
        Write-Host "Exporting CSV reports..." -ForegroundColor Yellow

        # Flatten and export different data types
        if ($AnalysisResults.FileAnalysis) {
            $csvFile = Join-Path $reportDir "file_analysis.csv"
            $AnalysisResults.FileAnalysis | Export-Csv $csvFile -NoTypeInformation
            $exportedFiles += $csvFile
        }

        if ($AnalysisResults.NetworkAnalysis) {
            $csvFile = Join-Path $reportDir "network_analysis.csv"
            $AnalysisResults.NetworkAnalysis | Export-Csv $csvFile -NoTypeInformation
            $exportedFiles += $csvFile
        }

        if ($AnalysisResults.ProcessAnalysis) {
            $csvFile = Join-Path $reportDir "process_analysis.csv"
            $AnalysisResults.ProcessAnalysis | Export-Csv $csvFile -NoTypeInformation
            $exportedFiles += $csvFile
        }

        Write-Host "✓ CSV reports exported" -ForegroundColor Green
    }

    # Export HTML format
    if ($Formats -contains "HTML") {
        Write-Host "Creating HTML report..." -ForegroundColor Yellow
        $htmlFile = New-ForensicHTMLReport -AnalysisData $AnalysisResults -OutputPath $reportDir -Title "Comprehensive Forensic Report"
        $exportedFiles += $htmlFile
        Write-Host "✓ HTML report created" -ForegroundColor Green
    }

    # Create report summary
    $summaryFile = Join-Path $reportDir "report_summary.txt"
    $summary = @"
FORENSIC ANALYSIS REPORT SUMMARY
================================

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Report Directory: $reportDir

EXPORTED FILES:
$($exportedFiles | ForEach-Object { "  - " + (Split-Path $_ -Leaf) })

ANALYSIS SUMMARY:
"@

    if ($AnalysisResults.SystemInfo) {
        $summary += "`nSystem Information:`n"
        $summary += "  Hostname: $($AnalysisResults.SystemInfo.Hostname)`n"
        $summary += "  OS: $($AnalysisResults.SystemInfo.OS)`n"
    }

    if ($AnalysisResults.FileAnalysis) {
        $highRisk = ($AnalysisResults.FileAnalysis | Where-Object { $_.RiskLevel -eq "High" }).Count
        $summary += "`nFile Analysis:`n"
        $summary += "  Files analyzed: $($AnalysisResults.FileAnalysis.Count)`n"
        $summary += "  High risk files: $highRisk`n"
    }

    if ($AnalysisResults.NetworkAnalysis) {
        $summary += "`nNetwork Analysis:`n"
        $summary += "  Connections analyzed: $($AnalysisResults.NetworkAnalysis.TotalConnections)`n"
        $summary += "  Suspicious activities: $($AnalysisResults.NetworkAnalysis.SuspiciousConnections)`n"
    }

    $summary | Out-File $summaryFile

    Write-Host "✓ Forensic report export complete!" -ForegroundColor Green
    Write-Host "Reports saved to: $reportDir" -ForegroundColor Cyan
    Write-Host "Summary: $summaryFile" -ForegroundColor Cyan

    return $reportDir
}