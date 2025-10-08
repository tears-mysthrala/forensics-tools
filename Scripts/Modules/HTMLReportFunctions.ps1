# HTMLReportFunctions.ps1 - HTML report generation

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