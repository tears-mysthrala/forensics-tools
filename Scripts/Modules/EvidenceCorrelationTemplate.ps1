# EvidenceCorrelationTemplate.ps1
# HTML template functions for evidence correlation dashboard

<#
.SYNOPSIS
    Evidence Correlation Dashboard Template Functions

.DESCRIPTION
    This module provides HTML template functions for creating evidence correlation dashboards.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function Get-EvidenceCorrelationHTMLTemplate {
    <#
    .SYNOPSIS
        Gets the HTML template for evidence correlation dashboard

    .DESCRIPTION
        Returns the complete HTML template with embedded CSS and JavaScript for the evidence correlation dashboard

    .PARAMETER Title
        Title for the dashboard

    .PARAMETER EvidenceData
        Evidence data to embed in the template

    .EXAMPLE
        $template = Get-EvidenceCorrelationHTMLTemplate -Title "Evidence Dashboard" -EvidenceData $evidence
    #>
    param(
        [string]$Title = "Evidence Correlation Dashboard",
        [hashtable]$EvidenceData = @{}
    )

    # Convert evidence data to JSON for embedding
    $evidenceJson = $EvidenceData | ConvertTo-Json -Depth 10 -Compress

    $htmlTemplate = @"
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
        const evidenceData = $evidenceJson;

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
                                item2: `\${item2.Type}: \${item2.Type}: \${item2.Name || item2.Path || 'Unknown'}`,
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

    return $htmlTemplate
}