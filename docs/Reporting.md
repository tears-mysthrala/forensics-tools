# Reporting and Visualization

Forensic reporting and visualization with interactive HTML reports and dashboards.

## Functions

### New-ForensicHTMLReport

Creates an interactive HTML forensic report with charts, timelines, and evidence correlation.

```powershell
New-ForensicHTMLReport -InputPath "C:\Analysis" -OutputPath "C:\Report.html"
```

**Parameters:**

- `InputPath`: Directory containing analysis data
- `OutputPath`: Path for HTML report file

**Returns:**

- Interactive HTML report
- Charts, tables, and visualizations

### New-ForensicTimelineVisualization

Generates an interactive timeline visualization of forensic events.

```powershell
New-ForensicTimelineVisualization -InputPath "C:\Analysis\Timeline.json" -OutputPath "C:\TimelineReport.html"
```

**Parameters:**

- `InputPath`: Path to timeline JSON data
- `OutputPath`: Path for timeline HTML file

**Returns:**

- Interactive timeline visualization
- Event filtering and navigation

### New-EvidenceCorrelationDashboard

Creates an evidence correlation dashboard showing relationships between evidence types.

```powershell
New-EvidenceCorrelationDashboard -InputPath "C:\Analysis\EvidenceCorrelation.json" -OutputPath "C:\CorrelationDashboard.html"
```

**Parameters:**

- `InputPath`: Path to correlation data
- `OutputPath`: Path for dashboard HTML file

**Returns:**

- Evidence correlation dashboard
- Interactive relationship graphs

### Export-ForensicReport

Exports comprehensive forensic reports in multiple formats.

```powershell
Export-ForensicReport -InputPath "C:\Analysis" -OutputPath "C:\ForensicReport.zip"
```

**Parameters:**

- `InputPath`: Directory containing analysis data
- `OutputPath`: Path for exported report package
- `Formats`: Export formats (JSON, CSV, HTML, PDF)

**Returns:**

- Multi-format report package
- Compressed archive with all findings