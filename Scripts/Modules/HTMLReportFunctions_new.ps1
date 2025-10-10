# HTMLReportFunctions.ps1 - HTML report generation

function New-ForensicHTMLReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisData,
        [string]$OutputPath = ".",
        [string]$Title = "Forensic Analysis Report"
    )

    Write-Host "Creating HTML forensic report..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $OutputPath "ForensicReport_$timestamp.html"

    # Create output directory if it doesn't exist
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Build HTML content
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { background-color: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric { display: inline-block; margin: 10px; padding: 15px; background-color: #3498db; color: white; border-radius: 5px; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>$Title</h1>
        <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
"@

    # Add system information section
    $htmlContent += @"

    <div class="section">
        <h2>System Information</h2>
"@

    $systemInfo = $AnalysisData.SystemInfo
    if ($systemInfo) {
        $htmlContent += @"
        <div class="metric"><strong>OS:</strong> $($systemInfo.OSVersion)</div>
        <div class="metric"><strong>Hostname:</strong> $($systemInfo.Hostname)</div>
        <div class="metric"><strong>User:</strong> $($systemInfo.Username)</div>
"@
    }

    $htmlContent += @"
    </div>

    <div class="section">
        <h2>Analysis Summary</h2>
"@

    # Add analysis summary
    if ($AnalysisData.Summary) {
        $htmlContent += "<p>$($AnalysisData.Summary)</p>"
    }

    $htmlContent += @"
    </div>

    <div class="section">
        <h2>Findings</h2>
"@

    # Add findings table
    if ($AnalysisData.Findings -and $AnalysisData.Findings.Count -gt 0) {
        $htmlContent += @"
        <table>
            <tr><th>Type</th><th>Description</th><th>Severity</th></tr>
"@

        foreach ($finding in $AnalysisData.Findings) {
            $htmlContent += @"
            <tr>
                <td>$($finding.Type)</td>
                <td>$($finding.Description)</td>
                <td>$($finding.Severity)</td>
            </tr>
"@
        }

        $htmlContent += "</table>"
    } else {
        $htmlContent += "<p>No findings to report.</p>"
    }

    $htmlContent += @"
    </div>
</body>
</html>
"@

    # Write the HTML report
    $htmlContent | Out-File $reportFile -Encoding UTF8

    Write-Host "[OK] HTML report created: $reportFile" -ForegroundColor Green

    # Try to open the report in default browser
    try {
        Start-Process $reportFile
        Write-Host "[OK] Report opened in default browser" -ForegroundColor Green
    } catch {
        Write-Host "Note: Could not automatically open report. Please open manually: $reportFile" -ForegroundColor Yellow
    }

    return $reportFile
}