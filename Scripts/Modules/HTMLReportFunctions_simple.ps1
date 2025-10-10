function New-ForensicHTMLReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisData,
        [string]$OutputPath = ".",
        [string]$Title = "Forensic Analysis Report"
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $OutputPath "ForensicReport_$timestamp.html"

    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$Title</title>
    <style>body{font-family:Arial;margin:20px;} .header{background:#2c3e50;color:white;padding:20px;margin-bottom:20px;}</style>
</head>
<body>
    <div class="header"><h1>$Title</h1><p>Generated: $(Get-Date)</p></div>
    <h2>Analysis Summary</h2>
    <p>$($AnalysisData.Summary)</p>
    <h2>Findings</h2>
    <p>Report generation completed successfully.</p>
</body>
</html>
"@

    $html | Out-File $reportFile -Encoding UTF8
    Write-Host "HTML report created: $reportFile" -ForegroundColor Green

    return $reportFile
}