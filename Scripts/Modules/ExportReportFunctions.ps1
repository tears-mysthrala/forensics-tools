function Export-ForensicReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisResults,
        [string]$OutputPath = ".",
        [string[]]$Formats = @("JSON", "HTML")
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportDir = Join-Path $OutputPath "ForensicReport_$timestamp"
    
    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    
    if ($Formats -contains "JSON") {
        $jsonFile = Join-Path $reportDir "forensic_report.json"
        $AnalysisResults | ConvertTo-Json -Depth 4 | Out-File $jsonFile
    }
    
    if ($Formats -contains "HTML") {
        $htmlFile = New-ForensicHTMLReport -AnalysisData $AnalysisResults -OutputPath $reportDir -Title "Comprehensive Forensic Report"
    }
    
    return $reportDir
}
