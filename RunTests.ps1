# RunTests.ps1 - Test runner for Forensics Toolkit

param(
    [switch]$EnableExit,
    [string]$OutputPath = ".\test-results",
    [string]$TestPath = ".\Tests"
)

# Ensure Pester 5+ is available
$pesterVersion = (Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
if ($pesterVersion -lt [version]"5.0.0") {
    Write-Error "Pester 5.0 or higher is required. Current version: $pesterVersion"
    if ($EnableExit) { exit 1 }
    return
}

# Import Pester
Import-Module Pester -MinimumVersion 5.0.0

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Configure Pester
$config = New-PesterConfiguration
$config.Run.Path = $TestPath
$config.Run.PassThru = $true
$config.Output.Verbosity = "Detailed"
$config.TestResult.Enabled = $true
$config.TestResult.OutputPath = Join-Path $OutputPath "test-results.xml"
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = ".\Scripts\Modules\*.ps1"
$config.CodeCoverage.OutputPath = Join-Path $OutputPath "coverage.xml"

# Run tests
$result = Invoke-Pester -Configuration $config

# Output summary
Write-Host "`nTest Summary:" -ForegroundColor Cyan
Write-Host "Passed: $($result.PassedCount)" -ForegroundColor Green
Write-Host "Failed: $($result.FailedCount)" -ForegroundColor Red
Write-Host "Skipped: $($result.SkippedCount)" -ForegroundColor Yellow
Write-Host "Total: $($result.TotalCount)" -ForegroundColor White

if ($result.FailedCount -gt 0) {
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    $result.Failed | ForEach-Object {
        Write-Host "- $($_.Name)" -ForegroundColor Red
    }
}

# Exit with appropriate code
if ($EnableExit) {
    exit $result.FailedCount
}