# Test Runner for Forensics Tools Testing Framework
# This script executes all tests and generates reports

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Unit', 'Integration', 'Performance', 'All')]
    [string]$TestType = 'Unit',

    [Parameter(Mandatory = $false)]
    [string[]]$Tags,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeTags,

    [Parameter(Mandatory = $false)]
    [switch]$EnableCoverage,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "TestResults",

    [Parameter(Mandatory = $false)]
    [switch]$CI
)

#Requires -Modules Pester

# Set error action preference
$ErrorActionPreference = 'Stop'

# Import test utilities
. "$PSScriptRoot/Utilities/TestUtilities.ps1"

# Import test configuration
$config = & "$PSScriptRoot/PesterConfiguration.ps1"

# Apply command-line overrides
if ($TestType -ne 'All') {
    # Filter paths based on test type
    switch ($TestType) {
        'Unit' {
            $config.Run.Path = @("$PSScriptRoot/Unit/*.Tests.ps1")
            $config.Filter.ExcludeTag = @('Slow', 'Integration', 'Performance')
        }
        'Integration' {
            $config.Run.Path = @("$PSScriptRoot/Integration/*.Tests.ps1")
            $config.Filter.ExcludeTag = @('Slow', 'Performance')
        }
        'Performance' {
            $config.Run.Path = @("$PSScriptRoot/Performance/*.Tests.ps1")
            $config.Filter.ExcludeTag = @('Integration')
        }
    }
}

if ($Tags) {
    $config.Filter.Tag = $Tags
}

if ($ExcludeTags) {
    $config.Filter.ExcludeTag = $ExcludeTags
}

if (-not $EnableCoverage) {
    $config.CodeCoverage.Enabled = $false
}

# Override output path if specified
if ($OutputPath) {
    $fullOutputPath = Join-Path $PSScriptRoot $OutputPath
    $config.TestResult.OutputPath = "$fullOutputPath.xml"
    if ($config.CodeCoverage.Enabled) {
        $config.CodeCoverage.OutputPath = "$fullOutputPath.Coverage.xml"
    }
}
# Create output directory if it doesn't exist
# Note: Output paths are now absolute, so directory creation is handled by Pester

# Display test execution information
Write-Host "=== Forensics Tools Test Runner ===" -ForegroundColor Cyan
Write-Host "Test Type: $TestType" -ForegroundColor Yellow
Write-Host "Test Paths: $($config.Run.Path -join ', ')" -ForegroundColor Yellow
Write-Host "Tags: $($config.Filter.Tag -join ', ')" -ForegroundColor Yellow
Write-Host "Exclude Tags: $($config.Filter.ExcludeTag -join ', ')" -ForegroundColor Yellow
Write-Host "Code Coverage: $($config.CodeCoverage.Enabled)" -ForegroundColor Yellow
Write-Host "Output: $($config.TestResult.OutputPath)" -ForegroundColor Yellow
if ($config.CodeCoverage.Enabled) {
    Write-Host "Coverage Output: $($config.CodeCoverage.OutputPath)" -ForegroundColor Yellow
}
Write-Host ""

try {
    # Execute tests
    $testResults = Invoke-Pester -Configuration $config

    # Display results summary
    Write-Host "=== Test Results Summary ===" -ForegroundColor Green
    Write-Host "Tests Run: $($testResults.TotalCount)" -ForegroundColor White
    Write-Host "Passed: $($testResults.PassedCount)" -ForegroundColor Green
    Write-Host "Failed: $($testResults.FailedCount)" -ForegroundColor Red
    Write-Host "Skipped: $($testResults.SkippedCount)" -ForegroundColor Yellow
    Write-Host "Inconclusive: $($testResults.InconclusiveCount)" -ForegroundColor Gray

    if ($testResults.CodeCoverage) {
        Write-Host ""
        Write-Host "=== Code Coverage Summary ===" -ForegroundColor Green
        $coverage = $testResults.CodeCoverage
        Write-Host "Coverage Report: $($coverage.CoverageReport)" -ForegroundColor White
        Write-Host "Coverage Percentage: $($coverage.CoveragePercent)%" -ForegroundColor White
        Write-Host "Commands Analyzed: $($coverage.CommandsAnalyzedCount)" -ForegroundColor White
        Write-Host "Commands Executed: $($coverage.CommandsExecutedCount)" -ForegroundColor White
        Write-Host "Commands Missed: $($coverage.CommandsMissedCount)" -ForegroundColor White

        if ($coverage.CoveragePercent -lt $config.CodeCoverage.CoveragePercentTarget) {
            Write-Warning "Code coverage ($($coverage.CoveragePercent)%) is below target ($($config.CodeCoverage.CoveragePercentTarget)%)"
        }
    }

    # Display failed tests if any
    if ($testResults.FailedCount -gt 0) {
        Write-Host ""
        Write-Host "=== Failed Tests ===" -ForegroundColor Red
        foreach ($failedTest in $testResults.Failed) {
            Write-Host "FAILED: $($failedTest.Block) > $($failedTest.Name)" -ForegroundColor Red
            Write-Host "  Error: $($failedTest.ErrorRecord.Exception.Message)" -ForegroundColor Red
            Write-Host ""
        }
    }

    # Set exit code for CI/CD
    if ($CI) {
        if ($testResults.FailedCount -gt 0) {
            exit 1
        }
        else {
            exit 0
        }
    }

}
catch {
    Write-Error "Test execution failed: $_"
    if ($CI) {
        exit 1
    }
}
finally {
    # Clean up test environment
    Clear-TestEnvironment
}