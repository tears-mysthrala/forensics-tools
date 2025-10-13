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
    [string]$OutputPath = "$PSScriptRoot/TestResults",

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

# For Pester 3.4.0 compatibility, convert config to parameters
$pesterParams = @{
    Path         = $config.Run.Path
    ExcludeTag   = $config.Filter.ExcludeTag
    OutputFile   = $config.TestResult.OutputPath
    OutputFormat = $config.TestResult.OutputFormat
    PassThru     = $true
}

if ($Tags) {
    $pesterParams.Tag = $Tags
}

# Note: Code coverage not supported in Pester 3.4.0
if ($EnableCoverage) {
    Write-Warning "Code coverage is not supported in Pester 3.4.0. Install Pester 4.0+ for code coverage features."
}

# Create output directory if it doesn't exist
$outputDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Display test execution information
Write-Host "=== Forensics Tools Test Runner ===" -ForegroundColor Cyan
Write-Host "Test Type: $TestType" -ForegroundColor Yellow
Write-Host "Test Paths: $($config.Run.Path -join ', ')" -ForegroundColor Yellow
Write-Host "Tags: $($config.Filter.Tag -join ', ')" -ForegroundColor Yellow
Write-Host "Exclude Tags: $($config.Filter.ExcludeTag -join ', ')" -ForegroundColor Yellow
Write-Host "Code Coverage: $($config.CodeCoverage.Enabled)" -ForegroundColor Yellow
Write-Host "Output: $OutputPath.xml" -ForegroundColor Yellow
Write-Host ""

try {
    # Execute tests
    $testResults = Invoke-Pester @pesterParams

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
        Write-Host "Coverage Report: $($testResults.CodeCoverage)" -ForegroundColor White
        # Note: Coverage percentage not directly available in Pester 3.4.0 format
    }

    # Display failed tests if any
    if ($testResults.FailedCount -gt 0) {
        Write-Host ""
        Write-Host "=== Failed Tests ===" -ForegroundColor Red
        foreach ($failedTest in $testResults.TestResult) {
            if ($failedTest.Result -eq 'Failed') {
                Write-Host "FAILED: $($failedTest.Describe) > $($failedTest.Context) > $($failedTest.Name)" -ForegroundColor Red
                Write-Host "  Error: $($failedTest.FailureMessage)" -ForegroundColor Red
                Write-Host ""
            }
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