# TestReporting.ps1
# Test reporting and automated test runner functions

<#
.SYNOPSIS
    Test Reporting Functions

.DESCRIPTION
    This module provides test reporting and automated test execution capabilities:
    - Export-TestResults: Exports test results to various formats (HTML, JSON, CSV)
    - Invoke-ForensicTestSuite: Runs comprehensive test suites for forensic functions

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Dependencies: TestingClasses.ps1, UnitTesting.ps1, IntegrationTesting.ps1, PerformanceTesting.ps1
#>

function Export-TestResults {
    <#
    .SYNOPSIS
        Exports test results to various formats

    .DESCRIPTION
        Generates comprehensive test reports in HTML, JSON, or CSV formats

    .PARAMETER TestSuite
        Test suite results to export

    .PARAMETER Format
        Export format (HTML, JSON, CSV)

    .PARAMETER OutputPath
        Path for the exported report

    .PARAMETER IncludeDetails
        Whether to include detailed test data in the report

    .EXAMPLE
        Export-TestResults -TestSuite $results -Format HTML -OutputPath "test-report.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$TestSuite,

        [Parameter(Mandatory = $true)]
        [ValidateSet("HTML", "JSON", "CSV")]
        [string]$Format,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails
    )

    try {
        Write-Host "Exporting test results to $Format format..." -ForegroundColor Cyan

        switch ($Format) {
            "HTML" {
                $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Test Report - $($TestSuite.SuiteName)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { display: flex; gap: 20px; margin-bottom: 20px; }
        .metric { background-color: #e8f4f8; padding: 10px; border-radius: 5px; text-align: center; }
        .passed { color: #28a745; }
        .failed { color: #dc3545; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .test-passed { background-color: #d4edda; }
        .test-failed { background-color: #f8d7da; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Forensic Test Report</h1>
        <h2>$($TestSuite.SuiteName)</h2>
        <p>Generated: $($TestSuite.EndTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p>Execution Time: $($TestSuite.TotalExecutionTime.ToString())</p>
    </div>

    <div class="summary">
        <div class="metric">
            <h3>Total Tests</h3>
            <div style="font-size: 24px;">$($TestSuite.TotalTests)</div>
        </div>
        <div class="metric passed">
            <h3>Passed</h3>
            <div style="font-size: 24px;">$($TestSuite.PassedTests)</div>
        </div>
        <div class="metric failed">
            <h3>Failed</h3>
            <div style="font-size: 24px;">$($TestSuite.FailedTests)</div>
        </div>
        <div class="metric">
            <h3>Pass Rate</h3>
            <div style="font-size: 24px;">$($TestSuite.GetPassRate())%</div>
        </div>
    </div>

    <h3>Test Results</h3>
    <table>
        <tr>
            <th>Test Name</th>
            <th>Function</th>
            <th>Status</th>
            <th>Execution Time</th>
            <th>Error Message</th>
        </tr>
"@

                foreach ($result in $TestSuite.TestResults) {
                    $statusClass = if ($result.Passed) { "test-passed" } else { "test-failed" }
                    $status = if ($result.Passed) { "PASSED" } else { "FAILED" }

                    $html += @"
        <tr class="$statusClass">
            <td>$($result.TestName)</td>
            <td>$($result.FunctionName)</td>
            <td>$status</td>
            <td>$($result.ExecutionTime.ToString())</td>
            <td>$($result.ErrorMessage)</td>
        </tr>
"@
                }

                $html += @"
    </table>
</body>
</html>
"@

                $html | Out-File $OutputPath -Encoding UTF8
            }

            "JSON" {
                $jsonData = @{
                    SuiteName          = $TestSuite.SuiteName
                    StartTime          = $TestSuite.StartTime
                    EndTime            = $TestSuite.EndTime
                    TotalExecutionTime = $TestSuite.TotalExecutionTime.ToString()
                    TotalTests         = $TestSuite.TotalTests
                    PassedTests        = $TestSuite.PassedTests
                    FailedTests        = $TestSuite.FailedTests
                    PassRate           = $TestSuite.GetPassRate()
                    TestResults        = @()
                }

                foreach ($result in $TestSuite.TestResults) {
                    $jsonData.TestResults += @{
                        TestName      = $result.TestName
                        FunctionName  = $result.FunctionName
                        Passed        = $result.Passed
                        ErrorMessage  = $result.ErrorMessage
                        ExecutionTime = $result.ExecutionTime.ToString()
                        Timestamp     = $result.Timestamp
                    }

                    if ($IncludeDetails) {
                        $jsonData.TestResults[-1].TestData = $result.TestData
                        $jsonData.TestResults[-1].ExpectedResults = $result.ExpectedResults
                        $jsonData.TestResults[-1].ActualResults = $result.ActualResults
                    }
                }

                $jsonData | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
            }

            "CSV" {
                $csvData = @()

                foreach ($result in $TestSuite.TestResults) {
                    $csvData += [PSCustomObject]@{
                        SuiteName     = $TestSuite.SuiteName
                        TestName      = $result.TestName
                        FunctionName  = $result.FunctionName
                        Passed        = $result.Passed
                        ErrorMessage  = $result.ErrorMessage
                        ExecutionTime = $result.ExecutionTime.ToString()
                        Timestamp     = $result.Timestamp
                    }
                }

                $csvData | Export-Csv -Path $OutputPath -NoTypeInformation
            }
        }

        Write-Host "Test results exported to $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to export test results: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-ForensicTestSuite {
    <#
    .SYNOPSIS
        Runs a complete test suite for forensic functions

    .DESCRIPTION
        Executes unit tests, integration tests, and performance benchmarks for all forensic functions

    .PARAMETER IncludePerformanceTests
        Whether to include performance benchmarking

    .PARAMETER OutputPath
        Base path for test reports

    .PARAMETER VerboseOutput
        Enable verbose test output

    .EXAMPLE
        Invoke-ForensicTestSuite -IncludePerformanceTests -OutputPath "TestResults"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformanceTests,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "TestResults",

        [Parameter(Mandatory = $false)]
        [switch]$VerboseOutput
    )

    try {
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath | Out-Null
        }

        Write-Host "Starting comprehensive forensic test suite..." -ForegroundColor Cyan
        $startTime = Get-Date

        $overallResults = @{
            UnitTests        = @()
            IntegrationTests = @()
            PerformanceTests = @()
            TotalTests       = 0
            PassedTests      = 0
            FailedTests      = 0
        }

        # Get available forensic functions
        $forensicFunctions = Get-Command -CommandType Function | Where-Object {
            $_.Name -match "^(Get-|Invoke-|Collect-|Search-|Export-)" -and
            $_.Source -match "ForensicFunctions|Modules"
        }

        Write-Host "Found $($forensicFunctions.Count) forensic functions to test" -ForegroundColor Gray

        # Run unit tests for each function
        Write-Host "`n=== RUNNING UNIT TESTS ===" -ForegroundColor Yellow
        foreach ($function in $forensicFunctions) {
            if ($VerboseOutput) {
                Write-Host "Testing function: $($function.Name)" -ForegroundColor Gray
            }

            # Create basic test cases (this would be expanded with real test data)
            $testCases = @(
                @{
                    TestName = "Basic Functionality"
                    Input    = @{}
                    Expected = @{NotNull = $true }
                }
            )

            $unitResult = Invoke-ForensicFunctionTest -FunctionName $function.Name -TestCases $testCases

            if ($unitResult) {
                $overallResults.UnitTests += $unitResult
                $overallResults.TotalTests += $unitResult.TotalTests
                $overallResults.PassedTests += $unitResult.PassedTests
                $overallResults.FailedTests += $unitResult.FailedTests

                # Export individual function results
                $functionReportPath = Join-Path $OutputPath "$($function.Name)_UnitTests.html"
                Export-TestResults -TestSuite $unitResult -Format HTML -OutputPath $functionReportPath | Out-Null
            }
        }

        # Run integration tests (sample workflows)
        Write-Host "`n=== RUNNING INTEGRATION TESTS ===" -ForegroundColor Yellow

        $integrationWorkflows = @(
            @{
                Name  = "Basic File Analysis"
                Steps = @(
                    @{Function = "Get-SystemInfo"; Params = @{}; Validate = @{NotNull = $true } }
                )
            }
        )

        foreach ($workflow in $integrationWorkflows) {
            $integrationResult = Invoke-ForensicIntegrationTest -WorkflowName $workflow.Name -Steps $workflow.Steps

            if ($integrationResult) {
                $overallResults.IntegrationTests += $integrationResult
                $overallResults.TotalTests += $integrationResult.TotalTests
                $overallResults.PassedTests += $integrationResult.PassedTests
                $overallResults.FailedTests += $integrationResult.FailedTests

                # Export integration test results
                $integrationReportPath = Join-Path $OutputPath "$($workflow.Name -replace ' ', '_')_IntegrationTest.html"
                Export-TestResults -TestSuite $integrationResult -Format HTML -OutputPath $integrationReportPath | Out-Null
            }
        }

        # Run performance tests if requested
        if ($IncludePerformanceTests) {
            Write-Host "`n=== RUNNING PERFORMANCE TESTS ===" -ForegroundColor Yellow

            $performanceTestCases = @(
                @{Function = "Get-SystemInfo"; TestCases = @(@{Name = "Basic"; Params = @{} }) }
            )

            foreach ($perfTest in $performanceTestCases) {
                $perfResult = Invoke-PerformanceBenchmark -FunctionName $perfTest.Function -TestCases $perfTest.TestCases -Iterations 2 -MeasureMemory

                if ($perfResult) {
                    $overallResults.PerformanceTests += $perfResult

                    # Export performance results
                    $perfReportPath = Join-Path $OutputPath "$($perfTest.Function)_Performance.json"
                    $perfResult | ConvertTo-Json -Depth 10 | Out-File $perfReportPath -Encoding UTF8
                }
            }
        }

        # Generate overall summary report
        $endTime = Get-Date
        $totalDuration = $endTime - $startTime

        $summaryReport = [PSCustomObject]@{
            TestSuiteName         = "Forensic Functions Comprehensive Test Suite"
            StartTime             = $startTime
            EndTime               = $endTime
            TotalDuration         = $totalDuration.ToString()
            TotalTests            = $overallResults.TotalTests
            PassedTests           = $overallResults.PassedTests
            FailedTests           = $overallResults.FailedTests
            PassRate              = if ($overallResults.TotalTests -gt 0) { [math]::Round(($overallResults.PassedTests / $overallResults.TotalTests) * 100, 2) } else { 0 }
            UnitTestSuites        = $overallResults.UnitTests.Count
            IntegrationTestSuites = $overallResults.IntegrationTests.Count
            PerformanceTests      = $overallResults.PerformanceTests.Count
        }

        $summaryPath = Join-Path $OutputPath "TestSuite_Summary.json"
        $summaryReport | ConvertTo-Json | Out-File $summaryPath -Encoding UTF8

        $summaryHtmlPath = Join-Path $OutputPath "TestSuite_Summary.html"
        Export-TestResults -TestSuite $summaryReport -Format HTML -OutputPath $summaryHtmlPath | Out-Null

        Write-Host "`n=== TEST SUITE COMPLETED ===" -ForegroundColor Green
        Write-Host "Total Tests: $($overallResults.TotalTests)" -ForegroundColor White
        Write-Host "Passed: $($overallResults.PassedTests)" -ForegroundColor Green
        Write-Host "Failed: $($overallResults.FailedTests)" -ForegroundColor $(if ($overallResults.FailedTests -eq 0) { "Green" } else { "Red" })
        Write-Host "Pass Rate: $($summaryReport.PassRate)%" -ForegroundColor $(if ($summaryReport.PassRate -ge 80) { "Green" } else { "Yellow" })
        Write-Host "Duration: $($totalDuration.ToString())" -ForegroundColor White
        Write-Host "Reports saved to: $OutputPath" -ForegroundColor Cyan

        return $summaryReport
    }
    catch {
        Write-Error "Failed to run test suite: $($_.Exception.Message)"
        return $null
    }
}