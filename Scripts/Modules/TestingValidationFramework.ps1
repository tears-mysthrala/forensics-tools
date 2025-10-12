# TestingValidationFrameworkFunctions.ps1
# Testing and validation framework for forensic functions

<#
.SYNOPSIS
    Testing and Validation Framework Functions

.DESCRIPTION
    This module provides comprehensive testing and validation capabilities including:
    - Unit testing for individual functions
    - Integration testing for module interactions
    - Performance benchmarking and validation
    - Automated test execution and reporting

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

# Test Framework Classes and Types

class ForensicTestResult {
    [string]$TestName
    [string]$FunctionName
    [bool]$Passed
    [string]$ErrorMessage
    [TimeSpan]$ExecutionTime
    [DateTime]$Timestamp
    [hashtable]$TestData
    [hashtable]$ExpectedResults
    [hashtable]$ActualResults

    ForensicTestResult([string]$testName, [string]$functionName) {
        $this.TestName = $testName
        $this.FunctionName = $functionName
        $this.Timestamp = Get-Date
        $this.TestData = @{}
        $this.ExpectedResults = @{}
        $this.ActualResults = @{}
    }
}

class ForensicTestSuite {
    [string]$SuiteName
    [System.Collections.Generic.List[ForensicTestResult]]$TestResults
    [int]$TotalTests
    [int]$PassedTests
    [int]$FailedTests
    [TimeSpan]$TotalExecutionTime
    [DateTime]$StartTime
    [DateTime]$EndTime

    ForensicTestSuite([string]$suiteName) {
        $this.SuiteName = $suiteName
        $this.TestResults = New-Object System.Collections.Generic.List[ForensicTestResult]
        $this.TotalTests = 0
        $this.PassedTests = 0
        $this.FailedTests = 0
        $this.StartTime = Get-Date
    }

    [void]AddTestResult([ForensicTestResult]$result) {
        $this.TestResults.Add($result)
        $this.TotalTests++
        if ($result.Passed) {
            $this.PassedTests++
        } else {
            $this.FailedTests++
        }
    }

    [void]Complete() {
        $this.EndTime = Get-Date
        $this.TotalExecutionTime = $this.EndTime - $this.StartTime
    }

    [double]GetPassRate() {
        if ($this.TotalTests -eq 0) { return 0 }
        return [math]::Round(($this.PassedTests / $this.TotalTests) * 100, 2)
    }
}

# Unit Testing Functions

function Invoke-ForensicFunctionTest {
    <#
    .SYNOPSIS
        Runs unit tests for forensic functions

    .DESCRIPTION
        Executes comprehensive unit tests for specified forensic functions with mock data and validation

    .PARAMETER FunctionName
        Name of the function to test

    .PARAMETER TestCases
        Array of test case hashtables with input parameters and expected results

    .PARAMETER MockData
        Mock data to use for testing instead of real system calls

    .EXAMPLE
        $testCases = @(
            @{Input = @{Path = "C:\Test"}; Expected = @{Count = 5}}
        )
        Invoke-ForensicFunctionTest -FunctionName "Get-FileHashes" -TestCases $testCases
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionName,

        [Parameter(Mandatory = $true)]
        [array]$TestCases,

        [Parameter(Mandatory = $false)]
        [hashtable]$MockData = @{}
    )

    try {
        Write-Host "Running unit tests for function: $FunctionName..." -ForegroundColor Cyan

        $testSuite = [ForensicTestSuite]::new("$FunctionName Unit Tests")

        foreach ($testCase in $TestCases) {
            $testResult = [ForensicTestResult]::new("$FunctionName Test $($testCase.TestName)", $FunctionName)
            $startTime = Get-Date

            try {
                # Prepare test parameters
                $params = @{}
                if ($testCase.ContainsKey('Input')) {
                    $params = $testCase.Input.Clone()
                }

                # Add mock data if provided
                foreach ($key in $MockData.Keys) {
                    if (-not $params.ContainsKey($key)) {
                        $params[$key] = $MockData[$key]
                    }
                }

                # Execute the function
                $result = & $FunctionName @params

                # Validate results
                $testResult.ActualResults = $result
                $testResult.ExpectedResults = $testCase.Expected

                $passed = $true
                if ($testCase.ContainsKey('Expected')) {
                    $passed = Test-ResultValidation -Actual $result -Expected $testCase.Expected
                }

                $testResult.Passed = $passed
                if (-not $passed) {
                    $testResult.ErrorMessage = "Test validation failed"
                }

            }
            catch {
                $testResult.Passed = $false
                $testResult.ErrorMessage = $_.Exception.Message
            }

            $testResult.ExecutionTime = (Get-Date) - $startTime
            $testResult.TestData = $testCase

            $testSuite.AddTestResult($testResult)
        }

        $testSuite.Complete()

        Write-Host "Unit tests completed for $FunctionName" -ForegroundColor Green
        Write-Host "Results: $($testSuite.PassedTests)/$($testSuite.TotalTests) tests passed ($($testSuite.GetPassRate())%)" -ForegroundColor $(if ($testSuite.FailedTests -eq 0) { "Green" } else { "Yellow" })

        return $testSuite
    }
    catch {
        Write-Error "Failed to run unit tests for $FunctionName : $($_.Exception.Message)"
        return $null
    }
}

function Test-ResultValidation {
    <#
    .SYNOPSIS
        Validates test results against expected outcomes

    .DESCRIPTION
        Compares actual test results with expected results using various validation methods

    .PARAMETER Actual
        Actual result from function execution

    .PARAMETER Expected
        Expected result specification

    .EXAMPLE
        Test-ResultValidation -Actual $result -Expected @{Count = 5; Type = "HashTable"}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Actual,

        [Parameter(Mandatory = $true)]
        [hashtable]$Expected
    )

    try {
        foreach ($key in $Expected.Keys) {
            $expectedValue = $Expected[$key]
            $actualValue = $Actual.$key

            switch ($key) {
                "Count" {
                    if ($Actual.Count -ne $expectedValue) { return $false }
                }
                "Type" {
                    if ($Actual.GetType().Name -ne $expectedValue) { return $false }
                }
                "NotNull" {
                    if ($expectedValue -and $null -eq $actualValue) { return $false }
                }
                "Contains" {
                    if ($expectedValue -and $actualValue -notcontains $expectedValue) { return $false }
                }
                "GreaterThan" {
                    if ($actualValue -le $expectedValue) { return $false }
                }
                "LessThan" {
                    if ($actualValue -ge $expectedValue) { return $false }
                }
                default {
                    if ($actualValue -ne $expectedValue) { return $false }
                }
            }
        }

        return $true
    }
    catch {
        return $false
    }
}

# Integration Testing Functions

function Invoke-ForensicIntegrationTest {
    <#
    .SYNOPSIS
        Runs integration tests for forensic workflows

    .DESCRIPTION
        Tests complete forensic workflows and module interactions

    .PARAMETER WorkflowName
        Name of the workflow to test

    .PARAMETER Steps
        Array of workflow steps with function calls and validations

    .EXAMPLE
        $steps = @(
            @{Function = "Get-FileHashes"; Params = @{Path = "C:\Test"}; Validate = @{NotNull = $true}},
            @{Function = "Export-DataToExternalFormat"; Params = @{Data = "PREV_RESULT"; Format = "CSV"}; Validate = @{Type = "Boolean"}}
        )
        Invoke-ForensicIntegrationTest -WorkflowName "File Analysis Workflow" -Steps $steps
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkflowName,

        [Parameter(Mandatory = $true)]
        [array]$Steps
    )

    try {
        Write-Host "Running integration test: $WorkflowName..." -ForegroundColor Cyan

        $testSuite = [ForensicTestSuite]::new("$WorkflowName Integration Test")
        $previousResult = $null

        foreach ($step in $Steps) {
            $testResult = [ForensicTestResult]::new("$WorkflowName - $($step.Function)", $step.Function)
            $startTime = Get-Date

            try {
                # Prepare parameters
                $params = @{}
                if ($step.ContainsKey('Params')) {
                    $params = $step.Params.Clone()
                }

                # Replace PREV_RESULT placeholder with previous step result
                foreach ($key in $params.Keys) {
                    if ($params[$key] -eq "PREV_RESULT") {
                        $params[$key] = $previousResult
                    }
                }

                # Execute the function
                $result = & $step.Function @params
                $previousResult = $result

                # Validate results
                $testResult.ActualResults = $result
                if ($step.ContainsKey('Validate')) {
                    $testResult.ExpectedResults = $step.Validate
                    $testResult.Passed = Test-ResultValidation -Actual $result -Expected $step.Validate
                } else {
                    $testResult.Passed = $true
                }

                if (-not $testResult.Passed) {
                    $testResult.ErrorMessage = "Integration step validation failed"
                }

            }
            catch {
                $testResult.Passed = $false
                $testResult.ErrorMessage = $_.Exception.Message
                break  # Stop workflow on first failure
            }

            $testResult.ExecutionTime = (Get-Date) - $startTime
            $testResult.TestData = $step

            $testSuite.AddTestResult($testResult)

            if (-not $testResult.Passed) {
                break
            }
        }

        $testSuite.Complete()

        Write-Host "Integration test completed for $WorkflowName" -ForegroundColor Green
        Write-Host "Results: $($testSuite.PassedTests)/$($testSuite.TotalTests) steps passed ($($testSuite.GetPassRate())%)" -ForegroundColor $(if ($testSuite.FailedTests -eq 0) { "Green" } else { "Yellow" })

        return $testSuite
    }
    catch {
        Write-Error "Failed to run integration test for $WorkflowName : $($_.Exception.Message)"
        return $null
    }
}

# Performance Testing Functions

function Invoke-PerformanceBenchmark {
    <#
    .SYNOPSIS
        Runs performance benchmarks for forensic functions

    .DESCRIPTION
        Measures execution time and resource usage for forensic functions under various conditions

    .PARAMETER FunctionName
        Name of the function to benchmark

    .PARAMETER TestCases
        Array of test cases with different input sizes/scenarios

    .PARAMETER Iterations
        Number of iterations to run for each test case

    .PARAMETER MeasureMemory
        Whether to measure memory usage during execution

    .EXAMPLE
        $testCases = @(
            @{Name = "Small"; Params = @{Path = "C:\SmallDir"}},
            @{Name = "Large"; Params = @{Path = "C:\LargeDir"}}
        )
        Invoke-PerformanceBenchmark -FunctionName "Get-FileHashes" -TestCases $testCases -Iterations 3
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionName,

        [Parameter(Mandatory = $true)]
        [array]$TestCases,

        [Parameter(Mandatory = $false)]
        [int]$Iterations = 1,

        [Parameter(Mandatory = $false)]
        [switch]$MeasureMemory
    )

    try {
        Write-Host "Running performance benchmark for $FunctionName..." -ForegroundColor Cyan

        $benchmarkResults = @()

        foreach ($testCase in $TestCases) {
            Write-Host "Testing scenario: $($testCase.Name)..." -ForegroundColor Gray

            $scenarioResults = @{
                Scenario = $testCase.Name
                Iterations = $Iterations
                ExecutionTimes = @()
                MemoryUsage = @()
                AverageTime = $null
                MinTime = $null
                MaxTime = $null
                AverageMemoryMB = $null
            }

            for ($i = 1; $i -le $Iterations; $i++) {
                Write-Host "  Iteration $i/$Iterations..." -ForegroundColor Gray

                # Measure memory before execution
                $memoryBefore = $null
                if ($MeasureMemory) {
                    $memoryBefore = (Get-Process -Id $PID).WorkingSet64 / 1MB
                }

                $startTime = Get-Date

                try {
                    # Execute function with test parameters
                    $params = if ($testCase.ContainsKey('Params')) { $testCase.Params } else { @{} }
                    $result = & $FunctionName @params

                    $executionTime = (Get-Date) - $startTime
                    $scenarioResults.ExecutionTimes += $executionTime

                    # Measure memory after execution
                    if ($MeasureMemory) {
                        $memoryAfter = (Get-Process -Id $PID).WorkingSet64 / 1MB
                        $memoryDelta = $memoryAfter - $memoryBefore
                        $scenarioResults.MemoryUsage += $memoryDelta
                    }

                }
                catch {
                    Write-Warning "Iteration $i failed: $($_.Exception.Message)"
                    $scenarioResults.ExecutionTimes += [TimeSpan]::Zero
                    if ($MeasureMemory) {
                        $scenarioResults.MemoryUsage += 0
                    }
                }

                # Small delay between iterations
                Start-Sleep -Milliseconds 100
            }

            # Calculate statistics
            if ($scenarioResults.ExecutionTimes.Count -gt 0) {
                $avgTicks = $scenarioResults.ExecutionTimes | ForEach-Object { $_.Ticks } | Measure-Object -Average | Select-Object -ExpandProperty Average
                $scenarioResults.AverageTime = [TimeSpan]::FromTicks([math]::Round($avgTicks))
                $scenarioResults.MinTime = $scenarioResults.ExecutionTimes | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum
                $scenarioResults.MaxTime = $scenarioResults.ExecutionTimes | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
            }

            if ($MeasureMemory -and $scenarioResults.MemoryUsage.Count -gt 0) {
                $scenarioResults.AverageMemoryMB = [math]::Round(($scenarioResults.MemoryUsage | Measure-Object -Average | Select-Object -ExpandProperty Average), 2)
            }

            $benchmarkResults += [PSCustomObject]$scenarioResults
        }

        Write-Host "Performance benchmark completed for $FunctionName" -ForegroundColor Green

        return [PSCustomObject]@{
            FunctionName = $FunctionName
            Timestamp = Get-Date
            BenchmarkResults = $benchmarkResults
        }
    }
    catch {
        Write-Error "Failed to run performance benchmark for $FunctionName : $($_.Exception.Message)"
        return $null
    }
}

# Test Reporting Functions

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
                    SuiteName = $TestSuite.SuiteName
                    StartTime = $TestSuite.StartTime
                    EndTime = $TestSuite.EndTime
                    TotalExecutionTime = $TestSuite.TotalExecutionTime.ToString()
                    TotalTests = $TestSuite.TotalTests
                    PassedTests = $TestSuite.PassedTests
                    FailedTests = $TestSuite.FailedTests
                    PassRate = $TestSuite.GetPassRate()
                    TestResults = @()
                }

                foreach ($result in $TestSuite.TestResults) {
                    $jsonData.TestResults += @{
                        TestName = $result.TestName
                        FunctionName = $result.FunctionName
                        Passed = $result.Passed
                        ErrorMessage = $result.ErrorMessage
                        ExecutionTime = $result.ExecutionTime.ToString()
                        Timestamp = $result.Timestamp
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
                        SuiteName = $TestSuite.SuiteName
                        TestName = $result.TestName
                        FunctionName = $result.FunctionName
                        Passed = $result.Passed
                        ErrorMessage = $result.ErrorMessage
                        ExecutionTime = $result.ExecutionTime.ToString()
                        Timestamp = $result.Timestamp
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

# Automated Test Runner Functions

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
            UnitTests = @()
            IntegrationTests = @()
            PerformanceTests = @()
            TotalTests = 0
            PassedTests = 0
            FailedTests = 0
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
                    Input = @{}
                    Expected = @{NotNull = $true}
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
                Name = "Basic File Analysis"
                Steps = @(
                    @{Function = "Get-SystemInfo"; Params = @{}; Validate = @{NotNull = $true}}
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
                @{Function = "Get-SystemInfo"; TestCases = @(@{Name = "Basic"; Params = @{}})}
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
            TestSuiteName = "Forensic Functions Comprehensive Test Suite"
            StartTime = $startTime
            EndTime = $endTime
            TotalDuration = $totalDuration.ToString()
            TotalTests = $overallResults.TotalTests
            PassedTests = $overallResults.PassedTests
            FailedTests = $overallResults.FailedTests
            PassRate = if ($overallResults.TotalTests -gt 0) { [math]::Round(($overallResults.PassedTests / $overallResults.TotalTests) * 100, 2) } else { 0 }
            UnitTestSuites = $overallResults.UnitTests.Count
            IntegrationTestSuites = $overallResults.IntegrationTests.Count
            PerformanceTests = $overallResults.PerformanceTests.Count
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