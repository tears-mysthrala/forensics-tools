# UnitTesting.ps1
# Unit testing functions for forensic analysis

<#
.SYNOPSIS
    Unit Testing Functions

.DESCRIPTION
    This module provides unit testing capabilities for forensic functions:
    - Invoke-ForensicFunctionTest: Runs comprehensive unit tests
    - Test-ResultValidation: Validates test results against expectations

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Dependencies: TestingClasses.ps1
#>

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