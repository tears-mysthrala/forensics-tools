# TestingClasses.ps1
# Test Framework Classes and Types for forensic testing

<#
.SYNOPSIS
    Testing Framework Classes

.DESCRIPTION
    This module contains the core classes used by the forensic testing framework:
    - ForensicTestResult: Represents individual test results
    - ForensicTestSuite: Manages collections of test results

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

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
        }
        else {
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