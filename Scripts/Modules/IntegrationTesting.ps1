# IntegrationTesting.ps1
# Integration testing functions for forensic workflows

<#
.SYNOPSIS
    Integration Testing Functions

.DESCRIPTION
    This module provides integration testing capabilities for forensic workflows:
    - Invoke-ForensicIntegrationTest: Tests complete forensic workflows and module interactions

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Dependencies: TestingClasses.ps1, UnitTesting.ps1
#>

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
                }
                else {
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