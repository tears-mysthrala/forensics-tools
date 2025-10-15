# PerformanceTesting.ps1
# Performance benchmarking functions for forensic analysis

<#
.SYNOPSIS
    Performance Testing Functions

.DESCRIPTION
    This module provides performance benchmarking capabilities for forensic functions:
    - Invoke-PerformanceBenchmark: Measures execution time and resource usage

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Dependencies: TestingClasses.ps1
#>

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
                Scenario        = $testCase.Name
                Iterations      = $Iterations
                ExecutionTimes  = @()
                MemoryUsage     = @()
                AverageTime     = $null
                MinTime         = $null
                MaxTime         = $null
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
            FunctionName     = $FunctionName
            Timestamp        = Get-Date
            BenchmarkResults = $benchmarkResults
        }
    }
    catch {
        Write-Error "Failed to run performance benchmark for $FunctionName : $($_.Exception.Message)"
        return $null
    }
}