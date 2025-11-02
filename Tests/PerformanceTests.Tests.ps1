# PerformanceTests.Tests.ps1
# Performance benchmarking tests

Describe "Performance Tests - Function Benchmarking" {

    BeforeAll {
        # Import required modules
        . "$PSScriptRoot\..\Scripts\Modules\CoreSystem.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\EventLog.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\Registry.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\StaticAnalysis.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\SystemAnalysis.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\FileSystem.ps1"

        # Create test directory with sample files
        $testDir = Join-Path $TestDrive "PerformanceTest"
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null

        # Create sample files for testing
        1..10 | ForEach-Object {
            $fileName = "testfile$_.txt"
            $filePath = Join-Path $testDir $fileName
            "Sample content for performance testing $_" | Out-File $filePath -Encoding UTF8
        }
    }

    Context "System Analysis Performance" {

        It "Should complete system analysis within reasonable time" {
            $startTime = Get-Date

            $analysis = Invoke-SystemAnalysis

            $endTime = Get-Date
            $duration = $endTime - $startTime

            $analysis | Should -Not -BeNull
            $duration.TotalSeconds | Should -BeLessThan 120  # Should complete within 2 minutes
        }

        It "Should handle repeated system analysis calls efficiently" {
            $runs = 3
            $times = @()

            for ($i = 1; $i -le $runs; $i++) {
                $startTime = Get-Date
                Invoke-SystemAnalysis | Out-Null
                $endTime = Get-Date
                $times += ($endTime - $startTime).TotalSeconds
            }

            $averageTime = ($times | Measure-Object -Average).Average
            $averageTime | Should -BeLessThan 60  # Average should be under 1 minute
        }
    }

    Context "File Analysis Performance" {

        It "Should hash files efficiently" {
            $startTime = Get-Date

            $hashes = Get-FileHashes -Path $testDir

            $endTime = Get-Date
            $duration = $endTime - $startTime

            $hashes | Should -Not -BeNull
            $duration.TotalSeconds | Should -BeLessThan 30  # Should complete within 30 seconds
        }

        It "Should analyze files within performance bounds" {
            $startTime = Get-Date

            $analysis = Get-FileStaticAnalysis -Path $testDir -OutputPath $TestDrive

            $endTime = Get-Date
            $duration = $endTime - $startTime

            $analysis | Should -Not -BeNull
            $duration.TotalSeconds | Should -BeLessThan 60  # Should complete within 1 minute
        }
    }

    Context "Memory Usage Validation" {

        It "Should not consume excessive memory during analysis" {
            $initialMemory = Get-Process -Id $PID | Select-Object -ExpandProperty WorkingSet

            $analysis = Invoke-SystemAnalysis

            $finalMemory = Get-Process -Id $PID | Select-Object -ExpandProperty WorkingSet
            $memoryIncrease = $finalMemory - $initialMemory

            $analysis | Should -Not -BeNull
            $memoryIncrease | Should -BeLessThan 500MB  # Should not increase memory by more than 500MB
        }
    }

    Context "Concurrent Operations" {

        It "Should handle multiple file analysis operations" {
            $jobs = @()

            # Start multiple analysis jobs
            1..3 | ForEach-Object {
                $job = Start-Job -ScriptBlock {
                    param($testDir, $outputDir)
                    . "$using:PSScriptRoot\..\Scripts\Modules\FileSystem.ps1"
                    . "$using:PSScriptRoot\..\Scripts\Modules\StaticAnalysis.ps1"

                    $hashes = Get-FileHashes -Path $testDir
                    return $hashes.Count
                } -ArgumentList $testDir, $TestDrive
                $jobs += $job
            }

            # Wait for all jobs to complete
            $results = $jobs | Wait-Job | Receive-Job

            # Clean up jobs
            $jobs | Remove-Job

            $results | Should -Not -BeNull
            $results.Count | Should -Be 3
            $results | ForEach-Object { $_ | Should -BeGreaterThan 0 }
        }
    }
}