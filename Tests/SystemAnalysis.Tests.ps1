# SystemAnalysis.Tests.ps1
# Unit tests for SystemAnalysis module

Describe "SystemAnalysis Module Tests" {

    BeforeAll {
        # Import dependent modules first
        . "$PSScriptRoot\..\Scripts\Modules\CoreSystem.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\EventLog.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\Registry.ps1"

        # Import the module under test
        . "$PSScriptRoot\..\Scripts\Modules\SystemAnalysis.ps1"
    }

    Context "Invoke-SystemAnalysis Functionality" {

        It "Should execute without parameters" {
            { Invoke-SystemAnalysis } | Should -Not -Throw
        }

        It "Should return analysis results" {
            $result = Invoke-SystemAnalysis
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [PSCustomObject]
        }

        It "Should contain expected properties" {
            $result = Invoke-SystemAnalysis
            $result.PSObject.Properties.Name | Should -Contain "Timestamp"
            $result.PSObject.Properties.Name | Should -Contain "SystemConfiguration"
            $result.PSObject.Properties.Name | Should -Contain "UserAccounts"
            $result.PSObject.Properties.Name | Should -Contain "ScheduledTasks"
            $result.PSObject.Properties.Name | Should -Contain "SystemLogs"
            $result.PSObject.Properties.Name | Should -Contain "RegistryAnalysis"
        }

        It "Should have valid timestamp" {
            $result = Invoke-SystemAnalysis
            $result.Timestamp | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -BeOfType [DateTime]
        }
    }

    Context "SystemAnalysis Result Validation" {

        It "Should attempt to analyze system configuration" {
            # Mock Get-SystemInfo to avoid actual system calls in tests
            Mock Get-SystemInfo { return @{ OS = "Test OS"; Version = "1.0" } }

            $result = Invoke-SystemAnalysis
            $result.SystemConfiguration | Should -Not -BeNullOrEmpty
        }

        It "Should attempt to analyze user accounts" {
            # Mock Get-UserAccounts to avoid actual system calls
            Mock Get-UserAccounts { return @(@{ Name = "TestUser"; SID = "S-1-5-21-123" }) }

            $result = Invoke-SystemAnalysis
            $result.UserAccounts | Should -Not -BeNullOrEmpty
        }

        It "Should attempt to analyze scheduled tasks" {
            # Mock Get-ScheduledTasks to avoid actual system calls
            Mock Get-ScheduledTasks { return @(@{ Name = "TestTask"; State = "Ready" }) }

            $result = Invoke-SystemAnalysis
            $result.ScheduledTasks | Should -Not -BeNullOrEmpty
        }

        It "Should attempt to analyze system logs" {
            # Mock Get-SystemLogsSummary to avoid actual system calls
            Mock Get-SystemLogsSummary { return @{ TotalEvents = 100; ErrorCount = 5 } }

            $result = Invoke-SystemAnalysis
            $result.SystemLogs | Should -Not -BeNullOrEmpty
        }
    }

    Context "Registry Analysis" {

        It "Should attempt registry persistence analysis" {
            # Mock registry functions to avoid actual registry access
            Mock Get-RegistryKeys {
                param($Hive, $Path)
                return @(@{ Key = "TestKey"; Value = "TestValue" })
            }

            $result = Invoke-SystemAnalysis
            $result.RegistryAnalysis | Should -Not -BeNullOrEmpty
            $result.RegistryAnalysis.RunKeys | Should -Not -BeNullOrEmpty
            $result.RegistryAnalysis.RunOnceKeys | Should -Not -BeNullOrEmpty
        }
    }
}