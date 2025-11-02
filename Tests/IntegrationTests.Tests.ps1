# IntegrationTests.Tests.ps1
# Integration tests for cross-module functionality

Describe "Integration Tests - Cross-Module Functionality" {

    BeforeAll {
        # Import all required modules
        . "$PSScriptRoot\..\Scripts\Modules\CoreSystem.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\EventLog.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\Registry.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\StaticAnalysis.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\SystemAnalysis.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\FileSystem.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\EvidenceCollection-Core.ps1"

        # Create test directory
        $testDir = Join-Path $TestDrive "IntegrationTest"
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    }

    Context "System Analysis Integration" {

        It "Should integrate system info with analysis results" {
            # Test that system analysis uses system info functions
            $analysis = Invoke-SystemAnalysis

            $analysis | Should -Not -BeNull
            $analysis.PSObject.Properties.Name | Should -Contain "Timestamp"
        }
    }

    Context "File Analysis Integration" {

        It "Should integrate file hashing with static analysis" {
            # Create test file
            $testFile = Join-Path $testDir "test_integration.exe"
            "MZ test executable content" | Out-File $testFile -Encoding ASCII

            # Test file hashing
            $hashes = Get-FileHashes -Path $testFile
            $hashes | Should -Not -BeNull
            $hashes.Hash | Should -Not -BeNull
        }
    }
}