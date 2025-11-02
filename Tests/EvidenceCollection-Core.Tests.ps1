# EvidenceCollection-Core.Tests.ps1 - Tests for EvidenceCollection-Core module

Describe "Collect-SystemEvidence" {
    BeforeAll {
        # Import the module
        $modulePath = Join-Path $PSScriptRoot "..\Scripts\Modules\EvidenceCollection-Core.ps1"
        . $modulePath

        # Create a temporary output directory for tests
        $testOutputPath = Join-Path $TestDrive "TestEvidence"
    }

    It "Should accept required OutputPath parameter" {
        # Test parameter validation without executing the function
        $params = @{
            OutputPath = $testOutputPath
        }
        { Collect-SystemEvidence @params } | Should -Not -Throw
    }

    It "Should accept IncludeMemory parameter" {
        $params = @{
            OutputPath    = $testOutputPath
            IncludeMemory = $false
        }
        { Collect-SystemEvidence @params } | Should -Not -Throw
    }

    It "Should accept IncludeNetwork parameter" {
        $params = @{
            OutputPath     = $testOutputPath
            IncludeNetwork = $false
        }
        { Collect-SystemEvidence @params } | Should -Not -Throw
    }

    It "Should accept IncludeFiles parameter" {
        $params = @{
            OutputPath   = $testOutputPath
            IncludeFiles = $false
        }
        { Collect-SystemEvidence @params } | Should -Not -Throw
    }

    It "Should require OutputPath parameter" {
        # Test that calling without parameters throws an error
        { Collect-SystemEvidence } | Should -Throw
    }
}