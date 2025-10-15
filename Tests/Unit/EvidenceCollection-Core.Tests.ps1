# Unit Tests for EvidenceCollection-Core Module
# Tests for Scripts/Modules/EvidenceCollection-Core.ps1 functions

Describe "Collect-SystemEvidence" {

    BeforeAll {
        # Import the module under test
        . "$PSScriptRoot/../../Scripts/Modules/EvidenceCollection-Core.ps1"
    }

    BeforeEach {
        # Create test directory
        $script:testDir = Join-Path $TestDrive "TestEvidence"
        if (Test-Path $script:testDir) {
            Remove-Item $script:testDir -Recurse -Force
        }
    }

    AfterEach {
        # Clean up test directory
        if (Test-Path $script:testDir) {
            Remove-Item $script:testDir -Recurse -Force
        }
    }

    Context "Parameter validation" {

        It "Should require OutputPath parameter" {
            { Collect-SystemEvidence } | Should -Throw
        }

        It "Should accept valid OutputPath" {
            { Collect-SystemEvidence -OutputPath $script:testDir } | Should -Not -Throw
        }
    }

    Context "Evidence collection" {

        It "Should create evidence directory" {
            Collect-SystemEvidence -OutputPath $script:testDir
            $evidenceDirs = Get-ChildItem $script:testDir -Directory -Filter "Evidence_*"
            $evidenceDirs | Should -Not -BeNullOrEmpty
        }

        It "Should create system_info.json file" {
            Collect-SystemEvidence -OutputPath $script:testDir
            $evidenceDir = Get-ChildItem $script:testDir -Directory -Filter "Evidence_*" | Select-Object -First 1
            $systemInfoFile = Join-Path $evidenceDir.FullName "system_info.json"
            Test-Path $systemInfoFile | Should -Be $true
        }

        It "Should handle IncludeMemory parameter" {
            { Collect-SystemEvidence -OutputPath $script:testDir -IncludeMemory $false } | Should -Not -Throw
        }

        It "Should handle IncludeNetwork parameter" {
            { Collect-SystemEvidence -OutputPath $script:testDir -IncludeNetwork $false } | Should -Not -Throw
        }

        It "Should handle IncludeFiles parameter" {
            { Collect-SystemEvidence -OutputPath $script:testDir -IncludeFiles $false } | Should -Not -Throw
        }
    }
}

Describe "Invoke-LiveForensics" {

    BeforeAll {
        . "$PSScriptRoot/../../Scripts/Modules/EvidenceCollection-Core.ps1"
    }

    Context "Parameter validation" {

        It "Should have appropriate parameters" {
            $command = Get-Command Invoke-LiveForensics
            $command | Should -Not -BeNullOrEmpty
        }
    }

    Context "Execution" {

        It "Should not throw when executed" {
            { Invoke-LiveForensics } | Should -Not -Throw
        }
    }
}