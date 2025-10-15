# Unit Tests for UnifiedAliases Module
# Tests for Core/Utils/unified_aliases.ps1 functions

Describe "Navigation Aliases" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/unified_aliases.ps1"
    }

    Context "Directory navigation" {

        It "Should define .. alias" {
            { .. } | Should -Not -Throw
        }

        It "Should define ... alias" {
            { ... } | Should -Not -Throw
        }

        It "Should define .3 alias" {
            { .3 } | Should -Not -Throw
        }
    }
}

Describe "Initialize-Editor" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/unified_aliases.ps1"
    }

    Context "Editor initialization" {

        It "Should not throw when called" {
            { Initialize-Editor } | Should -Not -Throw
        }

        It "Should set EDITOR variable after initialization" {
            Initialize-Editor
            $script:EDITOR | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "v (Editor Alias)" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/unified_aliases.ps1"
    }

    Context "Editor launching" {

        It "Should initialize editor on first call" {
            { v } | Should -Not -Throw
        }
    }
}

Describe "Test-CommandExists" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/unified_aliases.ps1"
    }

    Context "Command existence checking" {

        It "Should return true for existing commands" {
            $result = Test-CommandExists -command "Get-Process"
            $result | Should -Be $true
        }

        It "Should return false for non-existent commands" {
            $result = Test-CommandExists -command "NonExistentCommand12345"
            $result | Should -Be $false
        }
    }
}