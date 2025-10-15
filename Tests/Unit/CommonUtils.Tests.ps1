# Unit Tests for CommonUtils Module
# Tests for Core/Utils/CommonUtils.ps1 functions

Describe "Test-CommandExists" {

    BeforeAll {
        # Import the module under test
        . "$PSScriptRoot/../../Core/Utils/CommonUtils.ps1"
    }

    Context "When command exists" {

        It "Should return true for built-in commands" {
            $result = Test-CommandExists -command "Get-Process"
            $result | Should Be $true
        }

        It "Should return true for external commands in PATH" {
            # Test with a common external command
            $result = Test-CommandExists -command "powershell.exe"
            $result | Should Be $true
        }

        It "Should handle case-insensitive command names" {
            $result = Test-CommandExists -command "get-process"
            $result | Should Be $true
        }
    }

    Context "When command does not exist" {

        It "Should return false for non-existent commands" {
            $result = Test-CommandExists -command "NonExistentCommand12345"
            $result | Should Be $false
        }

        It "Should throw validation exception for empty command string" {
            $threwException = $false
            try {
                Test-CommandExists -command ""
            }
            catch {
                $threwException = $true
            }
            $threwException | Should Be $true
        }

        It "Should throw validation exception for null command" {
            $threwException = $false
            try {
                Test-CommandExists -command $null
            }
            catch {
                $threwException = $true
            }
            $threwException | Should Be $true
        }
    }

    Context "Error handling" {

        It "Should not throw exceptions for invalid commands" {
            { Test-CommandExists -command "invalid-command-!@#$%" } | Should Not Throw
        }

        It "Should handle commands with special characters" {
            $result = Test-CommandExists -command "test.exe"
            # This might be true or false depending on system, but shouldn't throw
            { $result } | Should Not Throw
        }
    }
}

Describe "Test-IsAdmin" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/CommonUtils.ps1"
    }

    Context "Administrator check" {

        It "Should return a boolean value" {
            $result = Test-IsAdmin
            $result | Should BeOfType [bool]
        }

        It "Should not throw exceptions" {
            { Test-IsAdmin } | Should Not Throw
        }
    }
}

Describe "Get-FormatedUptime" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/CommonUtils.ps1"
    }

    Context "Uptime formatting" {

        It "Should return a string" {
            $result = Get-FormatedUptime
            $result | Should BeOfType [string]
        }

        It "Should contain uptime information" {
            $result = Get-FormatedUptime
            $result | Should Match "Uptime:"
            $result | Should Match "Days?"
            $result | Should Match "Hours?"
            $result | Should Match "Minutes?"
        }

        It "Should not throw exceptions" {
            { Get-FormatedUptime } | Should Not Throw
        }
    }
}

Describe "Initialize-EncodingConfig" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/CommonUtils.ps1"
    }

    Context "Encoding configuration" {

        It "Should not throw exceptions" {
            { Initialize-EncodingConfig } | Should Not Throw
        }

        It "Should set PYTHONIOENCODING environment variable" {
            Initialize-EncodingConfig
            $env:PYTHONIOENCODING | Should Be "utf-8"
        }

        It "Should set console output encoding to UTF8" {
            Initialize-EncodingConfig
            [System.Console]::OutputEncoding | Should BeOfType [System.Text.UTF8Encoding]
        }
    }
}