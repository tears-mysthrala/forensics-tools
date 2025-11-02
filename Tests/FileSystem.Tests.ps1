# FileSystem.Tests.ps1
# Unit tests for FileSystem module

Describe "FileSystem Module Tests" {

    BeforeAll {
        # Import required modules
        . "$PSScriptRoot\..\Scripts\Modules\CoreSystem.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\EventLog.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\Registry.ps1"

        # Import the module
        . "$PSScriptRoot\..\Scripts\Modules\FileSystem.ps1"

        # Create test files
        $testDir = Join-Path $TestDrive "TestFiles"
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null

        $testFile1 = Join-Path $testDir "test1.txt"
        $testFile2 = Join-Path $testDir "test2.exe"

        "Test content 1" | Out-File $testFile1 -Encoding UTF8
        "Test content 2" | Out-File $testFile2 -Encoding UTF8
    }

    Context "Get-FileHashes Parameter Validation" {

        It "Should accept Path parameter" {
            { Get-FileHashes -Path $testDir } | Should -Not -Throw
        }

        It "Should accept Algorithm parameter" {
            { Get-FileHashes -Path $testDir -Algorithm "MD5" } | Should -Not -Throw
        }

        It "Should default to SHA256 algorithm" {
            $result = Get-FileHashes -Path $testDir
            $result | ForEach-Object { $_.Algorithm | Should -Be "SHA256" }
        }
    }

    Context "Get-FileHashes Functionality" {

        It "Should return hash objects for files" {
            $result = Get-FileHashes -Path $testDir
            $result | Should -Not -BeNullOrEmpty
            $result.Count | Should -Be 2
        }

        It "Should return proper hash object structure" {
            $result = Get-FileHashes -Path $testDir
            $firstResult = $result | Select-Object -First 1
            $firstResult.PSObject.Properties.Name | Should -Contain "Path"
            $firstResult.PSObject.Properties.Name | Should -Contain "Size"
            $firstResult.PSObject.Properties.Name | Should -Contain "LastWriteTime"
            $firstResult.PSObject.Properties.Name | Should -Contain "Hash"
            $firstResult.PSObject.Properties.Name | Should -Contain "Algorithm"
        }

        It "Should compute valid hashes" {
            $result = Get-FileHashes -Path $testDir -Algorithm "MD5"
            $result | ForEach-Object {
                $_.Hash | Should -Match "^[A-Fa-f0-9]{32}$"  # MD5 hash format
                $_.Algorithm | Should -Be "MD5"
            }
        }

        It "Should handle different algorithms" {
            $result = Get-FileHashes -Path $testFile1 -Algorithm "SHA1"
            $result.Hash | Should -Match "^[A-Fa-f0-9]{40}$"  # SHA1 hash format
            $result.Algorithm | Should -Be "SHA1"
        }
    }

    Context "Analyze-File Parameter Validation" {

        It "Should require Path parameter" {
            { Analyze-File } | Should -Throw
        }

        It "Should accept valid Path parameter" {
            { Analyze-File -Path $testFile1 } | Should -Not -Throw
        }
    }

    Context "Analyze-File Functionality" {

        It "Should return file analysis for existing file" {
            $result = Analyze-File -Path $testFile1
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [PSCustomObject]
        }

        It "Should return proper analysis structure" {
            $result = Analyze-File -Path $testFile1
            $result.PSObject.Properties.Name | Should -Contain "Name"
            $result.PSObject.Properties.Name | Should -Contain "FullPath"
            $result.PSObject.Properties.Name | Should -Contain "Size"
            $result.PSObject.Properties.Name | Should -Contain "Created"
            $result.PSObject.Properties.Name | Should -Contain "Modified"
            $result.PSObject.Properties.Name | Should -Contain "Accessed"
            $result.PSObject.Properties.Name | Should -Contain "Type"
        }

        It "Should return correct file information" {
            $result = Analyze-File -Path $testFile1
            $result.Name | Should -Be "test1.txt"
            $result.FullPath | Should -Be $testFile1
            $result.Size | Should -BeGreaterThan 0
            $result.Type | Should -Be ".txt"
        }

        It "Should handle different file types" {
            $result = Analyze-File -Path $testFile2
            $result.Name | Should -Be "test2.exe"
            $result.Type | Should -Be ".exe"
        }
    }

    Context "Error Handling" {

        It "Should handle non-existent file gracefully" {
            $nonExistent = Join-Path $TestDrive "nonexistent.txt"
            { Analyze-File -Path $nonExistent } | Should -Not -Throw
            # Function should handle this internally, but may return null or empty
        }

        It "Should handle invalid path gracefully" {
            { Get-FileHashes -Path "InvalidPath" } | Should -Not -Throw
            # Should return empty collection for invalid paths
        }
    }
}