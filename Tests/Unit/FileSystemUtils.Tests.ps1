# Unit Tests for FileSystemUtils Module
# Tests for Core/Utils/FileSystemUtils.ps1 functions

Describe "New-DirectoryAndEnter" {

    BeforeAll {
        # Import the module under test
        . "$PSScriptRoot/../../Core/Utils/FileSystemUtils.ps1"
    }

    BeforeEach {
        # Store original location
        $script:originalLocation = Get-Location
    }

    AfterEach {
        # Restore original location
        Set-Location $script:originalLocation

        # Clean up test directories
        $testDir = Join-Path $TestDrive "TestDir"
        if (Test-Path $testDir) {
            Remove-Item $testDir -Recurse -Force
        }
    }

    Context "Directory creation and navigation" {

        It "Should create directory if it doesn't exist" {
            $testDir = Join-Path $TestDrive "TestDir"
            New-DirectoryAndEnter -dir $testDir

            $currentLocation = Get-Location
            $currentLocation.Path | Should -Be $testDir
            Test-Path $testDir | Should -Be $true
        }

        It "Should navigate to existing directory" {
            $testDir = Join-Path $TestDrive "ExistingDir"
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null

            New-DirectoryAndEnter -dir $testDir

            $currentLocation = Get-Location
            $currentLocation.Path | Should -Be $testDir
        }

        It "Should handle relative paths" {
            $relativeDir = "RelativeTestDir"
            $expectedPath = Join-Path $script:originalLocation $relativeDir

            New-DirectoryAndEnter -dir $relativeDir

            $currentLocation = Get-Location
            $currentLocation.Path | Should -Be $expectedPath
            Test-Path $expectedPath | Should -Be $true
        }
    }
}

Describe "Expand-CustomArchive" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/FileSystemUtils.ps1"
    }

    Context "Parameter validation" {

        It "Should require File parameter" {
            $threwException = $false
            try {
                Expand-CustomArchive
            }
            catch {
                $threwException = $true
            }
            $threwException | Should -Be $true
        }

        It "Should accept valid file path" {
            # This will fail because the file doesn't exist, but should not fail on parameter validation
            $threwException = $false
            try {
                Expand-CustomArchive -File "nonexistent.zip"
            }
            catch {
                if ($_.Exception.Message -notmatch "File not found") {
                    $threwException = $true
                }
            }
            $threwException | Should -Be $false
        }
    }

    Context "Archive extraction logic" {

        It "Should create output folder if not specified" {
            # Mock the archive file
            $mockArchive = Join-Path $TestDrive "test.zip"
            New-Item -ItemType File -Path $mockArchive -Force | Out-Null

            # This will fail at the extraction step, but should create the folder
            $expectedFolder = Join-Path $TestDrive "test"

            try {
                Expand-CustomArchive -File $mockArchive
            }
            catch {
                # Expected to fail since it's not a real archive
            }

            # Should have created the output folder
            Test-Path $expectedFolder | Should -Be $true
        }

        It "Should use custom output folder when specified" {
            $mockArchive = Join-Path $TestDrive "test.zip"
            $customFolder = Join-Path $TestDrive "CustomOutput"
            New-Item -ItemType File -Path $mockArchive -Force | Out-Null

            try {
                Expand-CustomArchive -File $mockArchive -Folder $customFolder
            }
            catch {
                # Expected to fail since it's not a real archive
            }

            Test-Path $customFolder | Should -Be $true
        }

        It "Should handle non-existent files" {
            $nonExistentFile = Join-Path $TestDrive "nonexistent.zip"
            $threwException = $false
            try {
                Expand-CustomArchive -File $nonExistentFile
            }
            catch {
                $threwException = $true
            }
            $threwException | Should -Be $true
        }
    }
}

Describe "Expand-CustomArchives" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/FileSystemUtils.ps1"
    }

    Context "Multiple archive processing" {

        It "Should create base folder with timestamp" {
            $mockArchives = @(
                (Join-Path $TestDrive "test1.zip"),
                (Join-Path $TestDrive "test2.zip")
            )

            # Create mock files
            foreach ($archive in $mockArchives) {
                New-Item -ItemType File -Path $archive -Force | Out-Null
            }

            # Store original location and change to TestDrive
            $originalLocation = Get-Location
            Set-Location $TestDrive

            try {
                Expand-CustomArchives -Files $mockArchives
            }
            catch {
                # Expected to fail since they're not real archives
            }
            finally {
                Set-Location $originalLocation
            }

            # Should have created a folder starting with "expanded_" in TestDrive
            $expandedFolders = Get-ChildItem $TestDrive -Directory | Where-Object { $_.Name -like "expanded_*" }
            $expandedFolders | Should -Not -BeNullOrEmpty
            ($expandedFolders | Measure-Object).Count | Should -Be 1
        }

        It "Should handle empty file list" {
            # This Should -Not -Throw but also not create anything
            $threwException = $false
            try {
                Expand-CustomArchives -Files @()
            }
            catch {
                $threwException = $true
            }
            $threwException | Should -Be $false
        }
    }
}
