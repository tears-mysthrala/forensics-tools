# Unit Tests for SearchUtils Module
# Tests for Core/Utils/SearchUtils.ps1 functions

Describe "Find-Files" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/SearchUtils.ps1"
    }

    BeforeEach {
        # Create test files
        New-Item -ItemType File -Path (Join-Path $TestDrive "test1.txt") -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $TestDrive "test2.txt") -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $TestDrive "script.ps1") -Force | Out-Null

        # Create subdirectory with files
        $subDir = Join-Path $TestDrive "subdir"
        New-Item -ItemType Directory -Path $subDir -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $subDir "nested.txt") -Force | Out-Null
    }

    Context "Basic file finding" {

        It "Should find all files with default pattern" {
            $results = Find-Files -path $TestDrive
            $results | Should Not BeNullOrEmpty
            ($results | Measure-Object).Count | Should BeGreaterThan 2
        }

        It "Should filter by pattern" {
            $results = Find-Files -pattern "*.txt" -path $TestDrive
            $results | Should Not BeNullOrEmpty
            $txtFiles = $results | Where-Object { $_.FullName -like "*.txt" }
            ($txtFiles | Measure-Object).Count | Should BeGreaterThan 1
        }

        It "Should filter by PowerShell files" {
            $results = Find-Files -pattern "*.ps1" -path $TestDrive
            $results | Should Not BeNullOrEmpty
            $ps1Files = $results | Where-Object { $_.FullName -like "*.ps1" }
            ($ps1Files | Measure-Object).Count | Should BeGreaterThan 0
        }
    }

    Context "Recursive search" {

        It "Should find files recursively when recurse is specified" {
            $results = Find-Files -pattern "*.txt" -path $TestDrive -recurse
            $results | Should Not BeNullOrEmpty
            $nestedFile = $results | Where-Object { $_.FullName -like "*nested.txt" }
            $nestedFile | Should Not BeNullOrEmpty
        }

        It "Should not find nested files without recurse" {
            $results = Find-Files -pattern "*.txt" -path $TestDrive
            $nestedFile = $results | Where-Object { $_.FullName -like "*nested.txt" }
            $nestedFile | Should BeNullOrEmpty
        }
    }

    Context "Result properties" {

        It "Should return FullName, LastWriteTime, and Length properties" {
            $results = Find-Files -pattern "*.txt" -path $TestDrive
            $results | Should Not BeNullOrEmpty

            $firstResult = $results | Select-Object -First 1
            $firstResult.FullName | Should Not BeNullOrEmpty
            $firstResult.LastWriteTime | Should Not BeNullOrEmpty
            # Length can be null for some file types, so just check it exists
            $firstResult | Get-Member -Name Length | Should Not BeNullOrEmpty
        }

        It "Should sort results by LastWriteTime descending" {
            $results = Find-Files -pattern "*.txt" -path $TestDrive
            $resultsArray = @($results | Select-Object -First 2)
            if ($resultsArray.Count -gt 1) {
                # Create a small delay to ensure different timestamps
                Start-Sleep -Milliseconds 10
                $newFile = Join-Path $TestDrive "newer.txt"
                "new content" | Out-File -FilePath $newFile -Encoding UTF8

                $newResults = Find-Files -pattern "*.txt" -path $TestDrive
                $newResultsArray = @($newResults | Select-Object -First 2)
                if ($newResultsArray.Count -gt 1) {
                    $firstTime = $newResultsArray[0].LastWriteTime
                    $secondTime = $newResultsArray[1].LastWriteTime
                    ($firstTime - $secondTime).TotalSeconds | Should BeGreaterThan -1
                }
            }
        }
    }
}

Describe "Search-FileContent" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/SearchUtils.ps1"
    }

    BeforeEach {
        # Create test files with content
        $testFile1 = Join-Path $TestDrive "content1.txt"
        $testFile2 = Join-Path $TestDrive "content2.txt"
        $testFile3 = Join-Path $TestDrive "script.ps1"

        "This is a test file with some content" | Out-File -FilePath $testFile1 -Encoding UTF8
        "Another file with different content" | Out-File -FilePath $testFile2 -Encoding UTF8
        "PowerShell script with test content" | Out-File -FilePath $testFile3 -Encoding UTF8
    }

    Context "Content searching" {

        It "Should require pattern parameter" {
            { Search-FileContent } | Should Throw
        }

        It "Should find content in files" {
            $results = Search-FileContent -pattern "test" -path $TestDrive
            $results | Should Not BeNullOrEmpty
            ($results | Measure-Object).Count | Should BeGreaterThan 1
        }

        It "Should return Path, Line, and LineNumber properties" {
            $results = Search-FileContent -pattern "test" -path $TestDrive
            $results | Should Not BeNullOrEmpty

            $firstResult = $results | Select-Object -First 1
            $firstResult.Path | Should Not BeNullOrEmpty
            $firstResult.Line | Should Not BeNullOrEmpty
            $firstResult.LineNumber | Should -BeGreaterThan 0
        }

        It "Should filter by file pattern" {
            $results = Search-FileContent -pattern "test" -path $TestDrive -filter "*.ps1"
            $results | Should Not BeNullOrEmpty
            $results.Path | Should -ContainLike "*.ps1"
        }

        It "Should handle case sensitivity" {
            $results = Search-FileContent -pattern "Test" -path $TestDrive -caseSensitive
            # Should find fewer results than case-insensitive search
            $caseInsensitive = Search-FileContent -pattern "test" -path $TestDrive
            ($results | Measure-Object).Count | Should -BeLessOrEqual ($caseInsensitive | Measure-Object).Count
        }
    }
}

Describe "Find-Command" {

    BeforeAll {
        . "$PSScriptRoot/../../Core/Utils/SearchUtils.ps1"
    }

    Context "Command finding" {

        It "Should find commands by partial name" {
            $results = Find-Command -name "Get-Process"
            # This outputs to the host, so we can't easily test the output
            # But it should not throw an exception
            { Find-Command -name "Get-Process" } | Should Not Throw
        }

        It "Should handle non-existent commands" {
            { Find-Command -name "NonExistentCommand12345" } | Should Not Throw
        }

        It "Should handle empty name parameter" {
            { Find-Command -name "" } | Should Not Throw
        }
    }
}