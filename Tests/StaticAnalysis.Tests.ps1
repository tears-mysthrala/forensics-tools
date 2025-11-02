# StaticAnalysis.Tests.ps1
# Unit tests for StaticAnalysis module

Describe "StaticAnalysis Module Tests" {

    BeforeAll {
        # Import dependent modules first
        . "$PSScriptRoot\..\Scripts\Modules\CoreSystem.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\EventLog.ps1"
        . "$PSScriptRoot\..\Scripts\Modules\Registry.ps1"

        # Import the module under test
        . "$PSScriptRoot\..\Scripts\Modules\StaticAnalysis.ps1"

        # Create test directory and files
        $testDir = Join-Path $TestDrive "TestFiles"
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null

        # Create test files
        $testExe = Join-Path $testDir "test.exe"
        $testDll = Join-Path $testDir "test.dll"
        $testTxt = Join-Path $testDir "test.txt"

        # Create dummy executable content (just text for testing)
        "MZ dummy executable content" | Out-File $testExe -Encoding ASCII
        "DLL dummy content" | Out-File $testDll -Encoding ASCII
        "This is a text file content" | Out-File $testTxt -Encoding ASCII

        # Create hidden file
        $hiddenFile = Join-Path $testDir "hidden.exe"
        "MZ hidden executable" | Out-File $hiddenFile -Encoding ASCII
        $file = Get-Item $hiddenFile
        $file.Attributes = $file.Attributes -bor [System.IO.FileAttributes]::Hidden
    }

    Context "Get-FileStaticAnalysis Parameter Validation" {

        It "Should require Path parameter" {
            $originalErrorAction = $ErrorActionPreference
            $ErrorActionPreference = 'Stop'
            try {
                { Get-FileStaticAnalysis } | Should -Throw
            }
            finally {
                $ErrorActionPreference = $originalErrorAction
            }
        }

        It "Should accept valid Path parameter" {
            { Get-FileStaticAnalysis -Path $testDir } | Should -Not -Throw
        }

        It "Should accept OutputPath parameter" {
            { Get-FileStaticAnalysis -Path $testDir -OutputPath $TestDrive } | Should -Not -Throw
        }

        It "Should accept DeepAnalysis parameter" {
            { Get-FileStaticAnalysis -Path $testDir -DeepAnalysis $true } | Should -Not -Throw
        }
    }

    Context "Get-FileStaticAnalysis Functionality" {

        It "Should return analysis results for directory" {
            $result = Get-FileStaticAnalysis -Path $testDir -OutputPath $TestDrive
            $result | Should -Not -BeNullOrEmpty
            $result.Path | Should -Be $testDir
            $result.Results | Should -Not -BeNullOrEmpty
        }

        It "Should return analysis results for single file" {
            $result = Get-FileStaticAnalysis -Path $testExe -OutputPath $TestDrive
            $result | Should -Not -BeNullOrEmpty
            $result.Path | Should -Be $testExe
            $result.Results | Should -Not -BeNullOrEmpty
            $result.Results.Count | Should -Be 1
        }

        It "Should detect executable files" {
            $result = Get-FileStaticAnalysis -Path $testExe -OutputPath $TestDrive
            $fileResult = $result.Results[0]
            $fileResult.SuspiciousIndicators | Should -Contain "Executable file type"
            $fileResult.RiskScore | Should -BeGreaterThan 0
        }

        It "Should detect hidden files" {
            $result = Get-FileStaticAnalysis -Path $hiddenFile -OutputPath $TestDrive
            $fileResult = $result.Results[0]
            $fileResult.SuspiciousIndicators | Should -Contain "Hidden file"
            $fileResult.RiskScore | Should -BeGreaterThan 0
        }

        It "Should create output directory" {
            $outputDir = Join-Path $TestDrive "CustomOutput"
            Get-FileStaticAnalysis -Path $testTxt -OutputPath $outputDir | Out-Null
            Test-Path $outputDir | Should -Be $true
        }
    }

    Context "Analysis Results Structure" {

        It "Should return proper result structure" {
            $result = Get-FileStaticAnalysis -Path $testTxt -OutputPath $TestDrive
            $result | Should -BeOfType [PSCustomObject]
            $result.PSObject.Properties.Name | Should -Contain "Timestamp"
            $result.PSObject.Properties.Name | Should -Contain "Path"
            $result.PSObject.Properties.Name | Should -Contain "Results"
        }

        It "Should return proper file analysis structure" {
            $result = Get-FileStaticAnalysis -Path $testTxt -OutputPath $TestDrive
            $fileResult = $result.Results[0]
            $fileResult.PSObject.Properties.Name | Should -Contain "FileName"
            $fileResult.PSObject.Properties.Name | Should -Contain "FullPath"
            $fileResult.PSObject.Properties.Name | Should -Contain "Size"
            $fileResult.PSObject.Properties.Name | Should -Contain "RiskScore"
            $fileResult.PSObject.Properties.Name | Should -Contain "SuspiciousIndicators"
        }
    }
}