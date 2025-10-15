# Test Utilities for Forensics Tools Testing Framework
# Common functions and helpers for writing tests

#Requires -Modules Pester

# Import required modules for testing
$script:ForensicsModulesPath = Join-Path $PSScriptRoot "..\..\Scripts\Modules"
$script:CoreUtilsPath = Join-Path $PSScriptRoot "..\..\Core\Utils"

# Function to safely import forensics modules for testing
function Import-ForensicsModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $modulePath = Join-Path $script:ForensicsModulesPath "$ModuleName.ps1"

    if (-not (Test-Path $modulePath)) {
        throw "Module '$ModuleName' not found at '$modulePath'"
    }

    if ($Force -or -not (Get-Module -Name $ModuleName)) {
        try {
            . $modulePath
            Write-Verbose "Successfully imported module '$ModuleName'"
        }
        catch {
            throw "Failed to import module '$ModuleName': $_"
        }
    }
}

# Function to create mock test data
function New-TestFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Content = "Test file content",

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $fullPath = $Path
    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        $fullPath = Join-Path $TestDrive $Path
    }

    $directory = Split-Path $fullPath -Parent
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    if ($Force -or -not (Test-Path $fullPath)) {
        $Content | Out-File -FilePath $fullPath -Encoding UTF8 -Force
    }

    return $fullPath
}

# Function to create mock registry entries for testing
function New-TestRegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [hashtable]$Properties = @{},

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    # Note: This creates a mock registry key in HKCU\Software\ForensicsTest
    # In real tests, this should be mocked properly
    $testKeyPath = "HKCU:\Software\ForensicsTest\$Path"

    if ($Force -or -not (Test-Path $testKeyPath)) {
        New-Item -Path $testKeyPath -Force | Out-Null

        foreach ($property in $Properties.GetEnumerator()) {
            New-ItemProperty -Path $testKeyPath -Name $property.Key -Value $property.Value -PropertyType String -Force | Out-Null
        }
    }

    return $testKeyPath
}

# Function to clean up test artifacts
function Clear-TestEnvironment {
    [CmdletBinding()]
    param()

    # Remove test registry keys
    $testRoot = "HKCU:\Software\ForensicsTest"
    if (Test-Path $testRoot) {
        Remove-Item -Path $testRoot -Recurse -Force
    }

    # Clean up TestDrive
    if (Test-Path TestDrive:\) {
        Get-ChildItem TestDrive:\ | Remove-Item -Recurse -Force
    }
}

# Function to assert that a function exists and is properly defined
function Should-BeValidFunction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionName,

        [Parameter(Mandatory = $false)]
        [scriptblock]$TestBlock
    )

    $function = Get-Command -Name $FunctionName -ErrorAction SilentlyContinue
    $function | Should -Not -BeNullOrEmpty
    $function.CommandType | Should -Be 'Function'

    if ($TestBlock) {
        & $TestBlock
    }
}

# Function to run performance benchmarks
function Measure-TestPerformance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [int]$Iterations = 10,

        [Parameter(Mandatory = $false)]
        [timespan]$MaxDuration = [timespan]::FromSeconds(5)
    )

    $results = Measure-Command -Expression $ScriptBlock

    # Run multiple iterations for more accurate results
    $totalTime = [timespan]::Zero
    for ($i = 0; $i -lt $Iterations; $i++) {
        $iterationResult = Measure-Command -Expression $ScriptBlock
        $totalTime = $totalTime.Add($iterationResult)
    }

    $averageTime = [timespan]::FromTicks($totalTime.Ticks / $Iterations)

    return @{
        AverageTime     = $averageTime
        TotalTime       = $totalTime
        Iterations      = $Iterations
        WithinThreshold = $averageTime -lt $MaxDuration
    }
}

# Export functions for use in tests
# Note: Export-ModuleMember removed since this file is dot-sourced, not imported as a module