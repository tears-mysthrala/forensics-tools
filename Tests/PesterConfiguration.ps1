# Pester Configuration for Forensics Tools Testing Framework
# Updated for Pester 5.x with modern configuration

# Create Pester configuration object
$config = New-PesterConfiguration

# Test discovery
$config.Run.Path = @(
    "$PSScriptRoot/Unit/*.Tests.ps1"
    "$PSScriptRoot/Integration/*.Tests.ps1"
    "$PSScriptRoot/Performance/*.Tests.ps1"
)

# Exclude patterns (not needed when using specific file patterns)
# $config.Run.ExcludePath = @(
#     "*Fixtures*"
#     "*Utils*"
# )

# Filter configuration
$config.Filter.Tag = @()
$config.Filter.ExcludeTag = @('Slow', 'Integration', 'Performance')

# Code coverage configuration
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = @(
    "$PSScriptRoot/../Scripts/Modules/*.ps1"
    "$PSScriptRoot/../Core/Utils/*.ps1"
)
$config.CodeCoverage.ExcludeTests = $true
$config.CodeCoverage.CoveragePercentTarget = 80
$config.CodeCoverage.OutputPath = Join-Path $PSScriptRoot "Coverage.xml"
$config.CodeCoverage.OutputFormat = 'JaCoCo'

# Test result configuration
$config.TestResult.Enabled = $true
$config.TestResult.OutputPath = Join-Path $PSScriptRoot "TestResults.xml"
$config.TestResult.OutputFormat = 'NUnitXml'

# Output configuration
$config.Output.Verbosity = 'Normal'

# Should configuration
$config.Should.ErrorAction = 'Continue'

# Return the configuration object
$config