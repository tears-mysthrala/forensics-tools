# Pester Configuration for Forensics Tools Testing Framework
# This file defines the testing configuration and conventions

@{
    Run          = @{
        # Test discovery
        Path        = @(
            "$PSScriptRoot/Unit"
            "$PSScriptRoot/Integration"
            "$PSScriptRoot/Performance"
        )

        # Exclude patterns
        ExcludePath = @(
            "*.Fixtures.*"
            "*.Utils.*"
        )

        # Test file patterns
        ScriptBlock = {
            Get-ChildItem -Path $PSScriptRoot -Recurse -Include "*.Tests.ps1" -Exclude "*.Fixtures.*"
        }
    }

    Filter       = @{
        # Tag filters for selective test execution
        Tag        = @()
        ExcludeTag = @('Slow', 'Integration', 'Performance')
    }

    CodeCoverage = @{
        # Enable code coverage analysis
        Enabled               = $true

        # Paths to analyze for coverage
        Path                  = @(
            "$PSScriptRoot/../../Scripts/Modules/*.ps1"
            "$PSScriptRoot/../../Core/Utils/*.ps1"
        )

        # Exclude patterns from coverage
        ExcludePath           = @(
            "*.Tests.ps1"
            "*Test*.ps1"
            "*Fixture*.ps1"
        )

        # Coverage threshold
        CoveragePercentTarget = 80
    }

    TestResult   = @{
        # Output format
        OutputFormat = 'NUnitXml'

        # Output path
        OutputPath   = "$PSScriptRoot/TestResults.xml"

        # Enable test result output
        Enabled      = $true
    }

    Should       = @{
        # Error action for failed assertions
        ErrorAction = 'Continue'
    }

    Output       = @{
        # Verbosity level
        Verbosity = 'Normal'
    }
}