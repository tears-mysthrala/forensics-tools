# TestingValidationFramework.ps1
# Testing and validation framework for forensic functions

<#
.SYNOPSIS
    Testing and Validation Framework Functions

.DESCRIPTION
    This module provides comprehensive testing and validation capabilities including:
    - Unit testing for individual functions
    - Integration testing for module interactions
    - Performance benchmarking and validation
    - Automated test execution and reporting

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

# Import split modules
. "$PSScriptRoot\TestingClasses.ps1"
. "$PSScriptRoot\UnitTesting.ps1"
. "$PSScriptRoot\IntegrationTesting.ps1"
. "$PSScriptRoot\PerformanceTesting.ps1"
. "$PSScriptRoot\TestReporting.ps1"

# Note: This file has been split into smaller modules for better maintainability:
# - TestingClasses.ps1: ForensicTestResult and ForensicTestSuite classes
# - UnitTesting.ps1: Invoke-ForensicFunctionTest, Test-ResultValidation
# - IntegrationTesting.ps1: Invoke-ForensicIntegrationTest
# - PerformanceTesting.ps1: Invoke-PerformanceBenchmark
# - TestReporting.ps1: Export-TestResults, Invoke-ForensicTestSuite
