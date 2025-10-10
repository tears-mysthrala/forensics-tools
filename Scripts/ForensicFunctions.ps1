# ForensicFunctions.ps1 - Module loader for forensic functions

<#
.SYNOPSIS
    Loads all forensic analysis modules for PowerShell forensics and incident response.
.DESCRIPTION
    This script loads all modular forensic functions from the Modules directory.
    It provides a comprehensive toolkit for digital forensics and incident response.
.EXAMPLE
    . .\ForensicFunctions.ps1
.NOTES
    Requires PowerShell 7+ for full functionality
    Some functions require Administrator privileges
#>

param(
    [switch]$Verbose
)

# Get the script directory
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModulesDir = Join-Path $ScriptDir "Modules"

Write-Host "Loading Forensic Functions Modules..." -ForegroundColor Cyan

# Check if modules directory exists
if (-not (Test-Path $ModulesDir)) {
    Write-Error "Modules directory not found: $ModulesDir"
    Write-Host "Please ensure all module files are in the Modules subdirectory." -ForegroundColor Yellow
    return
}

# List of modules to load
$Modules = @(
    "CoreSystemFunctions.ps1",
    "NetworkFunctions.ps1",
    "FileSystemFunctions.ps1",
    "RegistryFunctions.ps1",
    "EventLogFunctions.ps1",
    "MemoryFunctions.ps1",
    "AdvancedMemoryFunctions.ps1",
    "AdvancedNetworkFunctions.ps1",
    "AdvancedFileSystemFunctions.ps1",
    "AdvancedMalwareAnalysisFunctions.ps1",
    "CloudForensicsFunctions.ps1",
    "EvidenceCollectionFunctions.ps1",
    "AnalysisWrapperFunctions.ps1",
    "PerformanceFunctions.ps1",
    "ExternalToolIntegrationsFunctions.ps1",
    "TestingValidationFrameworkFunctions.ps1",
    "PlaybookManagementFunctions.ps1",
    "CaseManagementFunctions.ps1",
    "ExecutionMonitoringFunctions.ps1",
    "EvidenceManagementSystemFunctions.ps1",
    "HTMLReportFunctions.ps1",
    "TimelineVisualizationFunctions.ps1",
    "EvidenceCorrelationFunctions.ps1",
    "ExportReportFunctions.ps1",
    "BrowserProfilesFunctions.ps1",
    "BrowserHistoryFunctions.ps1",
    "BrowserCacheFunctions.ps1",
    "BrowserCookiesFunctions.ps1",
    "BrowserBookmarksFunctions.ps1",
    "BrowserTimelineFunctions.ps1",
    "BrowserExportFunctions.ps1",
    "DatabaseForensicsFunctions.ps1",
    "AndroidDeviceFunctions.ps1",
    "iOSDeviceFunctions.ps1",
    "MobileDeviceReportingFunctions.ps1",
    "AutomatedReportingFunctions.ps1"
)

$LoadedModules = 0
$FailedModules = 0

foreach ($module in $Modules) {
    $modulePath = Join-Path $ModulesDir $module

    if (Test-Path $modulePath) {
        try {
            . $modulePath
            $LoadedModules++
        }
        catch {
            Write-Warning "Failed to load $module : $($_.Exception.Message)"
            $FailedModules++
        }
    }
    else {
        Write-Warning "Module not found: $modulePath"
        $FailedModules++
    }
}

# Load Automation Functions
$automationFunctionsPath = Join-Path $PSScriptRoot "Modules\AutomationFunctions.ps1"
if (Test-Path $automationFunctionsPath) {
    Write-Host "Loading Automation Functions..." -ForegroundColor Cyan
    try {
        . $automationFunctionsPath
    }
    catch {
        Write-Warning "Failed to load forensic toolkit: $($_.Exception.Message)"
    }
}

# Load Performance Functions
$performanceFunctionsPath = Join-Path $PSScriptRoot "Modules\PerformanceFunctions.ps1"
if (Test-Path $performanceFunctionsPath) {
    Write-Host "Loading Performance Functions..." -ForegroundColor Cyan
    try {
        . $performanceFunctionsPath
    }
    catch {
        Write-Warning "Failed to load Performance Functions: $($_.Exception.Message)"
    }
}

# Check for Administrator privileges
$IsAdministrator = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdministrator) {
    Write-Host ""
    Write-Host "WARNING: ELEVATION REQUIRED" -ForegroundColor Yellow
    Write-Host "Some functions require Administrator privileges." -ForegroundColor Yellow
}
else {
    Write-Host "`nRunning with Administrator privileges" -ForegroundColor Green
}

# Display loading summary
Write-Host "`n=== MODULE LOADING COMPLETE ===" -ForegroundColor Cyan
Write-Host "Modules loaded: $LoadedModules" -ForegroundColor Green
if ($FailedModules -gt 0) {
    Write-Host "Modules failed: $FailedModules" -ForegroundColor Yellow
}

# Display available functions
$ForensicFunctions = Get-Command -CommandType Function | Where-Object {
    $_.Name -match '^(Get-|Invoke-|Collect-|Search-|Export-)' -and
    $_.Source -match 'ForensicFunctions|Modules'
}

Write-Host ""
Write-Host "Available Forensic Functions:" -ForegroundColor Cyan
$ForensicFunctions | Sort-Object Name | ForEach-Object {
    Write-Host "  $($_.Name)" -ForegroundColor White
}

Write-Host ""
Write-Host "=== FORENSIC TOOLKIT READY ===" -ForegroundColor Green
Write-Host "Use Get-Help FunctionName for detailed usage information." -ForegroundColor Cyan
Write-Host "Some functions require Administrator privileges." -ForegroundColor Yellow

# Export functions for module use (only if running as module)
if ($MyInvocation.MyCommand.Name -match '\.psm1$') {
    Export-ModuleMember -Function $ForensicFunctions.Name
}