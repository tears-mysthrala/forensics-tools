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
    "AdvancedFileSystemAnalysis.ps1",
    "AdvancedMalwareAnalysis.ps1",
    "AdvancedMemory.ps1",
    "AdvancedNetworkAnalysis.ps1",
    "AnalysisWrapper.ps1",
    "AndroidDevice.ps1",
    "AutomatedReporting.ps1",
    "AutomationManagement.ps1",
    "BrowserBookmarks.ps1",
    "BrowserCache.ps1",
    "BrowserCookies.ps1",
    "BrowserExport.ps1",
    "BrowserHistory.ps1",
    "BrowserProfiles.ps1",
    "BrowserTimeline.ps1",
    "CaseManagement.ps1",
    "CloudForensics.ps1",
    "CoreSystem.ps1",
    "DatabaseDiscovery.ps1",
    "DatabaseExport.ps1",
    "DeletedFiles.ps1",
    "DNSAnalysis.ps1",
    "EventLog.ps1",
    "EvidenceAudit.ps1",
    "EvidenceChainOfCustody.ps1",
    "EvidenceClasses.ps1",
    "EvidenceCollection.ps1",
    "EvidenceCollectionWorkflow.ps1",
    "EvidenceCorrelation.ps1",
    "EvidenceItem.ps1",
    "EvidenceReporting.ps1",
    "EvidenceRepository.ps1",
    "EvidenceVerification.ps1",
    "ExecutionMonitoring.ps1",
    "ExportReport.ps1",
    "ExternalToolIntegrations.ps1",
    "FileAnomaly.ps1",
    "FileCarving.ps1",
    "FileSignature.ps1",
    "FileSystem.ps1",
    "FileSystemTimeline.ps1",
    "FirewallAnalysis.ps1",
    "HTMLReport.ps1",
    "iOSDevice.ps1",
    "Memory.ps1",
    "MobileDeviceReporting.ps1",
    "Network.ps1",
    "NetworkAnomaly.ps1",
    "NetworkCapture.ps1",
    "NetworkTrafficAnalysis.ps1",
    "Performance.ps1",
    "PlaybookManagement.ps1",
    "Registry.ps1",
    "ScheduledTask.ps1",
    "SIEMIntegration.ps1",
    "SQLiteDatabase.ps1",
    "SQLServerDatabase.ps1",
    "TestingValidationFramework.ps1",
    "TimelineVisualization.ps1",
    "WorkflowOrchestration.ps1"
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

# Load Performance Functions
$performanceFunctionsPath = Join-Path $PSScriptRoot "Modules\PerformanceFunctions.ps1"
if (Test-Path $performanceFunctionsPath) {
    Write-Host "Loading Performance Functions..." -ForegroundColor Cyan
    . $performanceFunctionsPath
}

# Check for Administrator privileges
$IsAdministrator = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdministrator) {
    Write-Host ""
    Write-Host "WARNING: ELEVATION REQUIRED" -ForegroundColor Yellow
    Write-Host "Some functions require Administrator privileges" -ForegroundColor Yellow
}
else {
    Write-Host ""
    Write-Host "Running with Administrator privileges" -ForegroundColor Green
}

# Display loading summary
Write-Host "`n=== MODULE LOADING COMPLETE ===" -ForegroundColor Cyan
Write-Host "Modules loaded: $LoadedModules" -ForegroundColor Green
if ($FailedModules -gt 0) {
    Write-Host "Modules failed: $FailedModules" -ForegroundColor Yellow
}

# Display available functions
$ForensicFunctions = Get-Command -CommandType Function

Write-Host ""
Write-Host "Key Forensic Functions:" -ForegroundColor Cyan

$KeyFunctions = @(
    "Get-SystemInfo",
    "Get-ProcessDetails", 
    "Get-NetworkConnections",
    "Get-FileHashes",
    "Analyze-File",
    "Get-EventLogsSummary",
    "Search-EventLogs",
    "Get-RegistryKeys",
    "Get-MemoryDump",
    "Collect-SystemEvidence"
)

$AvailableKeyFunctions = $KeyFunctions | Where-Object {
    Get-Command $_ -CommandType Function -ErrorAction SilentlyContinue
}

if ($AvailableKeyFunctions) {
    $AvailableKeyFunctions | Sort-Object | ForEach-Object {
        Write-Host "  $_" -ForegroundColor White
    }
}
else {
    Write-Host "No key forensic functions found." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== FORENSIC TOOLKIT READY ===" -ForegroundColor Green
Write-Host "Use Get-Help FunctionName for detailed usage information." -ForegroundColor Cyan
Write-Host "Some functions require Administrator privileges." -ForegroundColor Yellow

# Export functions for module use (only if running as module)
if ($MyInvocation.MyCommand.Name -match '\.psm1$') {
    Export-ModuleMember -Function $ForensicFunctions.Name
}