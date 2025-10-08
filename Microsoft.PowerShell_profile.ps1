# Microsoft.PowerShell_profile.ps1 - Forensics and Incident Response Profile

# Set essential environment variables
$ProfileDir = Split-Path -Parent $PROFILE

# Encoding settings
$env:PYTHONIOENCODING = 'utf-8'
[System.Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

# Module path
$customModulePath = "$ProfileDir\Modules"
if ($env:PSModulePath -notlike "*$customModulePath*") {
    $env:PSModulePath = "$customModulePath;" + $env:PSModulePath
}

# Performance optimizations
$env:POWERSHELL_TELEMETRY_OPTOUT = 1
$env:POWERSHELL_UPDATECHECK = 'Off'

# Load core utilities
. "$PSScriptRoot\Core\Utils\FileSystemUtils.ps1"
. "$PSScriptRoot\Core\Utils\SearchUtils.ps1"
. "$PSScriptRoot\Core\Utils\CommonUtils.ps1"

# Load forensic-specific functions
. "$PSScriptRoot\Scripts\ForensicFunctions.ps1"

# Install and import forensic modules if available
$forensicModules = @('PowerForensics', 'PSRecon', 'Invoke-LiveResponse')
foreach ($module in $forensicModules) {
    if (-not (Get-Module -Name $module -ListAvailable)) {
        try {
            Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to install module $module`: $_"
        }
    }
    try {
        Import-Module -Name $module -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to import module $module`: $_"
    }
}

# Configure PSReadLine with basic features
$PSReadLineOptions = @{
    PredictionSource              = 'History'
    HistorySearchCursorMovesToEnd = $true
}
try {
    Set-PSReadLineOption @PSReadLineOptions
    Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
    Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
    Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
}
catch {
    Write-Warning "PSReadLine configuration failed: $_"
}

# Load aliases relevant to forensics
. "$PSScriptRoot\Core\Utils\unified_aliases.ps1"

# Custom prompt for forensics traceability
function prompt {
    # Get current timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Get user and computer info
    $user = $env:USERNAME
    $computer = $env:COMPUTERNAME
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $adminIndicator = if ($isAdmin) { "[ADMIN]" } else { "" }
    
    # Get current directory (shorten if too long)
    $currentDir = $PWD.Path
    if ($currentDir.Length -gt 40) {
        $currentDir = "..." + $currentDir.Substring($currentDir.Length - 37)
    }
    
    # Show last exit code if non-zero
    $exitCode = if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { " [Exit:$LASTEXITCODE]" } else { "" }
    
    # Build the prompt
    $promptString = "[$timestamp] $user@$computer$adminIndicator $currentDir$exitCode`nPS> "
    
    # Set window title for additional traceability
    $Host.UI.RawUI.WindowTitle = "PowerShell - $user@$computer - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    
    # Return the prompt
    $promptString
}

Write-Host "Forensics and Incident Response PowerShell Profile Loaded" -ForegroundColor Green

# Display system information for forensics analysis
Write-Host "`n=== System Information ===" -ForegroundColor Cyan
Get-SystemInfo | Format-List
