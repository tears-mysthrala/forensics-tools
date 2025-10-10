<#
.SYNOPSIS
    Automated installation script for PowerShell Forensics Toolkit
.DESCRIPTION
    This script automatically installs the PowerShell Forensics Toolkit,
    including all required tools and dependencies.
.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -ToolsPath "C:\Forensics"
.PARAMETER ToolsPath
    Directory where to install forensic tools (defaults to current directory)
.PARAMETER ProfilePath
    Path to PowerShell profile to update (defaults to current user profile)
.PARAMETER SkipTools
    Skip installation of external forensic tools
#>

param(
    [string]$ToolsPath = $null,
    [string]$ProfilePath = $PROFILE,
    [switch]$SkipTools
)

#Requires -Version 5.1

Write-Host "=== PowerShell Forensics Toolkit Installer ===" -ForegroundColor Cyan
Write-Host ""

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 7) {
    Write-Warning "PowerShell 7.0+ is recommended for full functionality. Current version: $($psVersion.ToString())"
    Write-Host ""
}

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "Some tools require administrator privileges. Please run as administrator for full functionality."
    Write-Host ""
}

# Set default tools path
if (-not $ToolsPath) {
    $ToolsPath = $PSScriptRoot
    if (-not $ToolsPath) {
        $ToolsPath = Get-Location
    }
}

Write-Host "Installation Path: $ToolsPath" -ForegroundColor Yellow
Write-Host "Profile Path: $ProfilePath" -ForegroundColor Yellow
Write-Host ""

# Step 1: Import the toolkit functions
Write-Host "Step 1: Loading toolkit functions..." -ForegroundColor Cyan
try {
    $scriptPath = Join-Path $PSScriptRoot "Scripts\ForensicFunctions.ps1"
    if (Test-Path $scriptPath) {
        # Load with error handling for PowerShell version compatibility
        $ErrorActionPreference = "Continue"
        . $scriptPath
        $ErrorActionPreference = "Stop"
        Write-Host "Toolkit functions loaded successfully" -ForegroundColor Green
        Write-Host "Note: Some modules may have failed to load due to PowerShell version compatibility" -ForegroundColor Yellow
    } else {
        throw "ForensicFunctions.ps1 not found at $scriptPath"
    }
} catch {
    Write-Warning "Some toolkit functions failed to load. This may be due to PowerShell version compatibility issues."
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Continuing with installation..." -ForegroundColor Yellow
}

# Step 2: Install external forensic tools
if (-not $SkipTools) {
    Write-Host ""
    Write-Host "Step 2: Installing forensic tools..." -ForegroundColor Cyan
    try {
        Install-ForensicTools -ToolsPath $ToolsPath
        Write-Host "Forensic tools installation completed" -ForegroundColor Green
    } catch {
        Write-Warning "Some tools failed to install automatically. You can run Install-ForensicTools manually later."
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host ""
    Write-Host "Step 2: Skipping forensic tools installation (-SkipTools specified)" -ForegroundColor Yellow
}

# Step 3: Update PowerShell profile
Write-Host ""
Write-Host "Step 3: Updating PowerShell profile..." -ForegroundColor Cyan

try {
    # Create profile directory if it doesn't exist
    $profileDir = Split-Path $ProfilePath -Parent
    if (-not (Test-Path $profileDir)) {
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    }

    # Check if profile already contains toolkit
    $existingProfile = ""
    if (Test-Path $ProfilePath) {
        $existingProfile = Get-Content $ProfilePath -Raw
    }

    if ($existingProfile -notmatch "FORENSIC TOOLKIT") {
        # Backup existing profile
        if ($existingProfile) {
            $backupPath = "$ProfilePath.backup.$(Get-Date -Format 'yyyyMMddHHmmss')"
            $existingProfile | Out-File -FilePath $backupPath -Encoding UTF8
            Write-Host "Existing profile backed up to: $backupPath" -ForegroundColor Green
        }

        # Add toolkit to profile
        $profileContent = @"
# PowerShell Forensics Toolkit Profile
# Added by automated installer on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

# Import the forensics toolkit
try {
    `$toolkitPath = "$ToolsPath"
    `$scriptPath = Join-Path `$toolkitPath "Scripts\ForensicFunctions.ps1"
    if (Test-Path `$scriptPath) {
        . `$scriptPath
        Write-Host "=== FORENSIC TOOLKIT LOADED ===" -ForegroundColor Green
    } else {
        Write-Warning "Forensic toolkit not found at `$scriptPath. Run the installer again."
    }
} catch {
    Write-Warning "Failed to load forensic toolkit: `$(`$_.Exception.Message)"
}

# Set tools path for easy access
`$env:FORENSIC_TOOLS_PATH = "$ToolsPath"

"@

        $profileContent | Out-File -FilePath $ProfilePath -Encoding UTF8 -Append
        Write-Host "PowerShell profile updated successfully" -ForegroundColor Green
    } else {
        Write-Host "Toolkit already configured in profile" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to update PowerShell profile. You can manually add the toolkit import."
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 4: Create desktop shortcuts
Write-Host ""
Write-Host "Step 4: Creating desktop shortcuts..." -ForegroundColor Cyan

try {
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $wshShell = New-Object -ComObject WScript.Shell

    # Create shortcut for toolkit directory
    $shortcut = $wshShell.CreateShortcut("$desktopPath\Forensics Toolkit.lnk")
    $shortcut.TargetPath = $ToolsPath
    $shortcut.Description = "PowerShell Forensics Toolkit Directory"
    $shortcut.Save()

    # Create shortcut for quick start guide
    $guidePath = Join-Path $ToolsPath "guide.md"
    if (Test-Path $guidePath) {
        $shortcut = $wshShell.CreateShortcut("$desktopPath\Forensics Guide.lnk")
        $shortcut.TargetPath = $guidePath
        $shortcut.Description = "Forensics Toolkit Quick Start Guide"
        $shortcut.Save()
    }

    Write-Host "Desktop shortcuts created" -ForegroundColor Green
} catch {
    Write-Warning "Failed to create desktop shortcuts. You can access the toolkit directly from $ToolsPath"
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 5: Run post-installation tests
Write-Host ""
Write-Host "Step 5: Running post-installation tests..." -ForegroundColor Cyan

$testsPassed = 0
$testsTotal = 0

# Test 1: Check if functions are available
$testsTotal++
try {
    $functions = Get-Command -Name "*-Forensic*" -ErrorAction Stop
    if ($functions.Count -gt 0) {
        Write-Host "Forensic functions available ($($functions.Count) functions)" -ForegroundColor Green
        $testsPassed++
    } else {
        throw "No forensic functions found"
    }
} catch {
    Write-Host "Forensic functions test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: Check tools directory
$testsTotal++
$toolsDir = Join-Path $ToolsPath "Tools"
if (Test-Path $toolsDir) {
    $toolFiles = Get-ChildItem $toolsDir -File -ErrorAction SilentlyContinue
    if ($toolFiles) {
        Write-Host "Tools directory created with $($toolFiles.Count) files" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "Tools directory created (empty)" -ForegroundColor Green
        $testsPassed++
    }
} else {
    Write-Host "Tools directory not found" -ForegroundColor Red
}

# Test 3: Check Python availability
$testsTotal++
try {
    $pythonVersion = python --version 2>$null
    if ($pythonVersion -match "Python") {
        Write-Host "Python available: $pythonVersion" -ForegroundColor Green
        $testsPassed++
    } else {
        throw "Python not found"
    }
} catch {
    Write-Host "Python test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== INSTALLATION COMPLETE ===" -ForegroundColor Green
Write-Host "Tests passed: $testsPassed/$testsTotal" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Restart PowerShell to load the updated profile" -ForegroundColor White
Write-Host "2. Run 'Get-Help Install-ForensicTools' for manual tool installation" -ForegroundColor White
Write-Host "3. Check the guide.md file for usage examples" -ForegroundColor White
Write-Host "4. Use 'New-AutomatedReport' for scheduled reporting" -ForegroundColor White
Write-Host ""
Write-Host "Installation directory: $ToolsPath" -ForegroundColor Cyan
Write-Host "Profile location: $ProfilePath" -ForegroundColor Cyan