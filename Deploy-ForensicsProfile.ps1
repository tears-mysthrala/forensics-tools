# Deploy-ForensicsProfile.ps1
# Script to deploy the forensics PowerShell profile to the desktop for monitoring

param(
    [string]$SourcePath = "$PSScriptRoot",
    [string]$DesktopPath = "$env:USERPROFILE\Desktop\forensics-tools"
)

Write-Host "Deploying Forensics PowerShell Profile to Desktop..." -ForegroundColor Cyan

# Create desktop directory if it doesn't exist
if (-not (Test-Path $DesktopPath)) {
    New-Item -ItemType Directory -Path $DesktopPath -Force | Out-Null
    Write-Host "Created directory: $DesktopPath" -ForegroundColor Green
}

# Copy the profile and related files
$filesToCopy = @(
    "Microsoft.PowerShell_profile.ps1",
    "Scripts\ForensicFunctions.ps1",
    "Core\Utils\FileSystemUtils.ps1",
    "Core\Utils\SearchUtils.ps1",
    "Core\Utils\CommonUtils.ps1",
    "Core\Utils\unified_aliases.ps1",
    "README.md"
)

foreach ($file in $filesToCopy) {
    $sourceFile = Join-Path $SourcePath $file
    $destFile = Join-Path $DesktopPath $file

    if (Test-Path $sourceFile) {
        # Create destination directory if needed
        $destDir = Split-Path $destFile -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }

        Copy-Item -Path $sourceFile -Destination $destFile -Force
        Write-Host "Copied: $file" -ForegroundColor Green
    } else {
        Write-Warning "Source file not found: $sourceFile"
    }
}

Write-Host "`nDeployment complete!" -ForegroundColor Green
Write-Host "Forensics profile is now available at: $DesktopPath" -ForegroundColor Cyan
Write-Host "Use the '🔍 Forensics IR' profile in Windows Terminal for monitoring." -ForegroundColor Yellow

# Install forensic tools
Write-Host "`nInstalling forensic tools..." -ForegroundColor Cyan
try {
    # Load the profile to access the functions
    $profilePath = Join-Path $DesktopPath "Microsoft.PowerShell_profile.ps1"
    if (Test-Path $profilePath) {
        . $profilePath
        Install-ForensicTools -ToolsPath $DesktopPath
    } else {
        Write-Warning "Could not load profile for tool installation"
    }
} catch {
    Write-Warning "Tool installation failed: $($_.Exception.Message)"
}

Write-Host "`nSetup complete! Ready for forensics investigations." -ForegroundColor Green