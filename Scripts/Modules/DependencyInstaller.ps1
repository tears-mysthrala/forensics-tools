function Install-Dependencies {
    <#
    .SYNOPSIS
        Install PowerShell profile dependencies
    .DESCRIPTION
        Installs package managers and CLI tools required by the PowerShell profile
    .PARAMETER All
        Install all dependencies (package managers + CLI tools)
    .PARAMETER PackageManagers
        Install only package managers (Chocolatey, Scoop)
    .PARAMETER CliTools
        Install only CLI tools (git, fzf, bat, eza, etc.)
    .PARAMETER Tool
        Install a specific tool by name
    .EXAMPLE
        Install-Dependencies -All
    .EXAMPLE
        Install-Dependencies -PackageManagers
    .EXAMPLE
        Install-Dependencies -CliTools
    .EXAMPLE
        Install-Dependencies -Tool git
    #>
    param(
        [switch]$All,
        [switch]$PackageManagers,
        [switch]$CliTools,
        [string]$Tool
    )

    $installerPath = Join-Path $ProfileDir 'tools/DependencyInstaller.ps1'

    if (-not (Test-Path $installerPath)) {
        Write-Error "Dependency installer not found at: $installerPath"
        return
    }

    $arguments = @()

    if ($All) { $arguments += "-InstallAll" }
    elseif ($PackageManagers) { $arguments += "-PackageManagers" }
    elseif ($CliTools) { $arguments += "-CliTools" }
    elseif ($Tool) { $arguments += "-Tool", $Tool }
    else {
        Write-Host "PowerShell Profile Dependency Installer" -ForegroundColor Cyan
        Write-Host "=====================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "USAGE:" -ForegroundColor Yellow
        Write-Host "    Install-Dependencies [-All|-PackageManagers|-CliTools|-Tool <name>]"
        Write-Host ""
        Write-Host "EXAMPLES:" -ForegroundColor Yellow
        Write-Host "    Install-Dependencies -All"
        Write-Host "    Install-Dependencies -PackageManagers"
        Write-Host "    Install-Dependencies -CliTools"
        Write-Host "    Install-Dependencies -Tool git"
        Write-Host ""
        Write-Host "Run 'Install-Dependencies -List' to see available tools."
        return
    }

    # Execute the installer
    & $installerPath @arguments
}