# RegistryFunctions.ps1 - Registry analysis functions

function Get-RegistryKeys {
    <#
    .SYNOPSIS
        Retrieves registry key values.
    .PARAMETER Path
        Registry path.
    .EXAMPLE
        Get-RegistryKeys -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion
    #>
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            Get-ItemProperty -Path $Path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*
        } else {
            Write-Warning "Registry path not found: $Path"
        }
    } catch {
        Write-Error "Failed to access registry key: $($_.Exception.Message)"
        Write-Host "Try running as Administrator for registry access." -ForegroundColor Yellow
    }
}