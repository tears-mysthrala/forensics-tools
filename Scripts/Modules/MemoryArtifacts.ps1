function Get-MemoryArtifacts {
    <#
    .SYNOPSIS
        Extracts common memory artifacts for forensic analysis.
    .DESCRIPTION
        Gathers various memory-resident artifacts like clipboard contents, keystrokes, etc.
    .PARAMETER OutputPath
        Directory to save the artifacts.
    .EXAMPLE
        Get-MemoryArtifacts -OutputPath C:\Evidence
    #>
    param(
        [string]$OutputPath = "."
    )

    Write-Host "Collecting memory artifacts..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $artifactsDir = Join-Path $OutputPath "MemoryArtifacts_$timestamp"

    if (-not (Test-Path $artifactsDir)) {
        New-Item -ItemType Directory -Path $artifactsDir -Force | Out-Null
    }

    $artifacts = @{
        Timestamp = Get-Date
        Artifacts = @{}
    }

    # Clipboard contents
    Write-Host "Collecting clipboard contents..." -ForegroundColor Yellow
    try {
        $clipboard = Get-Clipboard -TextFormatType Text -ErrorAction SilentlyContinue
        if ($clipboard) {
            $clipboard | Out-File (Join-Path $artifactsDir "clipboard.txt")
            $artifacts.Artifacts.Clipboard = "Collected"
        }
        else {
            $artifacts.Artifacts.Clipboard = "No text content"
        }
        Write-Host "[OK] Clipboard collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to collect clipboard: $($_.Exception.Message)"
        $artifacts.Artifacts.Clipboard = "Error: $($_.Exception.Message)"
    }

    # Environment variables
    Write-Host "Collecting environment variables..." -ForegroundColor Yellow
    try {
        $envVars = Get-ChildItem Env: | Select-Object Name, Value
        $envVars | Export-Csv (Join-Path $artifactsDir "environment_variables.csv") -NoTypeInformation
        $artifacts.Artifacts.EnvironmentVariables = "Collected"
        Write-Host "[OK] Environment variables collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to collect environment variables: $($_.Exception.Message)"
        $artifacts.Artifacts.EnvironmentVariables = "Error: $($_.Exception.Message)"
    }

    # Recent commands (if available)
    Write-Host "Collecting command history..." -ForegroundColor Yellow
    try {
        $history = Get-History -Count 50 | Select-Object CommandLine, StartExecutionTime, EndExecutionTime
        $history | Export-Csv (Join-Path $artifactsDir "command_history.csv") -NoTypeInformation
        $artifacts.Artifacts.CommandHistory = "Collected"
        Write-Host "[OK] Command history collected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to collect command history: $($_.Exception.Message)"
        $artifacts.Artifacts.CommandHistory = "Error: $($_.Exception.Message)"
    }

    # Save artifacts manifest
    $manifestFile = Join-Path $artifactsDir "artifacts_manifest.json"
    $artifacts | ConvertTo-Json -Depth 3 | Out-File $manifestFile

    Write-Host "Memory artifacts collection complete!" -ForegroundColor Green
    Write-Host "Artifacts saved to: $artifactsDir" -ForegroundColor Cyan

    return $artifactsDir
}