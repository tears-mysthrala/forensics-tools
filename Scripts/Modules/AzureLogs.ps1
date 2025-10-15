# AzureLogs.ps1
# Azure activity logs collection functions for cloud forensics

<#
.SYNOPSIS
    Azure Logs Functions

.DESCRIPTION
    This module provides Azure activity logs collection capabilities for cloud forensics:
    - Get-AzureActivityLogs: Retrieves Azure activity logs, audit events, and administrative actions

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function Get-AzureActivityLogs {
    <#
    .SYNOPSIS
        Collects Azure activity logs for forensic analysis.
    .DESCRIPTION
        Retrieves Azure activity logs, audit events, and administrative actions.
    .PARAMETER SubscriptionId
        Azure subscription ID.
    .PARAMETER Days
        Number of days of logs to retrieve.
    .PARAMETER OutputPath
        Directory to save log results.
    .EXAMPLE
        Get-AzureActivityLogs -SubscriptionId "12345678-1234-1234-1234-123456789012" -Days 30 -OutputPath C:\AzureLogs
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        [int]$Days = 7,
        [string]$OutputPath = "."
    )

    Write-Host "Collecting Azure activity logs..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logsDir = Join-Path $OutputPath "AzureActivityLogs_$timestamp"

    if (-not (Test-Path $logsDir)) {
        New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    }

    $logsResults = @{
        Timestamp      = Get-Date
        SubscriptionId = $SubscriptionId
        Days           = $Days
        Logs           = @()
    }

    # Check Azure CLI
    $azCli = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCli) {
        Write-Error "Azure CLI required for activity log collection. Please install from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        return $null
    }

    try {
        # Set subscription
        az account set --subscription $SubscriptionId

        # Calculate date range
        $endDate = Get-Date
        $startDate = $endDate.AddDays(-$Days)
        $startDateStr = $startDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $endDateStr = $endDate.ToString("yyyy-MM-ddTHH:mm:ssZ")

        Write-Host "Retrieving activity logs from $startDateStr to $endDateStr..." -ForegroundColor Yellow

        # Get activity logs
        $logsOutput = az monitor activity-log list --start-time $startDateStr --end-time $endDateStr --output json

        if ($logsOutput) {
            $logs = $logsOutput | ConvertFrom-Json

            foreach ($log in $logs) {
                $logsResults.Logs += @{
                    Timestamp     = $log.eventTimestamp
                    Level         = $log.level
                    OperationName = $log.operationName
                    ResourceType  = $log.resourceType
                    ResourceGroup = $log.resourceGroupName
                    Resource      = $log.resource
                    Status        = $log.status.value
                    Caller        = $log.caller
                    CorrelationId = $log.correlationId
                    Category      = $log.category.value
                    Properties    = $log.properties
                }
            }

            Write-Host "[OK] Retrieved $($logs.Count) activity log entries" -ForegroundColor Green
        }
        else {
            Write-Host "[OK] No activity logs found in the specified time range" -ForegroundColor Green
        }

    }
    catch {
        Write-Warning "Failed to collect activity logs: $($_.Exception.Message)"
        $logsResults.Error = $_.Exception.Message
    }

    # Export results
    $resultsFile = Join-Path $logsDir "azure_activity_logs.json"
    $logsResults | ConvertTo-Json -Depth 4 | Out-File $resultsFile

    # Create summary CSV
    $csvData = $logsResults.Logs | ForEach-Object {
        [PSCustomObject]@{
            Timestamp     = $_.Timestamp
            Level         = $_.Level
            OperationName = $_.OperationName
            ResourceType  = $_.ResourceType
            ResourceGroup = $_.ResourceGroup
            Status        = $_.Status
            Caller        = $_.Caller
        }
    }

    if ($csvData) {
        $csvData | Export-Csv (Join-Path $logsDir "activity_logs_summary.csv") -NoTypeInformation
    }

    Write-Host "Azure activity logs collection complete!" -ForegroundColor Green
    Write-Host "Log entries: $($logsResults.Logs.Count)" -ForegroundColor Cyan
    Write-Host "Results saved to: $logsDir" -ForegroundColor Cyan

    return $logsDir
}