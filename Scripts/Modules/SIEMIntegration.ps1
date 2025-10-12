# SIEMIntegrationFunctions.ps1 - SIEM integration and alerting functions

# Global variables for automation
$script:SIEMIntegrations = @{}

function New-SIEMIntegration {
    <#
    .SYNOPSIS
        Creates a SIEM integration configuration

    .DESCRIPTION
        Configures integration with SIEM systems for automated alerting
        and incident response

    .PARAMETER SIEMType
        Type of SIEM system (Splunk, ELK, QRadar, etc.)

    .PARAMETER Server
        SIEM server hostname or IP

    .PARAMETER Port
        SIEM server port

    .PARAMETER APIKey
        API key for authentication

    .PARAMETER AlertThresholds
        Hash table of alert thresholds

    .EXAMPLE
        New-SIEMIntegration -SIEMType "Splunk" -Server "splunk.company.com" -Port 8088 -APIKey "your-api-key"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Splunk", "ELK", "QRadar", "ArcSight", "Custom")]
        [string]$SIEMType,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [int]$Port = 8088,

        [Parameter(Mandatory = $false)]
        [string]$APIKey,

        [Parameter(Mandatory = $false)]
        [hashtable]$AlertThresholds = @{
            HighSeverity = 8
            MediumSeverity = 5
            LowSeverity = 2
        }
    )

    try {
        $integration = @{
            Type = $SIEMType
            Server = $Server
            Port = $Port
            APIKey = $APIKey
            AlertThresholds = $AlertThresholds
            Created = Get-Date
            Status = "Configured"
        }

        $script:SIEMIntegrations[$SIEMType] = $integration

        Write-Host "Configured SIEM integration: $SIEMType" -ForegroundColor Green
        Write-Host "Server: $Server`:$Port" -ForegroundColor Cyan

        return $integration
    }
    catch {
        Write-Error "Failed to configure SIEM integration: $_"
        return $null
    }
}

function Send-SIEMAlert {
    <#
    .SYNOPSIS
        Sends an alert to configured SIEM systems

    .DESCRIPTION
        Sends forensic findings and alerts to integrated SIEM systems

    .PARAMETER SIEMType
        Type of SIEM system to send alert to

    .PARAMETER AlertData
        Alert data including severity, message, and details

    .EXAMPLE
        Send-SIEMAlert -SIEMType "Splunk" -AlertData @{ Severity = "High"; Message = "Malware detected"; Details = $malwareInfo }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SIEMType,

        [Parameter(Mandatory = $true)]
        [hashtable]$AlertData
    )

    try {
        if (-not $script:SIEMIntegrations.ContainsKey($SIEMType)) {
            throw "SIEM integration '$SIEMType' not configured"
        }

        $integration = $script:SIEMIntegrations[$SIEMType]

        # Check if alert meets threshold
        $severity = $AlertData.Severity
        $threshold = switch ($severity) {
            "High" { $integration.AlertThresholds.HighSeverity }
            "Medium" { $integration.AlertThresholds.MediumSeverity }
            "Low" { $integration.AlertThresholds.LowSeverity }
            default { 0 }
        }

        if ($AlertData.Score -lt $threshold) {
            Write-Host "Alert score ($($AlertData.Score)) below threshold ($threshold) for $severity severity. Skipping SIEM alert." -ForegroundColor Yellow
            return
        }

        # Format alert for SIEM
        $alertPayload = @{
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            source = "PowerShell Forensics"
            severity = $severity
            message = $AlertData.Message
            details = $AlertData.Details
            score = $AlertData.Score
        }

        # Send to SIEM based on type
        switch ($SIEMType) {
            "Splunk" {
                $url = "https://$($integration.Server):$($integration.Port)/services/collector/event"
                $headers = @{
                    "Authorization" = "Splunk $($integration.APIKey)"
                    "Content-Type" = "application/json"
                }

                $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($alertPayload | ConvertTo-Json) -SkipCertificateCheck
                Write-Host "Alert sent to Splunk SIEM" -ForegroundColor Green
            }
            "ELK" {
                $url = "http://$($integration.Server):$($integration.Port)/forensics-alerts/_doc"
                $response = Invoke-RestMethod -Uri $url -Method Post -Body ($alertPayload | ConvertTo-Json) -ContentType "application/json"
                Write-Host "Alert sent to ELK SIEM" -ForegroundColor Green
            }
            default {
                Write-Host "SIEM alert formatted for $SIEMType (custom integration required)" -ForegroundColor Yellow
                return $alertPayload
            }
        }

        return $true
    }
    catch {
        Write-Error "Failed to send SIEM alert: $_"
        return $false
    }
}