# StandardPlaybooks.ps1
# Standard incident response playbook creation functions

<#
.SYNOPSIS
    Standard Playbook Creation Functions for Incident Response

.DESCRIPTION
    This module provides functions for creating predefined incident response playbooks.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function New-StandardPlaybooks {
    <#
    .SYNOPSIS
        Creates standard incident response playbooks

    .DESCRIPTION
        Generates predefined playbooks for common incident types

    .PARAMETER Type
        Type of playbook to create (Malware, Phishing, DDoS, DataBreach, UnauthorizedAccess)

    .EXAMPLE
        $malwarePlaybook = New-StandardPlaybooks -Type "Malware"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Malware", "Phishing", "DDoS", "DataBreach", "UnauthorizedAccess")]
        [string]$Type
    )

    try {
        Write-Host "Creating standard $Type response playbook" -ForegroundColor Cyan

        switch ($Type) {
            "Malware" {
                $playbook = New-IncidentResponsePlaybook -Name "Malware Infection Response" -Description "Automated response to malware infections" -Category "Malware" -Author "Security Team"

                Add-PlaybookTrigger -Playbook $playbook -Type "EventLog" -Condition "EventID=1001 AND Source='Microsoft-Windows-Windows Defender'" -Parameters @{LogName = "System" }

                Add-PlaybookStep -Playbook $playbook -Name "Isolate Infected Host" -Action "Invoke-NetworkIsolation" -Parameters @{TargetHost = '${TargetHost}' }
                Add-PlaybookStep -Playbook $playbook -Name "Collect Memory Dump" -Action "Invoke-MemoryDump" -Parameters @{TargetHost = '${TargetHost}' }
                Add-PlaybookStep -Playbook $playbook -Name "Scan for Malware" -Action "Invoke-MalwareScan" -Parameters @{TargetHost = '${TargetHost}' }
                Add-PlaybookStep -Playbook $playbook -Name "Quarantine Files" -Action "Invoke-FileQuarantine" -Parameters @{TargetHost = '${TargetHost}' }
                Add-PlaybookStep -Playbook $playbook -Name "Update Signatures" -Action "Update-SecuritySignatures" -Parameters @{TargetHost = '${TargetHost}' }
            }

            "Phishing" {
                $playbook = New-IncidentResponsePlaybook -Name "Phishing Incident Response" -Description "Response to phishing attacks and credential theft" -Category "Phishing" -Author "Security Team"

                Add-PlaybookTrigger -Playbook $playbook -Type "EventLog" -Condition "EventID=4625" -Parameters @{LogName = "Security" }

                Add-PlaybookStep -Playbook $playbook -Name "Reset Compromised Credentials" -Action "Reset-UserCredentials" -Parameters @{Username = '${Username}' }
                Add-PlaybookStep -Playbook $playbook -Name "Check for Lateral Movement" -Action "Invoke-LateralMovementCheck" -Parameters @{Username = '${Username}' }
                Add-PlaybookStep -Playbook $playbook -Name "Review Email Logs" -Action "Search-EmailLogs" -Parameters @{Username = '${Username}' }
                Add-PlaybookStep -Playbook $playbook -Name "Enable MFA" -Action "Enable-MultiFactorAuth" -Parameters @{Username = '${Username}' }
            }

            "DDoS" {
                $playbook = New-IncidentResponsePlaybook -Name "DDoS Attack Response" -Description "Response to distributed denial of service attacks" -Category "Network" -Author "Security Team"

                Add-PlaybookTrigger -Playbook $playbook -Type "Network" -Condition "TrafficSpike > 1000%" -Parameters @{Interface = '${Interface}' }

                Add-PlaybookStep -Playbook $playbook -Name "Enable DDoS Protection" -Action "Enable-DDoSProtection" -Parameters @{Target = '${Target}' }
                Add-PlaybookStep -Playbook $playbook -Name "Scale Resources" -Action "Scale-Resources" -Parameters @{Service = '${Service}' }
                Add-PlaybookStep -Playbook $playbook -Name "Block Attack Sources" -Action "Block-IPRanges" -Parameters @{IPRanges = '${AttackSources}' }
                Add-PlaybookStep -Playbook $playbook -Name "Notify ISP" -Action "Send-ISPNotification" -Parameters @{AttackDetails = '${AttackDetails}' }
            }

            "DataBreach" {
                $playbook = New-IncidentResponsePlaybook -Name "Data Breach Response" -Description "Response to data breaches and unauthorized data access" -Category "Data" -Author "Security Team"

                Add-PlaybookTrigger -Playbook $playbook -Type "FileSystem" -Condition "UnauthorizedFileAccess" -Parameters @{FilePath = '${FilePath}' }

                Add-PlaybookStep -Playbook $playbook -Name "Assess Breach Scope" -Action "Assess-BreachScope" -Parameters @{AffectedData = '${AffectedData}' }
                Add-PlaybookStep -Playbook $playbook -Name "Contain Breach" -Action "Invoke-BreachContainment" -Parameters @{AffectedSystems = '${AffectedSystems}' }
                Add-PlaybookStep -Playbook $playbook -Name "Notify Affected Parties" -Action "Send-BreachNotification" -Parameters @{Recipients = '${Recipients}' }
                Add-PlaybookStep -Playbook $playbook -Name "Preserve Evidence" -Action "Invoke-EvidencePreservation" -Parameters @{Evidence = '${Evidence}' }
            }

            "UnauthorizedAccess" {
                $playbook = New-IncidentResponsePlaybook -Name "Unauthorized Access Response" -Description "Response to unauthorized system access attempts" -Category "Access" -Author "Security Team"

                Add-PlaybookTrigger -Playbook $playbook -Type "EventLog" -Condition "EventID=4625 OR EventID=4648" -Parameters @{LogName = "Security" }

                Add-PlaybookStep -Playbook $playbook -Name "Block Suspicious IP" -Action "Block-IPAddress" -Parameters @{IPAddress = '${IPAddress}' }
                Add-PlaybookStep -Playbook $playbook -Name "Review Access Logs" -Action "Review-AccessLogs" -Parameters @{Username = '${Username}' }
                Add-PlaybookStep -Playbook $playbook -Name "Change Access Credentials" -Action "Change-AccessCredentials" -Parameters @{Resource = '${Resource}' }
                Add-PlaybookStep -Playbook $playbook -Name "Enable Enhanced Monitoring" -Action "Enable-EnhancedMonitoring" -Parameters @{Target = '${Target}' }
            }
        }

        Write-Host "Standard $Type playbook created with $($playbook.Steps.Count) steps" -ForegroundColor Green
        return $playbook
    }
    catch {
        Write-Error "Failed to create standard playbook: $($_.Exception.Message)"
        return $null
    }
}