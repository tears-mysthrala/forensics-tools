# MobileDeviceReportingFunctions.ps1
# Mobile device forensics reporting functions

<#
.SYNOPSIS
    Mobile Device Reporting Functions

.DESCRIPTION
    This module provides functions for generating comprehensive reports
    from mobile device forensics data including Android and iOS analysis.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Export-MobileDeviceReport {
    <#
    .SYNOPSIS
        Generates comprehensive mobile device forensics report

    .DESCRIPTION
        Creates HTML report combining all mobile device evidence

    .PARAMETER DeviceData
        Array of mobile device data objects

    .PARAMETER OutputPath
        Path for the HTML report

    .EXAMPLE
        $androidData = Get-AndroidDeviceInfo
        $smsData = Get-AndroidSMSMessages -DeviceId $androidData.DeviceId -OutputPath "temp.json"
        Export-MobileDeviceReport -DeviceData @($androidData, $smsData) -OutputPath "C:\Evidence\mobile_report.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$DeviceData,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Generating mobile device forensics report..." -ForegroundColor Cyan

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>🔍 Mobile Device Forensics Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .section { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section-header { background: #667eea; color: white; padding: 15px; margin: 0; border-radius: 8px 8px 0 0; }
        .section-content { padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; color: #667eea; }
        .message-preview { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📱 Mobile Device Forensics Report</h1>
        <h2>Digital Evidence Analysis</h2>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>

    <div class="summary">
"@

        # Calculate summary metrics
        $totalMessages = 0
        $totalContacts = 0
        $totalCalls = 0
        $deviceType = "Unknown"

        foreach ($data in $DeviceData) {
            if ($data.PSObject.Properties.Name -contains "SMSMessages") {
                $totalMessages += $data.SMSMessages.Count
            }
            if ($data.PSObject.Properties.Name -contains "MMSMessages") {
                $totalMessages += $data.MMSMessages.Count
            }
            if ($data.PSObject.Properties.Name -contains "Messages") {
                $totalMessages += $data.Messages.Count
            }
            if ($data.PSObject.Properties.Name -contains "Contacts") {
                $totalContacts += $data.Contacts.Count
            }
            if ($data.PSObject.Properties.Name -contains "CallLogs") {
                $totalCalls += $data.CallLogs.Count
            }
            if ($data.PSObject.Properties.Name -contains "HardwareInfo") {
                $deviceType = "Android"
            }
            if ($data.PSObject.Properties.Name -contains "BackupPath") {
                $deviceType = "iOS"
            }
        }

        $html += @"
        <div class="metric">
            <h3>Device Type</h3>
            <div class="value">$deviceType</div>
        </div>
        <div class="metric">
            <h3>Messages</h3>
            <div class="value">$totalMessages</div>
        </div>
        <div class="metric">
            <h3>Contacts</h3>
            <div class="value">$totalContacts</div>
        </div>
        <div class="metric">
            <h3>Call Records</h3>
            <div class="value">$totalCalls</div>
        </div>
    </div>
"@

        # Device Information Section
        foreach ($data in $DeviceData) {
            if ($data.PSObject.Properties.Name -contains "HardwareInfo") {
                $html += @"

    <div class="section">
        <h2 class="section-header">📱 Device Information</h2>
        <div class="section-content">
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Device ID</td><td>$($data.DeviceId)</td></tr>
                <tr><td>Model</td><td>$($data.HardwareInfo.Model)</td></tr>
                <tr><td>Manufacturer</td><td>$($data.HardwareInfo.Manufacturer)</td></tr>
                <tr><td>Android Version</td><td>$($data.HardwareInfo.AndroidVersion)</td></tr>
                <tr><td>API Level</td><td>$($data.HardwareInfo.APILevel)</td></tr>
                <tr><td>Build Number</td><td>$($data.HardwareInfo.BuildNumber)</td></tr>
            </table>
        </div>
    </div>
"@
            }
        }

        # Messages Section
        foreach ($data in $DeviceData) {
            if ($data.PSObject.Properties.Name -contains "SMSMessages" -and $data.SMSMessages.Count -gt 0) {
                $html += @"

    <div class="section">
        <h2 class="section-header">💬 SMS Messages ($($data.SMSMessages.Count))</h2>
        <div class="section-content">
            <table>
                <tr>
                    <th>Date</th>
                    <th>Address</th>
                    <th>Type</th>
                    <th>Message</th>
                </tr>
"@

                foreach ($message in $data.SMSMessages | Select-Object -First 50) {
                    $typeText = switch ($message.Type) {
                        1 { "Received" }
                        2 { "Sent" }
                        default { "Unknown" }
                    }
                    $html += @"
                <tr>
                    <td>$($message.Date.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                    <td>$($message.Address)</td>
                    <td>$typeText</td>
                    <td class="message-preview">$($message.Body)</td>
                </tr>
"@
                }

                $html += @"
            </table>
        </div>
    </div>
"@
            }
        }

        # Contacts Section
        foreach ($data in $DeviceData) {
            if ($data.PSObject.Properties.Name -contains "Contacts" -and $data.Contacts.Count -gt 0) {
                $html += @"

    <div class="section">
        <h2 class="section-header">👥 Contacts ($($data.Contacts.Count))</h2>
        <div class="section-content">
            <table>
                <tr>
                    <th>Name</th>
                    <th>Phone Numbers</th>
                    <th>Emails</th>
                    <th>Last Contacted</th>
                </tr>
"@

                foreach ($contact in $data.Contacts | Select-Object -First 50) {
                    $phones = if ($contact.PhoneNumbers) { $contact.PhoneNumbers -join "; " } else { "" }
                    $emails = if ($contact.Emails) { $contact.Emails -join "; " } else { "" }
                    $name = if ($contact.DisplayName) { $contact.DisplayName } elseif ($contact.FirstName -or $contact.LastName) { "$($contact.FirstName) $($contact.LastName)".Trim() } else { "Unknown" }
                    $lastContact = if ($contact.LastTimeContacted) { $contact.LastTimeContacted.ToString('yyyy-MM-dd HH:mm:ss') } else { "Never" }

                    $html += @"
                <tr>
                    <td>$name</td>
                    <td>$phones</td>
                    <td>$emails</td>
                    <td>$lastContact</td>
                </tr>
"@
                }

                $html += @"
            </table>
        </div>
    </div>
"@
            }
        }

        $html += @"
</body>
</html>
"@

        $html | Out-File $OutputPath -Encoding UTF8

        Write-Host "Mobile device forensics report generated: $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to generate mobile device report: $($_.Exception.Message)"
        return $false
    }
}