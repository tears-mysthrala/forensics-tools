# ResponseReporting.ps1
# Incident response reporting functions

<#
.SYNOPSIS
    Incident Response Reporting Functions

.DESCRIPTION
    This module provides functions for generating incident response reports.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Get-IncidentResponseReport {
    <#
    .SYNOPSIS
        Generates an incident response summary report

    .DESCRIPTION
        Creates a comprehensive report of incident response activities and effectiveness

    .PARAMETER Cases
        Array of incident cases to include

    .PARAMETER Playbooks
        Array of playbooks to include

    .PARAMETER OutputPath
        Path for the HTML report

    .EXAMPLE
        Get-IncidentResponseReport -Cases $cases -Playbooks $playbooks -OutputPath "C:\Reports\incident-response-summary.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Cases,

        [Parameter(Mandatory = $true)]
        [array]$Playbooks,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Generating incident response summary report..." -ForegroundColor Cyan

        # Calculate statistics
        $totalCases = $Cases.Count
        $openCases = ($Cases | Where-Object { $_.Status -eq "Open" }).Count
        $resolvedCases = ($Cases | Where-Object { $_.Status -eq "Resolved" -or $_.Status -eq "Closed" }).Count
        $avgResolutionTime = 0

        if ($resolvedCases -gt 0) {
            $resolvedCasesList = $Cases | Where-Object { $_.Resolved }
            $totalResolutionTime = ($resolvedCasesList | ForEach-Object { ($_.Resolved - $_.Created).TotalHours } | Measure-Object -Sum).Sum
            $avgResolutionTime = $totalResolutionTime / $resolvedCases.Count
        }

        $severityBreakdown = $Cases | Group-Object -Property Severity | Select-Object Name, Count

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>🚨 Incident Response Summary Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .section { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section-header { background: #ff6b6b; color: white; padding: 15px; margin: 0; border-radius: 8px 8px 0 0; }
        .section-content { padding: 20px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; color: #ff6b6b; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #ffeaa7; }
        .status-open { background-color: #e74c3c; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-investigating { background-color: #f39c12; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-contained { background-color: #3498db; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-resolved { background-color: #27ae60; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-closed { background-color: #95a5a6; color: white; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Incident Response Summary Report</h1>
        <h2>Automated Response System Overview</h2>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>

    <div class="metrics-grid">
        <div class="metric">
            <h3>Total Cases</h3>
            <div class="value">$totalCases</div>
        </div>
        <div class="metric">
            <h3>Open Cases</h3>
            <div class="value">$openCases</div>
        </div>
        <div class="metric">
            <h3>Resolved Cases</h3>
            <div class="value">$resolvedCases</div>
        </div>
        <div class="metric">
            <h3>Avg Resolution Time</h3>
            <div class="value">$([math]::Round($avgResolutionTime, 1))h</div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-header">📊 Severity Breakdown</h2>
        <div class="section-content">
            <table>
                <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
"@

        foreach ($severity in $severityBreakdown) {
            $percentage = [math]::Round(($severity.Count / $totalCases) * 100, 1)
            $html += @"
                <tr><td>$($severity.Name)</td><td>$($severity.Count)</td><td>$percentage%</td></tr>
"@
        }

        $html += @"
            </table>
        </div>
    </div>

    <div class="section">
        <h2 class="section-header">📋 Recent Cases</h2>
        <div class="section-content">
            <table>
                <tr>
                    <th>Case ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Assigned To</th>
                </tr>
"@

        foreach ($case in $Cases | Sort-Object Created -Descending | Select-Object -First 20) {
            $html += @"
                <tr>
                    <td>$($case.CaseId)</td>
                    <td>$($case.Title)</td>
                    <td>$($case.Severity)</td>
                    <td><span class="status-$($case.Status.ToLower())">$($case.Status)</span></td>
                    <td>$($case.Created.ToString('yyyy-MM-dd HH:mm'))</td>
                    <td>$($case.AssignedTo)</td>
                </tr>
"@
        }

        $html += @"
            </table>
        </div>
    </div>

    <div class="section">
        <h2 class="section-header">📚 Active Playbooks</h2>
        <div class="section-content">
            <table>
                <tr>
                    <th>Name</th>
                    <th>Category</th>
                    <th>Triggers</th>
                    <th>Steps</th>
                    <th>Version</th>
                </tr>
"@

        foreach ($playbook in $Playbooks) {
            $html += @"
                <tr>
                    <td>$($playbook.Name)</td>
                    <td>$($playbook.Category)</td>
                    <td>$($playbook.Triggers.Count)</td>
                    <td>$($playbook.Steps.Count)</td>
                    <td>$($playbook.Version)</td>
                </tr>
"@
        }

        $html += @"
            </table>
        </div>
    </div>
</body>
</html>
"@

        $html | Out-File $OutputPath -Encoding UTF8

        Write-Host "Incident response summary report generated: $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to generate incident response report: $($_.Exception.Message)"
        return $false
    }
}