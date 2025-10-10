# EvidenceReporting.ps1
# Functions for generating evidence reports

<#
.SYNOPSIS
    Evidence Reporting Functions

.DESCRIPTION
    This file contains functions for generating reports including:
    - Export-EvidenceReport: Creates HTML reports for evidence items

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
    Depends on: EvidenceClasses.ps1
#>

function Export-EvidenceReport {
    <#
    .SYNOPSIS
        Generates a comprehensive evidence report

    .DESCRIPTION
        Creates detailed HTML reports for evidence items including metadata, chain of custody, and integrity information

    .PARAMETER Evidence
        Array of evidence items to include

    .PARAMETER OutputPath
        Path for the HTML report

    .PARAMETER IncludeChainOfCustody
        Whether to include full chain of custody details

    .EXAMPLE
        Export-EvidenceReport -Evidence $evidenceItems -OutputPath "C:\Reports\evidence-report.html" -IncludeChainOfCustody
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeChainOfCustody
    )

    try {
        Write-Host "Generating evidence report for $($Evidence.Count) items..." -ForegroundColor Cyan

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>🔐 Evidence Management Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .evidence-card { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .evidence-header { background: #3498db; color: white; padding: 15px; margin: 0; }
        .evidence-content { padding: 20px; }
        .evidence-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; color: #3498db; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .hash-section { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .status-verified { background-color: #27ae60; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-unverified { background-color: #e74c3c; color: white; padding: 2px 6px; border-radius: 3px; }
        .coc-timeline { position: relative; padding-left: 30px; }
        .coc-entry { margin-bottom: 15px; padding: 10px; border-left: 3px solid #3498db; background-color: #ecf0f1; }
        .coc-entry:before { content: '📋'; position: absolute; left: -5px; background: white; border-radius: 50%; width: 20px; height: 20px; text-align: center; line-height: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Evidence Management Report</h1>
        <h2>Chain of Custody & Integrity Verification</h2>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | <strong>Total Items:</strong> $($Evidence.Count)</p>
    </div>

    <div class="evidence-grid">
        <div class="metric">
            <h3>Total Evidence</h3>
            <div class="value">$($Evidence.Count)</div>
        </div>
        <div class="metric">
            <h3>Verified Items</h3>
            <div class="value">$($Evidence | Where-Object { $_.IsVerified }).Count)</div>
        </div>
        <div class="metric">
            <h3>Total Size</h3>
            <div class="value">$([math]::Round(($Evidence | Measure-Object -Property Size -Sum).Sum / 1MB, 2)) MB</div>
        </div>
        <div class="metric">
            <h3>Cases</h3>
            <div class="value">$($Evidence | Select-Object -Property CaseId -Unique | Measure-Object).Count</div>
        </div>
    </div>
"@

        foreach ($item in $Evidence) {
            if ($item.IsVerified) {
                $statusClass = "status-verified"
                $statusText = "Verified"
            } else {
                $statusClass = "status-unverified"
                $statusText = "Unverified"
            }

            $html += @"

    <div class="evidence-card">
        <h2 class="evidence-header">📄 $($item.Name) - $($item.EvidenceId)</h2>
        <div class="evidence-content">
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Case ID</td><td>$($item.CaseId)</td></tr>
                <tr><td>Description</td><td>$($item.Description)</td></tr>
                <tr><td>Type</td><td>$($item.Type)</td></tr>
                <tr><td>Status</td><td><span class="$statusClass">$statusText</span></td></tr>
                <tr><td>Size</td><td>$([math]::Round($item.Size / 1MB, 2)) MB</td></tr>
                <tr><td>Collected</td><td>$($item.Collected.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
                <tr><td>Collected By</td><td>$($item.CollectedBy)</td></tr>
                <tr><td>Last Verified</td><td>$($item.LastVerified.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
                <tr><td>Source</td><td>$($item.Source)</td></tr>
                <tr><td>Storage Location</td><td>$($item.StorageLocation)</td></tr>
            </table>

            <div class="hash-section">
                <h4>🔒 Cryptographic Hashes</h4>
                <strong>SHA256:</strong> $($item.HashSHA256)<br>
                <strong>SHA1:</strong> $($item.HashSHA1)<br>
                <strong>MD5:</strong> $($item.HashMD5)
            </div>
"@

            if ($IncludeChainOfCustody -and $item.ChainOfCustody -and $item.ChainOfCustody.Count -gt 0) {
                $html += @"
            <h4>⛓️ Chain of Custody</h4>
            <div class="coc-timeline">
"@

                foreach ($coc in $item.ChainOfCustody | Sort-Object Timestamp) {
                    $html += @"
                <div class="coc-entry">
                    <strong>$($coc.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</strong><br>
                    <strong>Action:</strong> $($coc.Action)<br>
                    <strong>Performed By:</strong> $($coc.PerformedBy)<br>
                    <strong>Reason:</strong> $($coc.Reason)<br>
"@

                    if ($coc.FromLocation) {
                        $html += "<strong>From:</strong> $($coc.FromLocation)<br>"
                    }
                    if ($coc.ToLocation) {
                        $html += "<strong>To:</strong> $($coc.ToLocation)<br>"
                    }
                    if ($coc.AuthorizedBy -and $coc.AuthorizedBy -ne $coc.PerformedBy) {
                        $html += "<strong>Authorized By:</strong> $($coc.AuthorizedBy)<br>"
                    }

                    $html += @"
                </div>
"@
                }

                $html += @"
            </div>
"@
            }

            if ($item.Tags -and $item.Tags.Count -gt 0) {
                $html += @"
            <h4>🏷️ Tags</h4>
            <p>$($item.Tags -join ", ")</p>
"@
            }

            $html += @"
        </div>
    </div>
"@
        }

        $html += @"
</body>
</html>
"@

        $html | Out-File $OutputPath -Encoding UTF8

        Write-Host "Evidence report generated: $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to generate evidence report: $($_.Exception.Message)"
        return $false
    }
}