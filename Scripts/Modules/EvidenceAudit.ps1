# EvidenceAudit.ps1
# Functions for auditing evidence integrity and compliance

<#
.SYNOPSIS
    Evidence Audit Functions

.DESCRIPTION
    This file contains functions for auditing evidence including:
    - Invoke-EvidenceAudit: Performs comprehensive integrity audits

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
    Depends on: EvidenceClasses.ps1, EvidenceVerification.ps1, EvidenceRepository.ps1
#>

function Invoke-EvidenceAudit {
    <#
    .SYNOPSIS
        Performs a comprehensive audit of evidence integrity

    .DESCRIPTION
        Audits all evidence in a repository or collection for integrity and chain of custody compliance

    .PARAMETER Evidence
        Array of evidence items to audit

    .PARAMETER Repository
        Repository to audit (alternative to Evidence parameter)

    .PARAMETER OutputPath
        Path for the audit report

    .EXAMPLE
        Invoke-EvidenceAudit -Evidence $evidenceItems -OutputPath "C:\Reports\evidence-audit.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$Evidence,

        [Parameter(Mandatory = $false)]
        [EvidenceRepository]$Repository,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Performing evidence integrity audit..." -ForegroundColor Cyan

        # Get evidence to audit
        if ($Repository) {
            $evidenceToAudit = @()
            foreach ($evidenceId in $Repository.EvidenceItems) {
                $evidence = Get-EvidenceFromRepository -Repository $Repository -EvidenceId $evidenceId
                if ($evidence) {
                    $evidenceToAudit += $evidence
                }
            }
        } elseif ($Evidence) {
            $evidenceToAudit = $Evidence
        } else {
            throw "Either Evidence or Repository parameter must be specified"
        }

        $auditResults = @()
        $totalItems = $evidenceToAudit.Count
        $verifiedItems = 0
        $failedItems = 0
        $missingItems = 0

        foreach ($item in $evidenceToAudit) {
            $auditResult = [PSCustomObject]@{
                EvidenceId = $item.EvidenceId
                Name = $item.Name
                IntegrityVerified = $false
                FileExists = $false
                ChainOfCustodyComplete = $false
                LastAudit = Get-Date
                Issues = @()
            }

            # Check if file exists
            if (Test-Path $item.Path) {
                $auditResult.FileExists = $true

                # Verify integrity
                $isValid = Verify-EvidenceIntegrity -Evidence $item
                $auditResult.IntegrityVerified = $isValid

                if ($isValid) {
                    $verifiedItems++
                } else {
                    $failedItems++
                    $auditResult.Issues += "Integrity verification failed"
                }
            } else {
                $missingItems++
                $auditResult.Issues += "Evidence file not found"
            }

            # Check chain of custody
            if ($item.ChainOfCustody -and $item.ChainOfCustody.Count -gt 0) {
                $auditResult.ChainOfCustodyComplete = $true
            } else {
                $auditResult.Issues += "Incomplete chain of custody"
            }

            $auditResults += $auditResult
        }

        # Generate audit report
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>🔍 Evidence Integrity Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; }
        .metric .value-good { color: #27ae60; }
        .metric .value-warning { color: #f39c12; }
        .metric .value-bad { color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #34495e; color: white; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .status-good { background-color: #27ae60; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-warning { background-color: #f39c12; color: white; padding: 2px 6px; border-radius: 3px; }
        .status-bad { background-color: #e74c3c; color: white; padding: 2px 6px; border-radius: 3px; }
        .issues { color: #e74c3c; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Evidence Integrity Audit Report</h1>
        <h2>Security & Compliance Verification</h2>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | <strong>Total Items Audited:</strong> $totalItems</p>
    </div>

    <div class="summary-grid">
        <div class="metric">
            <h3>Verified Items</h3>
            <div class="value value-good">$verifiedItems</div>
        </div>
        <div class="metric">
            <h3>Failed Items</h3>
            <div class="value value-bad">$failedItems</div>
        </div>
        <div class="metric">
            <h3>Missing Items</h3>
            <div class="value value-warning">$missingItems</div>
        </div>
        <div class="metric">
            <h3>Success Rate</h3>
            <div class="value $(if (($verifiedItems / $totalItems) -gt 0.95) { 'value-good' } elseif (($verifiedItems / $totalItems) -gt 0.80) { 'value-warning' } else { 'value-bad' })">$([math]::Round(($verifiedItems / $totalItems) * 100, 1))%</div>
        </div>
    </div>

    <table>
        <tr>
            <th>Evidence ID</th>
            <th>Name</th>
            <th>File Exists</th>
            <th>Integrity</th>
            <th>Chain of Custody</th>
            <th>Issues</th>
        </tr>
"@

        foreach ($result in $auditResults) {
            if ($result.FileExists) {
                $fileStatus = "<span class='status-good'>Yes</span>"
            } else {
                $fileStatus = "<span class='status-bad'>No</span>"
            }
            if ($result.IntegrityVerified) {
                $integrityStatus = "<span class='status-good'>Verified</span>"
            } else {
                $integrityStatus = "<span class='status-bad'>Failed</span>"
            }
            if ($result.ChainOfCustodyComplete) {
                $cocStatus = "<span class='status-good'>Complete</span>"
            } else {
                $cocStatus = "<span class='status-warning'>Incomplete</span>"
            }
            $issues = $result.Issues -join "; "

            $html += @"
        <tr>
            <td>$($result.EvidenceId)</td>
            <td>$($result.Name)</td>
            <td>$fileStatus</td>
            <td>$integrityStatus</td>
            <td>$cocStatus</td>
            <td class="issues">$issues</td>
        </tr>
"@
        }

        $html += @"
    </table>
</body>
</html>
"@

        $html | Out-File $OutputPath -Encoding UTF8

        Write-Host "Evidence audit completed. Report generated: $OutputPath" -ForegroundColor Green
        Write-Host "Results: $verifiedItems verified, $failedItems failed, $missingItems missing" -ForegroundColor $(if ($failedItems -eq 0 -and $missingItems -eq 0) { "Green" } else { "Yellow" })

        return [PSCustomObject]@{
            TotalItems = $totalItems
            VerifiedItems = $verifiedItems
            FailedItems = $failedItems
            MissingItems = $missingItems
            SuccessRate = [math]::Round(($verifiedItems / $totalItems) * 100, 2)
            AuditResults = $auditResults
            ReportPath = $OutputPath
        }
    }
    catch {
        Write-Error "Failed to perform evidence audit: $($_.Exception.Message)"
        return $null
    }
}