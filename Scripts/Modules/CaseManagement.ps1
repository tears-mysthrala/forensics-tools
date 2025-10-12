# CaseManagementFunctions.ps1
# Incident case management and tracking functions

<#
.SYNOPSIS
    Case Management Functions for Incident Response

.DESCRIPTION
    This module provides functions for creating, managing, and tracking
    incident cases including timeline management, evidence collection, and reporting.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

# Incident Response Classes

class IncidentCase {
    [string]$CaseId
    [string]$Title
    [string]$Description
    [string]$Severity
    [string]$Status
    [string]$Category
    [DateTime]$Created
    [DateTime]$Modified
    [DateTime]$Resolved
    [string]$AssignedTo
    [array]$Tags
    [array]$Evidence
    [array]$Timeline
    [hashtable]$Metadata
    [array]$RelatedCases

    IncidentCase() {
        $this.CaseId = "IR-" + (Get-Date -Format "yyyyMMdd-HHmmss")
        $this.Created = Get-Date
        $this.Modified = Get-Date
        $this.Status = "Open"
        $this.Tags = @()
        $this.Evidence = @()
        $this.Timeline = @()
        $this.Metadata = @{}
        $this.RelatedCases = @()
    }
}

# Case Management Functions

function New-IncidentCase {
    <#
    .SYNOPSIS
        Creates a new incident case

    .DESCRIPTION
        Initializes a new incident case for tracking and management

    .PARAMETER Title
        Title of the incident case

    .PARAMETER Description
        Description of the incident

    .PARAMETER Severity
        Severity level (Critical, High, Medium, Low, Info)

    .PARAMETER Category
        Category of the incident

    .PARAMETER AssignedTo
        Person assigned to handle the case

    .EXAMPLE
        $case = New-IncidentCase -Title "Suspicious Login Attempts" -Severity "High" -Category "Authentication"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [string]$Description = "",

        [Parameter(Mandatory = $true)]
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [string]$AssignedTo = ""
    )

    try {
        Write-Host "Creating new incident case: $Title" -ForegroundColor Cyan

        $case = [IncidentCase]::new()
        $case.Title = $Title
        $case.Description = $Description
        $case.Severity = $Severity
        $case.Category = $Category
        $case.AssignedTo = $AssignedTo

        # Add initial timeline entry
        Add-CaseTimelineEntry -Case $case -EntryType "Created" -Description "Incident case created" -User $env:USERNAME

        Write-Host "Incident case created with ID: $($case.CaseId)" -ForegroundColor Green
        return $case
    }
    catch {
        Write-Error "Failed to create incident case: $($_.Exception.Message)"
        return $null
    }
}

function Add-CaseTimelineEntry {
    <#
    .SYNOPSIS
        Adds an entry to the incident case timeline

    .DESCRIPTION
        Records an event or action in the case timeline for audit and tracking

    .PARAMETER Case
        The incident case object

    .PARAMETER EntryType
        Type of timeline entry (Created, Updated, Evidence, Action, Comment)

    .PARAMETER Description
        Description of the timeline entry

    .PARAMETER User
        User who performed the action

    .PARAMETER Evidence
        Associated evidence files or data

    .EXAMPLE
        Add-CaseTimelineEntry -Case $case -EntryType "Evidence" -Description "Collected system logs" -User "Analyst"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IncidentCase]$Case,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Created", "Updated", "Evidence", "Action", "Comment", "StatusChange")]
        [string]$EntryType,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [string]$User = $env:USERNAME,

        [Parameter(Mandatory = $false)]
        [array]$Evidence = @()
    )

    try {
        $timelineEntry = [PSCustomObject]@{
            Timestamp = Get-Date
            EntryType = $EntryType
            Description = $Description
            User = $User
            Evidence = $Evidence
        }

        $Case.Timeline += $timelineEntry
        $Case.Modified = Get-Date

        Write-Host "Added timeline entry to case $($Case.CaseId): $Description" -ForegroundColor Gray
        return $timelineEntry
    }
    catch {
        Write-Error "Failed to add timeline entry: $($_.Exception.Message)"
        return $null
    }
}

function Add-CaseEvidence {
    <#
    .SYNOPSIS
        Adds evidence to an incident case

    .DESCRIPTION
        Associates evidence files or data with an incident case

    .PARAMETER Case
        The incident case object

    .PARAMETER EvidencePath
        Path to the evidence file

    .PARAMETER Description
        Description of the evidence

    .PARAMETER Type
        Type of evidence (File, Memory, Network, Log, etc.)

    .PARAMETER Hash
        Hash of the evidence for integrity verification

    .EXAMPLE
        Add-CaseEvidence -Case $case -EvidencePath "C:\Evidence\malware.exe" -Description "Suspicious executable" -Type "File"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IncidentCase]$Case,

        [Parameter(Mandatory = $true)]
        [string]$EvidencePath,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [string]$Hash = ""
    )

    try {
        if (-not (Test-Path $EvidencePath)) {
            throw "Evidence file not found: $EvidencePath"
        }

        # Calculate hash if not provided
        if (-not $Hash) {
            $Hash = Get-FileHash -Path $EvidencePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
        }

        $evidence = [PSCustomObject]@{
            EvidenceId = "EVIDENCE-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff")
            Path = $EvidencePath
            Description = $Description
            Type = $Type
            Hash = $Hash
            Size = (Get-Item $EvidencePath).Length
            Collected = Get-Date
            CollectedBy = $env:USERNAME
        }

        $Case.Evidence += $evidence
        $Case.Modified = Get-Date

        # Add timeline entry
        Add-CaseTimelineEntry -Case $Case -EntryType "Evidence" -Description "Added evidence: $Description" -Evidence @($evidence.EvidenceId)

        Write-Host "Added evidence to case $($Case.CaseId): $Description" -ForegroundColor Green
        return $evidence
    }
    catch {
        Write-Error "Failed to add evidence to case: $($_.Exception.Message)"
        return $null
    }
}

function Update-CaseStatus {
    <#
    .SYNOPSIS
        Updates the status of an incident case

    .DESCRIPTION
        Changes the status of an incident case and records the change

    .PARAMETER Case
        The incident case object

    .PARAMETER Status
        New status (Open, Investigating, Contained, Resolved, Closed)

    .PARAMETER Comment
        Comment explaining the status change

    .EXAMPLE
        Update-CaseStatus -Case $case -Status "Investigating" -Comment "Starting detailed analysis"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IncidentCase]$Case,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Open", "Investigating", "Contained", "Resolved", "Closed")]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [string]$Comment = ""
    )

    try {
        $oldStatus = $Case.Status
        $Case.Status = $Status
        $Case.Modified = Get-Date

        if ($Status -eq "Resolved" -or $Status -eq "Closed") {
            $Case.Resolved = Get-Date
        }

        # Add timeline entry
        $description = "Status changed from $oldStatus to $Status"
        if ($Comment) {
            $description += ": $Comment"
        }

        Add-CaseTimelineEntry -Case $Case -EntryType "StatusChange" -Description $description

        Write-Host "Case $($Case.CaseId) status updated to: $Status" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to update case status: $($_.Exception.Message)"
        return $false
    }
}

function Export-CaseReport {
    <#
    .SYNOPSIS
        Exports an incident case report

    .DESCRIPTION
        Generates a comprehensive HTML report for an incident case

    .PARAMETER Case
        The incident case object

    .PARAMETER OutputPath
        Path for the HTML report

    .PARAMETER IncludeEvidence
        Whether to include evidence details

    .EXAMPLE
        Export-CaseReport -Case $case -OutputPath "C:\Reports\case-IR-20231008-143022.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IncidentCase]$Case,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeEvidence
    )

    try {
        Write-Host "Generating incident case report for $($Case.CaseId)" -ForegroundColor Cyan

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>🚨 Incident Case Report - $($Case.CaseId)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .section { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section-header { background: #ff6b6b; color: white; padding: 15px; margin: 0; border-radius: 8px 8px 0 0; }
        .section-content { padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #ffeaa7; }
        .status-badge { padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; }
        .status-open { background-color: #e74c3c; }
        .status-investigating { background-color: #f39c12; }
        .status-contained { background-color: #3498db; }
        .status-resolved { background-color: #27ae60; }
        .status-closed { background-color: #95a5a6; }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #e67e22; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #27ae60; font-weight: bold; }
        .severity-info { color: #3498db; font-weight: bold; }
        .timeline-entry { margin-bottom: 15px; padding: 10px; border-left: 4px solid #ff6b6b; background-color: #fff5f5; }
        .evidence-item { margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Incident Case Report</h1>
        <h2>$($Case.CaseId)</h2>
        <p><strong>Title:</strong> $($Case.Title)</p>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>

    <div class="section">
        <h2 class="section-header">📋 Case Details</h2>
        <div class="section-content">
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Title</td><td>$($Case.Title)</td></tr>
                <tr><td>Description</td><td>$($Case.Description)</td></tr>
                <tr><td>Severity</td><td><span class="severity-$($Case.Severity.ToLower())">$($Case.Severity)</span></td></tr>
                <tr><td>Status</td><td><span class="status-badge status-$($Case.Status.ToLower())">$($Case.Status)</span></td></tr>
                <tr><td>Category</td><td>$($Case.Category)</td></tr>
                <tr><td>Assigned To</td><td>$($Case.AssignedTo)</td></tr>
                <tr><td>Created</td><td>$($Case.Created.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
                <tr><td>Last Modified</td><td>$($Case.Modified.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
"@

        if ($Case.Resolved) {
            $html += @"
                <tr><td>Resolved</td><td>$($Case.Resolved.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
"@
        }

        $html += @"
            </table>
        </div>
    </div>

    <div class="section">
        <h2 class="section-header">⏰ Timeline</h2>
        <div class="section-content">
"@

        foreach ($entry in $Case.Timeline | Sort-Object Timestamp -Descending) {
            $html += @"
            <div class="timeline-entry">
                <strong>$($entry.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</strong> - <em>$($entry.EntryType)</em><br>
                $($entry.Description)<br>
                <small>User: $($entry.User)</small>
            </div>
"@
        }

        $html += @"
        </div>
    </div>
"@

        if ($IncludeEvidence -and $Case.Evidence.Count -gt 0) {
            $html += @"

    <div class="section">
        <h2 class="section-header">📁 Evidence ($($Case.Evidence.Count) items)</h2>
        <div class="section-content">
"@

            foreach ($evidence in $Case.Evidence) {
                $html += @"
            <div class="evidence-item">
                <strong>$($evidence.Description)</strong><br>
                <strong>Type:</strong> $($evidence.Type) | <strong>Size:</strong> $([math]::Round($evidence.Size / 1MB, 2)) MB<br>
                <strong>Path:</strong> $($evidence.Path)<br>
                <strong>Hash:</strong> $($evidence.Hash)<br>
                <small>Collected: $($evidence.Collected.ToString('yyyy-MM-dd HH:mm:ss')) by $($evidence.CollectedBy)</small>
            </div>
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

        Write-Host "Incident case report generated: $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to generate case report: $($_.Exception.Message)"
        return $false
    }
}