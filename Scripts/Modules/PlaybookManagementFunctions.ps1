# PlaybookManagementFunctions.ps1
# Incident response playbook management functions

<#
.SYNOPSIS
    Playbook Management Functions for Incident Response

.DESCRIPTION
    This module provides functions for creating, managing, and configuring
    incident response playbooks including triggers, steps, and automation workflows.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

# Incident Response Classes

class IncidentResponsePlaybook {
    [string]$Name
    [string]$Description
    [string]$Version
    [string]$Category
    [array]$Triggers
    [array]$Steps
    [hashtable]$Variables
    [DateTime]$Created
    [DateTime]$Modified
    [string]$Author

    IncidentResponsePlaybook() {
        $this.Created = Get-Date
        $this.Modified = Get-Date
        $this.Steps = @()
        $this.Triggers = @()
        $this.Variables = @{}
    }
}

# Playbook Management Functions

function New-IncidentResponsePlaybook {
    <#
    .SYNOPSIS
        Creates a new incident response playbook

    .DESCRIPTION
        Initializes a new incident response playbook with predefined structure

    .PARAMETER Name
        Name of the playbook

    .PARAMETER Description
        Description of the playbook

    .PARAMETER Category
        Category of incidents this playbook handles

    .PARAMETER Author
        Author of the playbook

    .EXAMPLE
        $playbook = New-IncidentResponsePlaybook -Name "Malware Infection Response" -Category "Malware" -Author "Security Team"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$Description = "",

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [string]$Author = $env:USERNAME
    )

    try {
        Write-Host "Creating new incident response playbook: $Name" -ForegroundColor Cyan

        $playbook = [IncidentResponsePlaybook]::new()
        $playbook.Name = $Name
        $playbook.Description = $Description
        $playbook.Category = $Category
        $playbook.Author = $Author
        $playbook.Version = "1.0.0"

        Write-Host "Playbook created successfully with ID: $($playbook.Name)" -ForegroundColor Green
        return $playbook
    }
    catch {
        Write-Error "Failed to create incident response playbook: $($_.Exception.Message)"
        return $null
    }
}

function Add-PlaybookStep {
    <#
    .SYNOPSIS
        Adds a step to an incident response playbook

    .DESCRIPTION
        Adds an automated action step to a playbook with dependencies and conditions

    .PARAMETER Playbook
        The playbook object to modify

    .PARAMETER Name
        Name of the step

    .PARAMETER Action
        The action to perform (function name or script block)

    .PARAMETER Parameters
        Parameters for the action

    .PARAMETER Dependencies
        Step IDs that must complete before this step

    .PARAMETER Condition
        Condition that must be met for this step to execute

    .EXAMPLE
        Add-PlaybookStep -Playbook $playbook -Name "Isolate Host" -Action "Invoke-NetworkIsolation" -Parameters @{HostName="target"}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IncidentResponsePlaybook]$Playbook,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{},

        [Parameter(Mandatory = $false)]
        [array]$Dependencies = @(),

        [Parameter(Mandatory = $false)]
        [string]$Condition = ""
    )

    try {
        $step = [PSCustomObject]@{
            StepId = "STEP-" + ($Playbook.Steps.Count + 1).ToString("D3")
            Name = $Name
            Action = $Action
            Parameters = $Parameters
            Dependencies = $Dependencies
            Condition = $Condition
            Status = "Pending"
            Result = ""
            ErrorMessage = ""
            Executed = $null
            Duration = 0
        }

        $Playbook.Steps += $step
        $Playbook.Modified = Get-Date

        Write-Host "Added step '$Name' to playbook '$($Playbook.Name)'" -ForegroundColor Green
        return $step
    }
    catch {
        Write-Error "Failed to add playbook step: $($_.Exception.Message)"
        return $null
    }
}

function Add-PlaybookTrigger {
    <#
    .SYNOPSIS
        Adds a trigger to an incident response playbook

    .DESCRIPTION
        Defines conditions that will automatically trigger the playbook execution

    .PARAMETER Playbook
        The playbook object to modify

    .PARAMETER Type
        Type of trigger (EventLog, FileSystem, Network, Custom)

    .PARAMETER Condition
        Condition that triggers the playbook

    .PARAMETER Parameters
        Additional parameters for the trigger

    .EXAMPLE
        Add-PlaybookTrigger -Playbook $playbook -Type "EventLog" -Condition "EventID=4625" -Parameters @{LogName="Security"}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IncidentResponsePlaybook]$Playbook,

        [Parameter(Mandatory = $true)]
        [ValidateSet("EventLog", "FileSystem", "Network", "Custom")]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$Condition,

        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{}
    )

    try {
        $trigger = [PSCustomObject]@{
            TriggerId = "TRIGGER-" + ($Playbook.Triggers.Count + 1).ToString("D3")
            Type = $Type
            Condition = $Condition
            Parameters = $Parameters
            Enabled = $true
            LastTriggered = $null
        }

        $Playbook.Triggers += $trigger
        $Playbook.Modified = Get-Date

        Write-Host "Added $Type trigger to playbook '$($Playbook.Name)'" -ForegroundColor Green
        return $trigger
    }
    catch {
        Write-Error "Failed to add playbook trigger: $($_.Exception.Message)"
        return $null
    }
}

function Export-Playbook {
    <#
    .SYNOPSIS
        Exports an incident response playbook to JSON

    .DESCRIPTION
        Saves a playbook configuration to a JSON file for persistence and sharing

    .PARAMETER Playbook
        The playbook object to export

    .PARAMETER Path
        Path to save the playbook JSON file

    .EXAMPLE
        Export-Playbook -Playbook $playbook -Path "C:\Playbooks\malware-response.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IncidentResponsePlaybook]$Playbook,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        Write-Host "Exporting playbook '$($Playbook.Name)' to $Path" -ForegroundColor Cyan

        $playbookData = [PSCustomObject]@{
            Name = $Playbook.Name
            Description = $Playbook.Description
            Version = $Playbook.Version
            Category = $Playbook.Category
            Triggers = $Playbook.Triggers
            Steps = $Playbook.Steps
            Variables = $Playbook.Variables
            Created = $Playbook.Created
            Modified = $Playbook.Modified
            Author = $Playbook.Author
        }

        $playbookData | ConvertTo-Json -Depth 10 | Out-File $Path -Encoding UTF8

        Write-Host "Playbook exported successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to export playbook: $($_.Exception.Message)"
        return $false
    }
}

function Import-Playbook {
    <#
    .SYNOPSIS
        Imports an incident response playbook from JSON

    .DESCRIPTION
        Loads a playbook configuration from a JSON file

    .PARAMETER Path
        Path to the playbook JSON file

    .EXAMPLE
        $playbook = Import-Playbook -Path "C:\Playbooks\malware-response.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        Write-Host "Importing playbook from $Path" -ForegroundColor Cyan

        if (-not (Test-Path $Path)) {
            throw "Playbook file not found: $Path"
        }

        $playbookData = Get-Content $Path -Raw | ConvertFrom-Json

        $playbook = [IncidentResponsePlaybook]::new()
        $playbook.Name = $playbookData.Name
        $playbook.Description = $playbookData.Description
        $playbook.Version = $playbookData.Version
        $playbook.Category = $playbookData.Category
        $playbook.Triggers = $playbookData.Triggers
        $playbook.Steps = $playbookData.Steps
        $playbook.Variables = $playbookData.Variables
        $playbook.Created = [DateTime]::Parse($playbookData.Created)
        $playbook.Modified = [DateTime]::Parse($playbookData.Modified)
        $playbook.Author = $playbookData.Author

        Write-Host "Playbook '$($playbook.Name)' imported successfully" -ForegroundColor Green
        return $playbook
    }
    catch {
        Write-Error "Failed to import playbook: $($_.Exception.Message)"
        return $null
    }
}