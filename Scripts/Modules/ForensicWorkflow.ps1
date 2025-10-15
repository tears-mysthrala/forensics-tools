# ForensicWorkflow.ps1
# Forensic workflow and complete forensics functions

<#
.SYNOPSIS
    Forensic Workflow Functions for Forensic Analysis

.DESCRIPTION
    This module provides functions for executing complete forensic investigation workflows.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
#>

function Invoke-ForensicWorkflow {
    <#
    .SYNOPSIS
        Executes a complete forensic investigation workflow.
    .DESCRIPTION
        Runs all analysis functions in sequence and generates reports.
    .PARAMETER OutputPath
        Directory where to save results and reports.
    .PARAMETER IncludeMemory
        Whether to include memory analysis.
    .EXAMPLE
        Invoke-ForensicWorkflow -OutputPath C:\Forensics
    #>
    param(
        [string]$OutputPath = ".",
        [bool]$IncludeMemory = $false
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $workflowDir = Join-Path $OutputPath "ForensicWorkflow_$timestamp"

    if (-not (Test-Path $workflowDir)) {
        New-Item -ItemType Directory -Path $workflowDir -Force | Out-Null
    }

    Write-Host "=== FORENSIC INVESTIGATION WORKFLOW ===" -ForegroundColor Cyan
    Write-Host "Results will be saved to: $workflowDir" -ForegroundColor Cyan

    $workflow = @{
        Timestamp     = Get-Date
        WorkflowSteps = @()
        Results       = @{}
    }

    # Step 1: Live System Status
    Write-Host "`nStep 1: Live System Status" -ForegroundColor Yellow
    try {
        $result = Invoke-LiveSystemStatus
        $result | ConvertTo-Json -Depth 3 | Out-File (Join-Path $workflowDir "01_system_status.json")
        $workflow.Results.SystemStatus = "Completed"
        $workflow.WorkflowSteps += "System Status: Completed"
        Write-Host "[OK] System status completed" -ForegroundColor Green
    }
    catch {
        $workflow.WorkflowSteps += "System Status: Failed - $($_.Exception.Message)"
        Write-Warning "System status failed: $($_.Exception.Message)"
    }

    # Step 2: System Analysis
    Write-Host "`nStep 2: System Analysis" -ForegroundColor Yellow
    try {
        $result = Invoke-SystemAnalysis
        $result | ConvertTo-Json -Depth 3 | Out-File (Join-Path $workflowDir "02_system_analysis.json")
        $workflow.Results.SystemAnalysis = "Completed"
        $workflow.WorkflowSteps += "System Analysis: Completed"
        Write-Host "[OK] System analysis completed" -ForegroundColor Green
    }
    catch {
        $workflow.WorkflowSteps += "System Analysis: Failed - $($_.Exception.Message)"
        Write-Warning "System analysis failed: $($_.Exception.Message)"
    }

    # Step 3: Network Analysis
    Write-Host "`nStep 3: Network Analysis" -ForegroundColor Yellow
    try {
        $result = Invoke-NetworkAnalysis
        $result | ConvertTo-Json -Depth 3 | Out-File (Join-Path $workflowDir "03_network_analysis.json")
        $workflow.Results.NetworkAnalysis = "Completed"
        $workflow.WorkflowSteps += "Network Analysis: Completed"
        Write-Host "[OK] Network analysis completed" -ForegroundColor Green
    }
    catch {
        $workflow.WorkflowSteps += "Network Analysis: Failed - $($_.Exception.Message)"
        Write-Warning "Network analysis failed: $($_.Exception.Message)"
    }

    # Step 4: File System Analysis
    Write-Host "`nStep 4: File System Analysis" -ForegroundColor Yellow
    try {
        $result = Invoke-FileSystemAnalysis
        $result | ConvertTo-Json -Depth 3 | Out-File (Join-Path $workflowDir "04_filesystem_analysis.json")
        $workflow.Results.FileSystemAnalysis = "Completed"
        $workflow.WorkflowSteps += "File System Analysis: Completed"
        Write-Host "[OK] File system analysis completed" -ForegroundColor Green
    }
    catch {
        $workflow.WorkflowSteps += "File System Analysis: Failed - $($_.Exception.Message)"
        Write-Warning "File system analysis failed: $($_.Exception.Message)"
    }

    # Step 5: Security Analysis
    Write-Host "`nStep 5: Security Analysis" -ForegroundColor Yellow
    try {
        $result = Invoke-SecurityAnalysis
        $result | ConvertTo-Json -Depth 3 | Out-File (Join-Path $workflowDir "05_security_analysis.json")
        $workflow.Results.SecurityAnalysis = "Completed"
        $workflow.WorkflowSteps += "Security Analysis: Completed"
        Write-Host "[OK] Security analysis completed" -ForegroundColor Green
    }
    catch {
        $workflow.WorkflowSteps += "Security Analysis: Failed - $($_.Exception.Message)"
        Write-Warning "Security analysis failed: $($_.Exception.Message)"
    }

    # Step 6: Memory Analysis (optional)
    if ($IncludeMemory) {
        Write-Host "`nStep 6: Memory Analysis" -ForegroundColor Yellow
        try {
            $memoryDump = Get-MemoryDump -OutputPath $workflowDir
            if ($memoryDump) {
                $workflow.Results.MemoryAnalysis = "Completed - $memoryDump"
                $workflow.WorkflowSteps += "Memory Analysis: Completed"
                Write-Host "[OK] Memory analysis completed" -ForegroundColor Green
            }
            else {
                $workflow.WorkflowSteps += "Memory Analysis: No memory dump tool available"
                Write-Warning "Memory analysis: No memory dump tool available"
            }
        }
        catch {
            $workflow.WorkflowSteps += "Memory Analysis: Failed - $($_.Exception.Message)"
            Write-Warning "Memory analysis failed: $($_.Exception.Message)"
        }
    }

    # Step 7: Generate Report
    Write-Host "`nStep 7: Generating Report" -ForegroundColor Yellow
    try {
        # Load all analysis results into a hashtable for the HTML report
        $analysisData = @{}
        $jsonFiles = Get-ChildItem -Path $workflowDir -Filter "*.json" | Where-Object { $_.Name -notlike "workflow_*" }
        foreach ($jsonFile in $jsonFiles) {
            $key = $jsonFile.BaseName -replace '^\d+_', ''
            try {
                $data = Get-Content $jsonFile.FullName | ConvertFrom-Json
                $analysisData[$key] = $data
            }
            catch {
                Write-Warning "Failed to load $($jsonFile.Name): $($_.Exception.Message)"
            }
        }

        # Generate HTML report using the improved function
        $htmlReport = New-ForensicHTMLReport -AnalysisData $analysisData -OutputPath $workflowDir -Title "Comprehensive Forensic Report"
        $workflow.Results.Report = "Generated - $htmlReport"
        $workflow.WorkflowSteps += "Report Generation: Completed"
        Write-Host "[OK] Report generation completed" -ForegroundColor Green
    }
    catch {
        $workflow.WorkflowSteps += "Report Generation: Failed - $($_.Exception.Message)"
        Write-Warning "Report generation failed: $($_.Exception.Message)"
    }

    # Save workflow summary
    $workflow | ConvertTo-Json -Depth 3 | Out-File (Join-Path $workflowDir "workflow_summary.json")

    Write-Host "`n=== WORKFLOW COMPLETE ===" -ForegroundColor Green
    Write-Host "Results saved to: $workflowDir" -ForegroundColor Cyan
    Write-Host "Summary: $(Join-Path $workflowDir "workflow_summary.json")" -ForegroundColor Cyan

    return $workflowDir
}

function Invoke-CompleteForensics {
    <#
    .SYNOPSIS
        Executes a complete forensic investigation workflow.
    .DESCRIPTION
        Runs all analysis functions in sequence and generates reports.
        This is an alias for Invoke-ForensicWorkflow for convenience.
    .PARAMETER OutputPath
        Directory where to save results and reports.
    .PARAMETER IncludeMemory
        Whether to include memory analysis.
    .EXAMPLE
        Invoke-CompleteForensics -OutputPath C:\Forensics
        Invoke-CompleteForensics -OutputPath "C:\Forensics" -IncludeMemory $true
    #>
    param(
        [string]$OutputPath = ".",
        [bool]$IncludeMemory = $false
    )

    # Call the existing Invoke-ForensicWorkflow function
    Invoke-ForensicWorkflow -OutputPath $OutputPath -IncludeMemory $IncludeMemory
}