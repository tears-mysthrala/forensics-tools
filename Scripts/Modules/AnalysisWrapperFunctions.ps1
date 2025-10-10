# AnalysisWrapperFunctions.ps1 - Single-command analysis wrapper functions

function Invoke-LiveSystemStatus {
    <#
    .SYNOPSIS
        Performs a quick live system status check.
    .DESCRIPTION
        Gathers basic system information, running processes, and network status.
    .EXAMPLE
        Invoke-LiveSystemStatus
    #>
    Write-Host "=== LIVE SYSTEM STATUS ===" -ForegroundColor Cyan

    $status = @{
        Timestamp = Get-Date
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        SystemInfo = $null
        Processes = $null
        Network = $null
        Services = $null
    }

    # System Information
    Write-Host "Gathering system information..." -ForegroundColor Yellow
    try {
        $status.SystemInfo = Get-SystemInfo
        Write-Host "[OK] System information collected" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to get system info: $($_.Exception.Message)"
    }

    # Process Information
    Write-Host "Checking running processes..." -ForegroundColor Yellow
    try {
        $status.Processes = Get-ProcessDetails | Where-Object { $_.ProcessName -notlike "*svchost*" } | Select-Object -First 20
        Write-Host "[OK] Process information collected (showing top 20 non-svchost)" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to get process info: $($_.Exception.Message)"
    }

    # Network Status
    Write-Host "Checking network connections..." -ForegroundColor Yellow
    try {
        $status.Network = Get-NetworkConnections | Where-Object { $_.State -eq "Established" } | Select-Object -First 10
        Write-Host "[OK] Network connections collected (showing top 10 established)" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to get network info: $($_.Exception.Message)"
    }

    # Service Status
    Write-Host "Checking critical services..." -ForegroundColor Yellow
    try {
        $status.Services = Get-ServicesStatus | Where-Object { $_.Status -ne "Running" }
        Write-Host "[OK] Service status collected (showing non-running services)" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to get service info: $($_.Exception.Message)"
    }

    Write-Host "Live system status check complete!" -ForegroundColor Green
    return $status
}

function Invoke-SystemAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive system analysis.
    .DESCRIPTION
        Analyzes system configuration, user accounts, scheduled tasks, and system logs.
    .EXAMPLE
        Invoke-SystemAnalysis
    #>
    Write-Host "=== SYSTEM ANALYSIS ===" -ForegroundColor Cyan

    $analysis = @{
        Timestamp = Get-Date
        SystemConfiguration = $null
        UserAccounts = $null
        ScheduledTasks = $null
        SystemLogs = $null
        RegistryAnalysis = $null
    }

    # System Configuration
    Write-Host "Analyzing system configuration..." -ForegroundColor Yellow
    try {
        $analysis.SystemConfiguration = Get-SystemInfo
        Write-Host "[OK] System configuration analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze system config: $($_.Exception.Message)"
    }

    # User Accounts
    Write-Host "Analyzing user accounts..." -ForegroundColor Yellow
    try {
        $analysis.UserAccounts = Get-UserAccounts
        Write-Host "[OK] User accounts analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze user accounts: $($_.Exception.Message)"
    }

    # Scheduled Tasks
    Write-Host "Analyzing scheduled tasks..." -ForegroundColor Yellow
    try {
        $analysis.ScheduledTasks = Get-ScheduledTasks
        Write-Host "[OK] Scheduled tasks analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze scheduled tasks: $($_.Exception.Message)"
    }

    # System Logs
    Write-Host "Analyzing system logs..." -ForegroundColor Yellow
    try {
        $analysis.SystemLogs = Get-SystemLogsSummary
        Write-Host "[OK] System logs analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze system logs: $($_.Exception.Message)"
    }

    # Registry Analysis
    Write-Host "Analyzing registry for persistence..." -ForegroundColor Yellow
    try {
        $runKeys = Get-RegistryKeys -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $runOnceKeys = Get-RegistryKeys -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        $analysis.RegistryAnalysis = @{
            RunKeys = $runKeys
            RunOnceKeys = $runOnceKeys
        }
        Write-Host "[OK] Registry persistence analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze registry: $($_.Exception.Message)"
    }

    Write-Host "System analysis complete!" -ForegroundColor Green
    return $analysis
}

function Invoke-NetworkAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive network analysis.
    .DESCRIPTION
        Analyzes network connections, shares, firewall rules, and network configuration.
    .EXAMPLE
        Invoke-NetworkAnalysis
    #>
    Write-Host "=== NETWORK ANALYSIS ===" -ForegroundColor Cyan

    $analysis = @{
        Timestamp = Get-Date
        NetworkConnections = $null
        NetworkShares = $null
        FirewallRules = $null
        USBHistory = $null
        NetworkConfig = $null
    }

    # Network Connections
    Write-Host "Analyzing network connections..." -ForegroundColor Yellow
    try {
        $analysis.NetworkConnections = Get-NetworkConnections
        Write-Host "[OK] Network connections analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze network connections: $($_.Exception.Message)"
    }

    # Network Shares
    Write-Host "Analyzing network shares..." -ForegroundColor Yellow
    try {
        $analysis.NetworkShares = Get-NetworkShares
        Write-Host "[OK] Network shares analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze network shares: $($_.Exception.Message)"
    }

    # Firewall Rules
    Write-Host "Analyzing firewall rules..." -ForegroundColor Yellow
    try {
        $analysis.FirewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true } | Select-Object DisplayName, Direction, Action, Profile
        Write-Host "[OK] Firewall rules analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze firewall rules: $($_.Exception.Message)"
    }

    # USB Device History
    Write-Host "Analyzing USB device history..." -ForegroundColor Yellow
    try {
        $analysis.USBHistory = Get-USBDeviceHistory
        Write-Host "[OK] USB device history analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze USB history: $($_.Exception.Message)"
    }

    # Network Configuration
    Write-Host "Analyzing network configuration..." -ForegroundColor Yellow
    try {
        $analysis.NetworkConfig = Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed
        Write-Host "[OK] Network configuration analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze network config: $($_.Exception.Message)"
    }

    Write-Host "Network analysis complete!" -ForegroundColor Green
    return $analysis
}

function Invoke-FileSystemAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive file system analysis.
    .DESCRIPTION
        Analyzes file hashes, alternate data streams, recent files, and large files.
    .EXAMPLE
        Invoke-FileSystemAnalysis
    #>
    Write-Host "=== FILE SYSTEM ANALYSIS ===" -ForegroundColor Cyan

    $analysis = @{
        Timestamp = Get-Date
        RecentFiles = $null
        LargeFiles = $null
        AlternateDataStreams = $null
        FileHashes = $null
        SuspiciousFiles = $null
    }

    # Recent Files
    Write-Host "Analyzing recent files..." -ForegroundColor Yellow
    try {
        $analysis.RecentFiles = Get-RecentFiles -Days 7
        Write-Host "[OK] Recent files analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze recent files: $($_.Exception.Message)"
    }

    # Large Files
    Write-Host "Analyzing large files..." -ForegroundColor Yellow
    try {
        $analysis.LargeFiles = Get-LargeFiles -SizeMB 500
        Write-Host "[OK] Large files analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze large files: $($_.Exception.Message)"
    }

    # Alternate Data Streams
    Write-Host "Analyzing alternate data streams..." -ForegroundColor Yellow
    try {
        $analysis.AlternateDataStreams = Get-AlternateDataStreams -Path "C:\"
        Write-Host "[OK] Alternate data streams analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze ADS: $($_.Exception.Message)"
    }

    # File Hashes (sample of system files)
    Write-Host "Calculating file hashes..." -ForegroundColor Yellow
    try {
        $systemFiles = @(
            "$env:windir\System32\cmd.exe",
            "$env:windir\System32\powershell.exe",
            "$env:windir\System32\svchost.exe"
        )
        $hashResults = @()
        foreach ($file in $systemFiles) {
            if (Test-Path $file) {
                $hashResults += Get-FileHashes -Path $file
            }
        }
        $analysis.FileHashes = $hashResults
        Write-Host "[OK] File hashes calculated" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to calculate file hashes: $($_.Exception.Message)"
    }

    # Suspicious Files (basic check)
    Write-Host "Checking for suspicious files..." -ForegroundColor Yellow
    try {
        $suspiciousPaths = @(
            "$env:TEMP",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        )
        $suspiciousFiles = @()
        foreach ($path in $suspiciousPaths) {
            if (Test-Path $path) {
                $suspiciousFiles += Get-ChildItem $path -File -ErrorAction SilentlyContinue | Select-Object Name, FullName, Length, LastWriteTime
            }
        }
        $analysis.SuspiciousFiles = $suspiciousFiles
        Write-Host "[OK] Suspicious files checked" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to check suspicious files: $($_.Exception.Message)"
    }

    Write-Host "File system analysis complete!" -ForegroundColor Green
    return $analysis
}

function Invoke-SecurityAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive security analysis.
    .DESCRIPTION
        Analyzes security events, user privileges, installed software, and potential security issues.
    .EXAMPLE
        Invoke-SecurityAnalysis
    #>
    Write-Host "=== SECURITY ANALYSIS ===" -ForegroundColor Cyan

    $analysis = @{
        Timestamp = Get-Date
        SecurityEvents = $null
        UserPrivileges = $null
        InstalledSoftware = $null
        AntivirusStatus = $null
        OpenPorts = $null
    }

    # Security Events
    Write-Host "Analyzing security events..." -ForegroundColor Yellow
    try {
        $analysis.SecurityEvents = Search-EventLogs -LogName "Security" -EventId 4625,4624,4634,4648 -Hours 24
        Write-Host "[OK] Security events analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze security events: $($_.Exception.Message)"
    }

    # User Privileges
    Write-Host "Analyzing user privileges..." -ForegroundColor Yellow
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

        $analysis.UserPrivileges = @{
            CurrentUser = $currentUser.Name
            IsAdmin = $principal.IsInRole($adminRole)
            Groups = $currentUser.Groups | ForEach-Object { $_.Translate([Security.Principal.NTAccount]).Value }
        }
        Write-Host "[OK] User privileges analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze user privileges: $($_.Exception.Message)"
    }

    # Installed Software
    Write-Host "Analyzing installed software..." -ForegroundColor Yellow
    try {
        $analysis.InstalledSoftware = Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor | Sort-Object Name
        Write-Host "[OK] Installed software analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze installed software: $($_.Exception.Message)"
    }

    # Antivirus Status
    Write-Host "Checking antivirus status..." -ForegroundColor Yellow
    try {
        $antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
        if ($antivirus) {
            $analysis.AntivirusStatus = $antivirus | Select-Object displayName, productState, timestamp
        } else {
            $analysis.AntivirusStatus = "Security Center not available or no antivirus detected"
        }
        Write-Host "[OK] Antivirus status checked" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to check antivirus status: $($_.Exception.Message)"
    }

    # Open Ports
    Write-Host "Analyzing open ports..." -ForegroundColor Yellow
    try {
        $analysis.OpenPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object LocalAddress, LocalPort, OwningProcess
        Write-Host "[OK] Open ports analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze open ports: $($_.Exception.Message)"
    }

    Write-Host "Security analysis complete!" -ForegroundColor Green
    return $analysis
}

function Invoke-QuickForensicScan {
    <#
    .SYNOPSIS
        Performs a quick forensic scan of the system.
    .DESCRIPTION
        Runs essential forensic checks without deep analysis or memory dumping.
    .EXAMPLE
        Invoke-QuickForensicScan
    #>
    Write-Host "=== QUICK FORENSIC SCAN ===" -ForegroundColor Cyan

    $scan = @{
        Timestamp = Get-Date
        SystemStatus = $null
        SuspiciousProcesses = $null
        NetworkConnections = $null
        RecentFiles = $null
        SecurityEvents = $null
    }

    # System Status
    Write-Host "Checking system status..." -ForegroundColor Yellow
    try {
        $scan.SystemStatus = Invoke-LiveSystemStatus
        Write-Host "[OK] System status checked" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to check system status: $($_.Exception.Message)"
    }

    # Suspicious Processes
    Write-Host "Checking for suspicious processes..." -ForegroundColor Yellow
    try {
        $suspicious = Get-Process | Where-Object {
            $_.ProcessName -match "(?i)(cmd|powershell|net|wmic|reg|sc|tasklist|netstat|whoami|systeminfo)" -and
            $_.StartTime -gt (Get-Date).AddHours(-1)
        } | Select-Object Name, Id, StartTime, CPU, WorkingSet
        $scan.SuspiciousProcesses = $suspicious
        Write-Host "[OK] Suspicious processes checked" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to check suspicious processes: $($_.Exception.Message)"
    }

    # Network Connections
    Write-Host "Checking network connections..." -ForegroundColor Yellow
    try {
        $scan.NetworkConnections = Get-NetworkConnections | Where-Object {
            $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
        } | Select-Object -First 10
        Write-Host "[OK] Network connections checked" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to check network connections: $($_.Exception.Message)"
    }

    # Recent Files
    Write-Host "Checking recent files..." -ForegroundColor Yellow
    try {
        $scan.RecentFiles = Get-RecentFiles -Days 1
        Write-Host "[OK] Recent files checked" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to check recent files: $($_.Exception.Message)"
    }

    # Security Events
    Write-Host "Checking recent security events..." -ForegroundColor Yellow
    try {
        $scan.SecurityEvents = Search-EventLogs -LogName "Security" -Hours 1 | Select-Object -First 5
        Write-Host "[OK] Security events checked" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to check security events: $($_.Exception.Message)"
    }

    Write-Host "Quick forensic scan complete!" -ForegroundColor Green
    return $scan
}

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
        Timestamp = Get-Date
        WorkflowSteps = @()
        Results = @{}
    }

    # Step 1: Live System Status
    Write-Host "`nStep 1: Live System Status" -ForegroundColor Yellow
    try {
        $result = Invoke-LiveSystemStatus
        $result | ConvertTo-Json -Depth 3 | Out-File (Join-Path $workflowDir "01_system_status.json")
        $workflow.Results.SystemStatus = "Completed"
        $workflow.WorkflowSteps += "System Status: Completed"
        Write-Host "[OK] System status completed" -ForegroundColor Green
    } catch {
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
    } catch {
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
    } catch {
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
    } catch {
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
    } catch {
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
            } else {
                $workflow.WorkflowSteps += "Memory Analysis: No memory dump tool available"
                Write-Warning "Memory analysis: No memory dump tool available"
            }
        } catch {
            $workflow.WorkflowSteps += "Memory Analysis: Failed - $($_.Exception.Message)"
            Write-Warning "Memory analysis failed: $($_.Exception.Message)"
        }
    }

    # Step 7: Generate Report
    Write-Host "`nStep 7: Generating Report" -ForegroundColor Yellow
    try {
        $reportFile = Export-ForensicReport -EvidencePath $workflowDir -OutputFile (Join-Path $workflowDir "forensic_report.html")
        $timelineFile = Get-ForensicTimeline -EvidencePath $workflowDir -OutputFile (Join-Path $workflowDir "forensic_timeline.csv")
        $workflow.Results.Report = "Generated - $reportFile"
        $workflow.Results.Timeline = "Generated - $timelineFile"
        $workflow.WorkflowSteps += "Report Generation: Completed"
        Write-Host "[OK] Report generation completed" -ForegroundColor Green
    } catch {
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