# ForensicFunctions.ps1 - Custom functions for Forensics and Incident Response

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Retrieves basic system information for forensic analysis.
    .DESCRIPTION
        Collects hostname, OS version, uptime, users, etc.
    .EXAMPLE
        Get-SystemInfo
    #>
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS

    [PSCustomObject]@{
        Hostname = $env:COMPUTERNAME
        OS = $os.Caption
        Version = $os.Version
        Build = $os.BuildNumber
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        BIOSVersion = $bios.Version
        SerialNumber = $bios.SerialNumber
        Uptime = (Get-Date) - $os.LastBootUpTime
        CurrentUser = $env:USERNAME
        Domain = $cs.Domain
    }
}

function Get-ProcessDetails {
    <#
    .SYNOPSIS
        Gets detailed process information including paths and hashes.
    .DESCRIPTION
        Enhanced Get-Process with file paths and SHA256 hashes.
    .EXAMPLE
        Get-ProcessDetails | Where-Object { $_.Name -eq 'notepad' }
    #>
    Get-Process | ForEach-Object {
        $path = $_.Path
        $hash = if ($path -and (Test-Path $path)) { Get-FileHash $path -Algorithm SHA256 | Select-Object -ExpandProperty Hash } else { $null }
        [PSCustomObject]@{
            Name = $_.Name
            Id = $_.Id
            CPU = $_.CPU
            MemoryMB = [math]::Round($_.WorkingSet / 1MB, 2)
            Path = $path
            SHA256 = $hash
            StartTime = $_.StartTime
            User = (Get-Process -Id $_.Id -IncludeUserName | Select-Object -ExpandProperty UserName)
        }
    }
}

function Get-NetworkConnections {
    <#
    .SYNOPSIS
        Retrieves network connections similar to netstat.
    .DESCRIPTION
        Lists active TCP and UDP connections with process info.
    .EXAMPLE
        Get-NetworkConnections
    #>
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $_ | Add-Member -MemberType NoteProperty -Name ProcessName -Value $proc.Name -PassThru
    }
}

function Get-EventLogsSummary {
    <#
    .SYNOPSIS
        Summarizes event logs for quick overview.
    .DESCRIPTION
        Counts events by level in System, Security, Application logs.
    .EXAMPLE
        Get-EventLogsSummary
    #>
    $logs = 'System', 'Security', 'Application'
    foreach ($log in $logs) {
        $events = Get-EventLog -LogName $log -Newest 1000 -ErrorAction SilentlyContinue
        if ($events) {
            $summary = $events | Group-Object -Property EntryType | Select-Object Name, Count
            [PSCustomObject]@{
                LogName = $log
                TotalEvents = $events.Count
                Error = ($summary | Where-Object Name -eq 'Error').Count
                Warning = ($summary | Where-Object Name -eq 'Warning').Count
                Information = ($summary | Where-Object Name -eq 'Information').Count
            }
        }
    }
}

function Search-EventLogs {
    <#
    .SYNOPSIS
        Searches event logs for specific keywords.
    .PARAMETER Keyword
        The keyword to search for.
    .PARAMETER LogName
        The log to search (default: Security).
    .EXAMPLE
        Search-EventLogs -Keyword "failed" -LogName Security
    #>
    param(
        [string]$Keyword,
        [string]$LogName = 'Security'
    )
    Get-EventLog -LogName $LogName | Where-Object { $_.Message -like "*$Keyword*" } | Select-Object TimeGenerated, EntryType, Source, EventID, Message
}

function Get-FileHashes {
    <#
    .SYNOPSIS
        Computes hashes for files in a directory.
    .PARAMETER Path
        Directory path to scan.
    .PARAMETER Algorithm
        Hash algorithm (default: SHA256).
    .EXAMPLE
        Get-FileHashes -Path C:\Windows\System32
    #>
    param(
        [string]$Path,
        [string]$Algorithm = 'SHA256'
    )
    Get-ChildItem -Path $Path -File -Recurse | ForEach-Object {
        $hash = Get-FileHash $_.FullName -Algorithm $Algorithm
        [PSCustomObject]@{
            Path = $_.FullName
            Size = $_.Length
            LastWriteTime = $_.LastWriteTime
            Hash = $hash.Hash
            Algorithm = $Algorithm
        }
    }
}

function Analyze-File {
    <#
    .SYNOPSIS
        Basic file analysis: type, size, timestamps.
    .PARAMETER Path
        File path.
    .EXAMPLE
        Analyze-File -Path C:\example.txt
    #>
    param([string]$Path)
    if (Test-Path $Path) {
        $file = Get-Item $Path
        $type = if ($file.Extension) { $file.Extension } else { 'Unknown' }
        [PSCustomObject]@{
            Name = $file.Name
            FullPath = $file.FullName
            Size = $file.Length
            Created = $file.CreationTime
            Modified = $file.LastWriteTime
            Accessed = $file.LastAccessTime
            Type = $type
            Attributes = $file.Attributes
        }
    } else {
        Write-Warning "File not found: $Path"
    }
}

function Get-RegistryKeys {
    <#
    .SYNOPSIS
        Retrieves registry key values.
    .PARAMETER Path
        Registry path.
    .EXAMPLE
        Get-RegistryKeys -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion
    #>
    param([string]$Path)
    Get-ItemProperty -Path $Path | Select-Object * -ExcludeProperty PS*
}

function Get-RecentFiles {
    <#
    .SYNOPSIS
        Finds files modified within the last X days.
    .PARAMETER Days
        Number of days to look back (default: 7).
    .PARAMETER Path
        Directory to search (default: C:\).
    .EXAMPLE
        Get-RecentFiles -Days 1 -Path C:\Users
    #>
    param(
        [int]$Days = 7,
        [string]$Path = "C:\"
    )
    $cutoffDate = (Get-Date).AddDays(-$Days)
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $cutoffDate } |
    Select-Object FullName, LastWriteTime, Length |
    Sort-Object LastWriteTime -Descending
}

function Get-LargeFiles {
    <#
    .SYNOPSIS
        Finds files larger than specified size.
    .PARAMETER MinSizeMB
        Minimum file size in MB (default: 100).
    .PARAMETER Path
        Directory to search (default: C:\).
    .EXAMPLE
        Get-LargeFiles -MinSizeMB 500 -Path C:\Users
    #>
    param(
        [int]$MinSizeMB = 100,
        [string]$Path = "C:\"
    )
    $minSize = $MinSizeMB * 1MB
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt $minSize } |
    Select-Object FullName, @{Name="SizeMB";Expression={[math]::Round($_.Length/1MB,2)}}, LastWriteTime |
    Sort-Object SizeMB -Descending
}

function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Lists installed software from registry.
    .EXAMPLE
        Get-InstalledSoftware
    #>
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    }
}

function Get-ScheduledTasks {
    <#
    .SYNOPSIS
        Lists scheduled tasks.
    .EXAMPLE
        Get-ScheduledTasks
    #>
    Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } |
    Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime, Author
}

function Get-ServicesStatus {
    <#
    .SYNOPSIS
        Shows running services and their details.
    .EXAMPLE
        Get-ServicesStatus
    #>
    Get-Service | Where-Object { $_.Status -eq "Running" } |
    Select-Object Name, DisplayName, Status, StartType, @{Name="ProcessId";Expression={$_.ServiceHandle}}
}

function Get-StartupPrograms {
    <#
    .SYNOPSIS
        Lists programs that run at startup.
    .EXAMPLE
        Get-StartupPrograms
    #>
    $startupPaths = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Get-Member -MemberType NoteProperty |
            Where-Object { $_.Name -notlike "PS*" } |
            ForEach-Object {
                [PSCustomObject]@{
                    RegistryPath = $path
                    Name = $_.Name
                    Command = (Get-ItemProperty -Path $path -Name $_.Name).$($_.Name)
                }
            }
        }
    }
}

function Get-UserAccounts {
    <#
    .SYNOPSIS
        Lists user accounts and their status.
    .EXAMPLE
        Get-UserAccounts
    #>
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, AccountExpires, Description
}

function Get-AlternateDataStreams {
    <#
    .SYNOPSIS
        Scans for alternate data streams in files.
    .PARAMETER Path
        Directory to scan (default: current directory).
    .EXAMPLE
        Get-AlternateDataStreams -Path C:\Suspicious
    #>
    param([string]$Path = ".")
    
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
        $streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue |
        Where-Object { $_.Stream -ne ':$DATA' }
        
        foreach ($stream in $streams) {
            [PSCustomObject]@{
                FilePath = $_.FullName
                StreamName = $stream.Stream
                Size = $stream.Size
            }
        }
    }
}

function Get-SystemLogsSummary {
    <#
    .SYNOPSIS
        Provides a summary of system logs.
    .PARAMETER Hours
        Hours to look back (default: 24).
    .EXAMPLE
        Get-SystemLogsSummary -Hours 48
    #>
    param([int]$Hours = 24)
    
    $startTime = (Get-Date).AddHours(-$Hours)
    
    $logs = @('System', 'Application', 'Security')
    foreach ($log in $logs) {
        $entries = Get-EventLog -LogName $log -After $startTime -ErrorAction SilentlyContinue
        if ($entries) {
            $summary = $entries | Group-Object -Property EntryType | 
            Select-Object Name, Count
            
            [PSCustomObject]@{
                LogName = $log
                TotalEntries = $entries.Count
                Errors = ($summary | Where-Object Name -eq 'Error').Count
                Warnings = ($summary | Where-Object Name -eq 'Warning').Count
                Information = ($summary | Where-Object Name -eq 'Information').Count
                TimeRange = "$Hours hours"
            }
        }
    }
}

function Get-NetworkShares {
    <#
    .SYNOPSIS
        Lists network shares.
    .EXAMPLE
        Get-NetworkShares
    #>
    Get-SmbShare | Select-Object Name, Path, Description, ShareState
}

function Get-USBDeviceHistory {
    <#
    .SYNOPSIS
        Shows USB device connection history from registry.
    .EXAMPLE
        Get-USBDeviceHistory
    #>
    $usbKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    if (Test-Path $usbKey) {
        Get-ChildItem -Path $usbKey -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $deviceKey = $_.PSPath
            $friendlyName = (Get-ItemProperty -Path $deviceKey -Name "FriendlyName" -ErrorAction SilentlyContinue).FriendlyName
            $deviceDesc = (Get-ItemProperty -Path $deviceKey -Name "DeviceDesc" -ErrorAction SilentlyContinue).DeviceDesc
            
            if ($friendlyName -or $deviceDesc) {
                [PSCustomObject]@{
                    DeviceID = $_.PSChildName
                    FriendlyName = $friendlyName
                    DeviceDescription = $deviceDesc
                    LastConnected = $_.LastWriteTime
                }
            }
        }
    }
}

# Add more functions as needed