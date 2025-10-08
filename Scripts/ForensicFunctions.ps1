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

# Add more functions as needed