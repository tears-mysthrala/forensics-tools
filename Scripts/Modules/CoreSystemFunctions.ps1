# CoreSystemFunctions.ps1 - Core system analysis functions

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Retrieves basic system information for forensic analysis.
    .DESCRIPTION
        Collects hostname, OS version, uptime, users, etc.
    .EXAMPLE
        Get-SystemInfo
    #>
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop

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
    } catch {
        Write-Error "Failed to retrieve system information: $($_.Exception.Message)"
        Write-Host "Try running as Administrator for complete system information." -ForegroundColor Yellow
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
    try {
        Get-Process -ErrorAction Stop | ForEach-Object {
            try {
                $path = $_.Path
                $hash = if ($path -and (Test-Path $path)) {
                    try {
                        Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop | Select-Object -ExpandProperty Hash
                    } catch {
                        "Hash Error"
                    }
                } else { $null }

                $user = try {
                    (Get-Process -Id $_.Id -IncludeUserName -ErrorAction Stop | Select-Object -ExpandProperty UserName)
                } catch {
                    "Access Denied"
                }

                [PSCustomObject]@{
                    Name = $_.Name
                    Id = $_.Id
                    CPU = $_.CPU
                    MemoryMB = [math]::Round($_.WorkingSet / 1MB, 2)
                    Path = $path
                    SHA256 = $hash
                    StartTime = $_.StartTime
                    User = $user
                }
            } catch {
                Write-Warning "Could not query process '$($_.Name)': $($_.Exception.Message)"
                $null
            }
        } | Where-Object { $_ -ne $null }
    } catch {
        Write-Error "Failed to enumerate processes: $($_.Exception.Message)"
    }
}

function Get-UserAccounts {
    <#
    .SYNOPSIS
        Lists user accounts and their status.
    .EXAMPLE
        Get-UserAccounts
    #>
    try {
        Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, PasswordLastSet, AccountExpires, Description
    } catch {
        Write-Error "Failed to retrieve user accounts: $($_.Exception.Message)"
        Write-Host "Try running as Administrator for user account details." -ForegroundColor Yellow
    }
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
        try {
            if (Test-Path $path) {
                Get-ItemProperty -Path $path -ErrorAction Stop |
                Get-Member -MemberType NoteProperty -ErrorAction Stop |
                Where-Object { $_.Name -notlike "PS*" } |
                ForEach-Object {
                    try {
                        [PSCustomObject]@{
                            RegistryPath = $path
                            Name = $_.Name
                            Command = (Get-ItemProperty -Path $path -Name $_.Name -ErrorAction Stop).$($_.Name)
                        }
                    } catch {
                        Write-Warning "Could not read startup entry '$($_.Name)' from $path"
                        $null
                    }
                } | Where-Object { $_ -ne $null }
            }
        } catch {
            Write-Warning "Could not access startup registry path: $path - $($_.Exception.Message)"
        }
    }
}

function Get-ScheduledTasks {
    <#
    .SYNOPSIS
        Lists scheduled tasks.
    .EXAMPLE
        Get-ScheduledTasks
    #>
    Write-Host "Enumerating scheduled tasks (this may take a moment)..." -ForegroundColor Yellow

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne "Disabled" }
        $results = @()

        foreach ($task in $tasks) {
            try {
                $job = Start-Job -ScriptBlock {
                    param($t)
                    try {
                        $t | Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime, Author
                    } catch {
                        $null
                    }
                } -ArgumentList $task

                # Wait for job with timeout
                if (Wait-Job $job -Timeout 2) {
                    $result = Receive-Job $job
                    if ($result) {
                        $results += $result
                    }
                } else {
                    Write-Warning "Timeout querying task: $($task.TaskName)"
                    Stop-Job $job -ErrorAction SilentlyContinue
                }

                Remove-Job $job -ErrorAction SilentlyContinue

            } catch {
                Write-Warning "Could not query task '$($task.TaskName)': $($_.Exception.Message)"
            }
        }

        $results

    } catch {
        Write-Error "Failed to enumerate scheduled tasks: $($_.Exception.Message)"
        Write-Host "Try running as Administrator for better results." -ForegroundColor Yellow
    }
}

function Get-ServicesStatus {
    <#
    .SYNOPSIS
        Shows running services and their details.
    .EXAMPLE
        Get-ServicesStatus
    #>
    Write-Host "Enumerating services (this may take a moment)..." -ForegroundColor Yellow

    try {
        $services = Get-Service -ErrorAction Stop | Where-Object { $_.Status -eq "Running" }
        $results = @()

        foreach ($service in $services) {
            try {
                # Use a timeout for service queries to avoid hangs
                $job = Start-Job -ScriptBlock {
                    param($svc)
                    try {
                        $details = $svc | Select-Object Name, DisplayName, Status, StartType
                        $processId = "N/A"
                        try {
                            # This can sometimes hang, so we wrap it
                            $timeout = 2  # seconds
                            $processId = $svc.ServiceHandle
                        } catch {
                            $processId = "Access Denied"
                        }
                        $details | Add-Member -MemberType NoteProperty -Name ProcessId -Value $processId -PassThru
                    } catch {
                        $null
                    }
                } -ArgumentList $service

                # Wait for job with timeout
                if (Wait-Job $job -Timeout 3) {
                    $result = Receive-Job $job
                    if ($result) {
                        $results += $result
                    }
                } else {
                    Write-Warning "Timeout querying service: $($service.Name)"
                    Stop-Job $job -ErrorAction SilentlyContinue
                }

                Remove-Job $job -ErrorAction SilentlyContinue

            } catch {
                Write-Warning "Could not query service '$($service.Name)': $($_.Exception.Message)"
            }
        }

        $results | Select-Object Name, DisplayName, Status, StartType, ProcessId

    } catch {
        Write-Error "Failed to enumerate services: $($_.Exception.Message)"
        Write-Host "Try running as Administrator for better results." -ForegroundColor Yellow
    }
}