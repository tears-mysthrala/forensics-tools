# NetworkFunctions.ps1 - Network analysis functions

function Get-NetworkConnections {
    <#
    .SYNOPSIS
        Retrieves network connections similar to netstat.
    .DESCRIPTION
        Lists active TCP and UDP connections with process info.
    .EXAMPLE
        Get-NetworkConnections
    #>
    try {
        Get-NetTCPConnection -ErrorAction Stop | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        ForEach-Object {
            try {
                $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                $_ | Add-Member -MemberType NoteProperty -Name ProcessName -Value $proc.Name -PassThru
            } catch {
                $_ | Add-Member -MemberType NoteProperty -Name ProcessName -Value "Unknown" -PassThru
            }
        }
    } catch {
        Write-Error "Failed to retrieve network connections: $($_.Exception.Message)"
        Write-Host "Try running as Administrator for network connection details." -ForegroundColor Yellow
    }
}

function Get-NetworkShares {
    <#
    .SYNOPSIS
        Lists network shares.
    .EXAMPLE
        Get-NetworkShares
    #>
    try {
        Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description, ShareState
    } catch {
        Write-Error "Failed to retrieve network shares: $($_.Exception.Message)"
        Write-Host "Try running as Administrator for network share details." -ForegroundColor Yellow
    }
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