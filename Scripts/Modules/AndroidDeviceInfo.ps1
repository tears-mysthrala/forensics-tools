function Get-AndroidDeviceInfo {
    <#
    .SYNOPSIS
        Retrieves comprehensive information about connected Android devices

    .DESCRIPTION
        Uses ADB to gather device information, system properties, and installed applications

    .PARAMETER DeviceId
        Specific device ID to target (optional, uses first device if not specified)

    .EXAMPLE
        Get-AndroidDeviceInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DeviceId
    )

    try {
        Write-Host "Gathering Android device information..." -ForegroundColor Cyan

        # Check if ADB is available
        $adbPath = Get-Command adb -ErrorAction SilentlyContinue
        if (-not $adbPath) {
            throw "ADB (Android Debug Bridge) not found. Please install Android SDK Platform Tools."
        }

        # Get connected devices
        $devices = & adb devices 2>$null | Where-Object { $_ -match '\tdevice$' } | ForEach-Object {
            $_.Split("`t")[0]
        }

        if ($devices.Count -eq 0) {
            throw "No Android devices found. Ensure USB debugging is enabled and device is connected."
        }

        # Select device
        if (-not $DeviceId) {
            $DeviceId = $devices[0]
        }
        elseif ($DeviceId -notin $devices) {
            throw "Device $DeviceId not found in connected devices."
        }

        Write-Host "Analyzing device: $DeviceId" -ForegroundColor Gray

        $deviceInfo = [PSCustomObject]@{
            DeviceId     = $DeviceId
            Timestamp    = Get-Date
            SystemInfo   = @{}
            HardwareInfo = @{}
            NetworkInfo  = @{}
            Applications = @()
            StorageInfo  = @{}
        }

        # Get system properties
        $props = & adb -s $DeviceId shell getprop 2>$null
        foreach ($prop in $props) {
            if ($prop -match '^(\[.*?\]):\s*\[(.*?)\]') {
                $key = $matches[1].Trim('[]')
                $value = $matches[2]
                $deviceInfo.SystemInfo[$key] = $value
            }
        }

        # Get device model and manufacturer
        $deviceInfo.HardwareInfo["Model"] = $deviceInfo.SystemInfo["ro.product.model"]
        $deviceInfo.HardwareInfo["Manufacturer"] = $deviceInfo.SystemInfo["ro.product.manufacturer"]
        $deviceInfo.HardwareInfo["Brand"] = $deviceInfo.SystemInfo["ro.product.brand"]
        $deviceInfo.HardwareInfo["AndroidVersion"] = $deviceInfo.SystemInfo["ro.build.version.release"]
        $deviceInfo.HardwareInfo["APILevel"] = $deviceInfo.SystemInfo["ro.build.version.sdk"]
        $deviceInfo.HardwareInfo["BuildNumber"] = $deviceInfo.SystemInfo["ro.build.display.id"]

        # Get network information
        $deviceInfo.NetworkInfo["WiFiMAC"] = $deviceInfo.SystemInfo["wifi.interfaceMac"]
        $deviceInfo.NetworkInfo["BluetoothAddress"] = $deviceInfo.SystemInfo["ro.boot.btmacaddr"]

        # Get storage information
        $storage = & adb -s $DeviceId shell df 2>$null | Where-Object { $_ -match '^/data' -or $_ -match '^/storage' }
        foreach ($line in $storage) {
            $parts = $line -split '\s+'
            if ($parts.Count -ge 6) {
                $deviceInfo.StorageInfo[$parts[5]] = [PSCustomObject]@{
                    Total      = [long]$parts[1] * 1024
                    Used       = [long]$parts[2] * 1024
                    Available  = [long]$parts[3] * 1024
                    UsePercent = $parts[4]
                }
            }
        }

        # Get installed applications
        $packages = & adb -s $DeviceId shell pm list packages -f 2>$null
        foreach ($package in $packages) {
            if ($package -match 'package:(.+?)=(.+)') {
                $apkPath = $matches[1]
                $packageName = $matches[2]

                $appInfo = [PSCustomObject]@{
                    PackageName = $packageName
                    ApkPath     = $apkPath
                    AppName     = ""
                    Version     = ""
                    InstallTime = $null
                    Size        = 0
                }

                # Get app label
                try {
                    $label = & adb -s $DeviceId shell pm dump $packageName 2>$null | Where-Object { $_ -match 'label:' } | Select-Object -First 1
                    if ($label -match 'label:\s*(.+)') {
                        $appInfo.AppName = $matches[1]
                    }
                }
                catch { }

                $deviceInfo.Applications += $appInfo
            }
        }

        Write-Host "Android device analysis completed. Found $($deviceInfo.Applications.Count) applications" -ForegroundColor Green
        return $deviceInfo
    }
    catch {
        Write-Error "Failed to analyze Android device: $($_.Exception.Message)"
        return $null
    }
}