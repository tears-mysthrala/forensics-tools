# AndroidDeviceFunctions.ps1
# Android device forensics functions

<#
.SYNOPSIS
    Android Device Forensics Functions

.DESCRIPTION
    This module provides functions for analyzing Android devices including
    device information, SMS messages, call logs, contacts, and location data.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: ADB (Android Debug Bridge) for device communication
#>

# Android Forensics Functions

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
        } elseif ($DeviceId -notin $devices) {
            throw "Device $DeviceId not found in connected devices."
        }

        Write-Host "Analyzing device: $DeviceId" -ForegroundColor Gray

        $deviceInfo = [PSCustomObject]@{
            DeviceId = $DeviceId
            Timestamp = Get-Date
            SystemInfo = @{}
            HardwareInfo = @{}
            NetworkInfo = @{}
            Applications = @()
            StorageInfo = @{}
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
                    Total = [long]$parts[1] * 1024
                    Used = [long]$parts[2] * 1024
                    Available = [long]$parts[3] * 1024
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
                    ApkPath = $apkPath
                    AppName = ""
                    Version = ""
                    InstallTime = $null
                    Size = 0
                }

                # Get app label
                try {
                    $label = & adb -s $DeviceId shell pm dump $packageName 2>$null | Where-Object { $_ -match 'label:' } | Select-Object -First 1
                    if ($label -match 'label:\s*(.+)') {
                        $appInfo.AppName = $matches[1]
                    }
                } catch { }

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

function Get-AndroidSMSMessages {
    <#
    .SYNOPSIS
        Extracts SMS messages from Android device

    .DESCRIPTION
        Retrieves SMS and MMS messages from Android device SMS database

    .PARAMETER DeviceId
        Specific device ID to target

    .PARAMETER OutputPath
        Path to save extracted messages

    .EXAMPLE
        Get-AndroidSMSMessages -DeviceId "emulator-5554" -OutputPath "C:\Evidence\sms.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Extracting SMS messages from Android device..." -ForegroundColor Cyan

        # Pull SMS database
        $remotePath = "/data/data/com.android.providers.telephony/databases/mmssms.db"
        $localPath = [System.IO.Path]::GetTempFileName() + ".db"

        & adb -s $DeviceId pull $remotePath $localPath 2>$null | Out-Null

        if (-not (Test-Path $localPath)) {
            throw "Failed to pull SMS database from device"
        }

        # Analyze SMS database
        $connectionString = "Data Source=$localPath;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Get SMS messages
        $smsQuery = @"
SELECT
    _id,
    thread_id,
    address,
    person,
    date,
    date_sent,
    protocol,
    read,
    status,
    type,
    reply_path_present,
    subject,
    body,
    service_center,
    locked,
    error_code,
    seen
FROM sms
ORDER BY date DESC
"@

        $command = $connection.CreateCommand()
        $command.CommandText = $smsQuery
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $messages = @()
        foreach ($row in $dataSet.Tables[0].Rows) {
            $messages += [PSCustomObject]@{
                Id = $row._id
                ThreadId = $row.thread_id
                Address = $row.address
                Person = $row.person
                Date = [DateTime]::FromFileTimeUtc($row.date)
                DateSent = if ($row.date_sent) { [DateTime]::FromFileTimeUtc($row.date_sent) } else { $null }
                Protocol = $row.protocol
                Read = [bool]$row.read
                Status = $row.status
                Type = $row.type
                Subject = $row.subject
                Body = $row.body
                ServiceCenter = $row.service_center
                Locked = [bool]$row.locked
                ErrorCode = $row.error_code
                Seen = [bool]$row.seen
            }
        }

        # Get MMS messages
        $mmsQuery = @"
SELECT
    _id,
    thread_id,
    date,
    date_sent,
    read,
    msg_box,
    sub,
    sub_cs,
    ct_t,
    ct_l,
    exp,
    m_cls,
    m_id,
    m_size,
    pri,
    rr,
    rpt_a,
    resp_st,
    st,
    text_only,
    retr_st,
    retr_txt,
    retr_txt_cs,
    d_rpt,
    locked,
    seen
FROM pdu
ORDER BY date DESC
"@

        $command.CommandText = $mmsQuery
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $mmsMessages = @()
        foreach ($row in $dataSet.Tables[0].Rows) {
            $mmsMessages += [PSCustomObject]@{
                Id = $row._id
                ThreadId = $row.thread_id
                Date = [DateTime]::FromFileTimeUtc($row.date)
                DateSent = if ($row.date_sent) { [DateTime]::FromFileTimeUtc($row.date_sent) } else { $null }
                Read = [bool]$row.read
                MessageBox = $row.msg_box
                Subject = $row.sub
                ContentType = $row.ct_t
                MessageClass = $row.m_cls
                MessageId = $row.m_id
                MessageSize = $row.m_size
                Priority = $row.pri
                Locked = [bool]$row.locked
                Seen = [bool]$row.seen
            }
        }

        $connection.Close()
        Remove-Item $localPath -Force

        # Combine and export
        $result = [PSCustomObject]@{
            DeviceId = $DeviceId
            ExtractionDate = Get-Date
            SMSMessages = $messages
            MMSMessages = $mmsMessages
            TotalMessages = $messages.Count + $mmsMessages.Count
        }

        $result | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8

        Write-Host "SMS extraction completed. Found $($messages.Count) SMS and $($mmsMessages.Count) MMS messages" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "Failed to extract SMS messages: $($_.Exception.Message)"
        return $null
    }
}

function Get-AndroidCallLogs {
    <#
    .SYNOPSIS
        Extracts call logs from Android device

    .DESCRIPTION
        Retrieves call history from Android call log database

    .PARAMETER DeviceId
        Specific device ID to target

    .PARAMETER OutputPath
        Path to save extracted call logs

    .EXAMPLE
        Get-AndroidCallLogs -DeviceId "emulator-5554" -OutputPath "C:\Evidence\calls.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Extracting call logs from Android device..." -ForegroundColor Cyan

        # Pull call log database
        $remotePath = "/data/data/com.android.providers.contacts/databases/calllog.db"
        $localPath = [System.IO.Path]::GetTempFileName() + ".db"

        & adb -s $DeviceId pull $remotePath $localPath 2>$null | Out-Null

        if (-not (Test-Path $localPath)) {
            throw "Failed to pull call log database from device"
        }

        # Analyze call log database
        $connectionString = "Data Source=$localPath;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Get call logs
        $callQuery = @"
SELECT
    _id,
    number,
    date,
    duration,
    type,
    new,
    name,
    numbertype,
    numberlabel,
    countryiso,
    geocoded_location,
    lookup_uri,
    matched_number,
    normalized_number,
    photo_id,
    formatted_number,
    is_read
FROM calls
ORDER BY date DESC
"@

        $command = $connection.CreateCommand()
        $command.CommandText = $callQuery
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $calls = @()
        foreach ($row in $dataSet.Tables[0].Rows) {
            $calls += [PSCustomObject]@{
                Id = $row._id
                Number = $row.number
                Date = [DateTime]::FromFileTimeUtc($row.date)
                Duration = $row.duration
                Type = switch ($row.type) {
                    1 { "Incoming" }
                    2 { "Outgoing" }
                    3 { "Missed" }
                    4 { "Voicemail" }
                    5 { "Rejected" }
                    6 { "Blocked" }
                    default { "Unknown" }
                }
                New = [bool]$row.new
                Name = $row.name
                NumberType = $row.numbertype
                NumberLabel = $row.numberlabel
                CountryISO = $row.countryiso
                GeocodedLocation = $row.geocoded_location
                IsRead = [bool]$row.is_read
            }
        }

        $connection.Close()
        Remove-Item $localPath -Force

        # Export results
        $result = [PSCustomObject]@{
            DeviceId = $DeviceId
            ExtractionDate = Get-Date
            CallLogs = $calls
            TotalCalls = $calls.Count
        }

        $result | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8

        Write-Host "Call log extraction completed. Found $($calls.Count) call records" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "Failed to extract call logs: $($_.Exception.Message)"
        return $null
    }
}

function Get-AndroidContacts {
    <#
    .SYNOPSIS
        Extracts contacts from Android device

    .DESCRIPTION
        Retrieves contact information from Android contacts database

    .PARAMETER DeviceId
        Specific device ID to target

    .PARAMETER OutputPath
        Path to save extracted contacts

    .EXAMPLE
        Get-AndroidContacts -DeviceId "emulator-5554" -OutputPath "C:\Evidence\contacts.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Extracting contacts from Android device..." -ForegroundColor Cyan

        # Pull contacts database
        $remotePath = "/data/data/com.android.providers.contacts/databases/contacts2.db"
        $localPath = [System.IO.Path]::GetTempFileName() + ".db"

        & adb -s $DeviceId pull $remotePath $localPath 2>$null | Out-Null

        if (-not (Test-Path $localPath)) {
            throw "Failed to pull contacts database from device"
        }

        # Analyze contacts database
        $connectionString = "Data Source=$localPath;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Get contacts
        $contactQuery = @"
SELECT
    c._id,
    c.display_name,
    c.display_name_alt,
    c.sort_key,
    c.phonebook_label,
    c.phonebook_bucket,
    c.lookup,
    c.photo_id,
    c.custom_ringtone,
    c.send_to_voicemail,
    c.times_contacted,
    c.last_time_contacted,
    c.starred,
    c.pinned,
    c.has_phone_number,
    c.has_email,
    c.contact_last_updated_timestamp
FROM raw_contacts c
ORDER BY c.display_name
"@

        $command = $connection.CreateCommand()
        $command.CommandText = $contactQuery
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $contacts = @()
        foreach ($row in $dataSet.Tables[0].Rows) {
            # Get phone numbers for this contact
            $phoneQuery = @"
SELECT
    p.data1 as number,
    p.data2 as type,
    p.data3 as label
FROM data p
WHERE p.raw_contact_id = $($row._id) AND p.mimetype = 'vnd.android.cursor.item/phone_v2'
"@

            $phoneCommand = $connection.CreateCommand()
            $phoneCommand.CommandText = $phoneQuery
            $phoneAdapter = New-Object System.Data.SQLite.SQLiteDataAdapter($phoneCommand)
            $phoneDataSet = New-Object System.Data.DataSet
            $phoneAdapter.Fill($phoneDataSet) | Out-Null

            $phoneNumbers = @()
            foreach ($phoneRow in $phoneDataSet.Tables[0].Rows) {
                $phoneNumbers += [PSCustomObject]@{
                    Number = $phoneRow.number
                    Type = $phoneRow.type
                    Label = $phoneRow.label
                }
            }

            # Get email addresses for this contact
            $emailQuery = @"
SELECT
    e.data1 as email,
    e.data2 as type,
    e.data3 as label
FROM data e
WHERE e.raw_contact_id = $($row._id) AND e.mimetype = 'vnd.android.cursor.item/email_v2'
"@

            $emailCommand = $connection.CreateCommand()
            $emailCommand.CommandText = $emailQuery
            $emailAdapter = New-Object System.Data.SQLite.SQLiteDataAdapter($emailCommand)
            $emailDataSet = New-Object System.Data.DataSet
            $emailAdapter.Fill($emailDataSet) | Out-Null

            $emails = @()
            foreach ($emailRow in $emailDataSet.Tables[0].Rows) {
                $emails += [PSCustomObject]@{
                    Email = $emailRow.email
                    Type = $emailRow.type
                    Label = $emailRow.label
                }
            }

            $contacts += [PSCustomObject]@{
                Id = $row._id
                DisplayName = $row.display_name
                DisplayNameAlt = $row.display_name_alt
                PhoneNumbers = $phoneNumbers
                Emails = $emails
                TimesContacted = $row.times_contacted
                LastTimeContacted = if ($row.last_time_contacted) { [DateTime]::FromFileTimeUtc($row.last_time_contacted) } else { $null }
                Starred = [bool]$row.starred
                Pinned = [bool]$row.pinned
                HasPhoneNumber = [bool]$row.has_phone_number
                HasEmail = [bool]$row.has_email
                LastUpdated = if ($row.contact_last_updated_timestamp) { [DateTime]::FromFileTimeUtc($row.contact_last_updated_timestamp) } else { $null }
            }
        }

        $connection.Close()
        Remove-Item $localPath -Force

        # Export results
        $result = [PSCustomObject]@{
            DeviceId = $DeviceId
            ExtractionDate = Get-Date
            Contacts = $contacts
            TotalContacts = $contacts.Count
        }

        $result | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8

        Write-Host "Contacts extraction completed. Found $($contacts.Count) contacts" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "Failed to extract contacts: $($_.Exception.Message)"
        return $null
    }
}

function Get-AndroidLocationData {
    <#
    .SYNOPSIS
        Extracts location data from Android device

    .DESCRIPTION
        Retrieves GPS location history and WiFi positioning data

    .PARAMETER DeviceId
        Specific device ID to target

    .PARAMETER OutputPath
        Path to save extracted location data

    .EXAMPLE
        Get-AndroidLocationData -DeviceId "emulator-5554" -OutputPath "C:\Evidence\locations.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Extracting location data from Android device..." -ForegroundColor Cyan

        $locations = @()

        # Try to get Google Location History (if available)
        try {
            $remotePath = "/data/data/com.google.android.gms/databases/location_history.db"
            $localPath = [System.IO.Path]::GetTempFileName() + ".db"

            & adb -s $DeviceId pull $remotePath $localPath 2>$null | Out-Null

            if (Test-Path $localPath) {
                $connectionString = "Data Source=$localPath;Version=3;Read Only=True;"
                $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
                $connection.Open()

                # Query location history
                $locationQuery = "SELECT timestamp, latitude, longitude, accuracy, altitude FROM location_history ORDER BY timestamp DESC"
                $command = $connection.CreateCommand()
                $command.CommandText = $locationQuery
                $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
                $dataSet = New-Object System.Data.DataSet
                $adapter.Fill($dataSet) | Out-Null

                foreach ($row in $dataSet.Tables[0].Rows) {
                    $locations += [PSCustomObject]@{
                        Timestamp = [DateTime]::FromFileTimeUtc($row.timestamp * 1000)
                        Latitude = $row.latitude
                        Longitude = $row.longitude
                        Accuracy = $row.accuracy
                        Altitude = $row.altitude
                        Source = "Google Location History"
                    }
                }

                $connection.Close()
                Remove-Item $localPath -Force
            }
        }
        catch {
            Write-Warning "Could not access Google Location History: $($_.Exception.Message)"
        }

        # Get WiFi scan results
        try {
            $wifiResults = & adb -s $DeviceId shell dumpsys wifi 2>$null | Where-Object { $_ -match 'SSID|frequency|BSSID' }
            # Parse WiFi data (simplified parsing)
            $wifiData = @()
            foreach ($line in $wifiResults) {
                if ($line -match 'SSID:\s*"([^"]+)"') {
                    $wifiData += [PSCustomObject]@{
                        SSID = $matches[1]
                        Timestamp = Get-Date
                        Source = "WiFi Scan"
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not retrieve WiFi scan data: $($_.Exception.Message)"
        }

        # Export results
        $result = [PSCustomObject]@{
            DeviceId = $DeviceId
            ExtractionDate = Get-Date
            LocationHistory = $locations
            WiFiData = $wifiData
            TotalLocations = $locations.Count
        }

        $result | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8

        Write-Host "Location data extraction completed. Found $($locations.Count) location records" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "Failed to extract location data: $($_.Exception.Message)"
        return $null
    }
}