# MobileDeviceForensicsFunctions.ps1
# Mobile device forensics tools for Android and iOS analysis

<#
.SYNOPSIS
    Mobile Device Forensics Functions

.DESCRIPTION
    This module provides comprehensive mobile device forensics capabilities including:
    - Android device analysis and artifact extraction
    - iOS device backup analysis and data recovery
    - Mobile app data extraction and analysis
    - SMS, call logs, and contact analysis
    - Location data and timeline reconstruction
    - Social media and messaging app forensics

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: ADB for Android devices, iTunes/iCloud for iOS
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

# iOS Forensics Functions

function Get-iOSBackupInfo {
    <#
    .SYNOPSIS
        Analyzes iOS backup directory structure

    .DESCRIPTION
        Examines iOS backup files and extracts device information

    .PARAMETER BackupPath
        Path to iOS backup directory

    .EXAMPLE
        Get-iOSBackupInfo -BackupPath "C:\Users\User\AppData\Roaming\Apple Computer\MobileSync\Backup\backup_id"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    try {
        Write-Host "Analyzing iOS backup: $BackupPath" -ForegroundColor Cyan

        if (-not (Test-Path $BackupPath)) {
            throw "Backup path not found: $BackupPath"
        }

        # Read Info.plist for device information
        $infoPlistPath = Join-Path $BackupPath "Info.plist"
        if (-not (Test-Path $infoPlistPath)) {
            throw "Info.plist not found in backup directory"
        }

        # Parse Info.plist (simplified parsing)
        $infoContent = Get-Content $infoPlistPath -Raw
        $backupInfo = [PSCustomObject]@{
            BackupPath = $BackupPath
            Timestamp = Get-Date
            DeviceInfo = @{}
            Applications = @()
            Files = @()
        }

        # Extract basic device info from plist
        if ($infoContent -match '<key>Device Name</key>\s*<string>([^<]+)</string>') {
            $backupInfo.DeviceInfo["DeviceName"] = $matches[1]
        }
        if ($infoContent -match '<key>Product Type</key>\s*<string>([^<]+)</string>') {
            $backupInfo.DeviceInfo["ProductType"] = $matches[1]
        }
        if ($infoContent -match '<key>Product Version</key>\s*<string>([^<]+)</string>') {
            $backupInfo.DeviceInfo["ProductVersion"] = $matches[1]
        }
        if ($infoContent -match '<key>Serial Number</key>\s*<string>([^<]+)</string>') {
            $backupInfo.DeviceInfo["SerialNumber"] = $matches[1]
        }

        # Get all files in backup
        $backupFiles = Get-ChildItem $BackupPath -File | Where-Object { $_.Name -notmatch '^Info\.plist$|^Manifest\.plist$|^Status\.plist$' }

        foreach ($file in $backupFiles) {
            $fileInfo = [PSCustomObject]@{
                FileName = $file.Name
                Size = $file.Length
                LastModified = $file.LastWriteTime
                Domain = ""
                Path = ""
            }

            # Try to determine domain and path from filename (SHA1 hash)
            # In a real implementation, you'd read the Manifest.plist to map hashes to paths
            $backupInfo.Files += $fileInfo
        }

        Write-Host "iOS backup analysis completed. Found $($backupInfo.Files.Count) files" -ForegroundColor Green
        return $backupInfo
    }
    catch {
        Write-Error "Failed to analyze iOS backup: $($_.Exception.Message)"
        return $null
    }
}

function Get-iOSMessages {
    <#
    .SYNOPSIS
        Extracts iOS messages from backup

    .DESCRIPTION
        Retrieves SMS and iMessage data from iOS backup files

    .PARAMETER BackupPath
        Path to iOS backup directory

    .PARAMETER OutputPath
        Path to save extracted messages

    .EXAMPLE
        Get-iOSMessages -BackupPath "C:\Backup" -OutputPath "C:\Evidence\ios_messages.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Extracting iOS messages from backup..." -ForegroundColor Cyan

        # Find SMS database file (would need to identify the correct SHA1 hash from Manifest.plist)
        # For this implementation, we'll look for common SMS database patterns
        $smsFiles = Get-ChildItem $BackupPath -File | Where-Object {
            $_.Name -match '^[a-f0-9]{40}$' -and $_.Length -gt 1000000  # Large files that might be SMS db
        }

        $messages = @()

        foreach ($file in $smsFiles) {
            try {
                # Try to open as SQLite database
                $connectionString = "Data Source=$($file.FullName);Version=3;Read Only=True;"
                $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
                $connection.Open()

                # Check if this is the SMS database
                $tableQuery = "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%message%'"
                $command = $connection.CreateCommand()
                $command.CommandText = $tableQuery
                $reader = $command.ExecuteReader()

                if ($reader.HasRows) {
                    # This appears to be the SMS database
                    $messageQuery = @"
SELECT
    m.ROWID,
    m.guid,
    m.text,
    m.handle_id,
    m.service,
    m.date,
    m.date_read,
    m.date_delivered,
    m.is_from_me,
    m.is_read,
    m.is_sent,
    m.is_delivered,
    h.id as phone_number,
    c.display_name
FROM message m
LEFT JOIN handle h ON m.handle_id = h.ROWID
LEFT JOIN chat_message_join cmj ON m.ROWID = cmj.message_id
LEFT JOIN chat c ON cmj.chat_id = c.ROWID
ORDER BY m.date DESC
"@

                    $msgCommand = $connection.CreateCommand()
                    $msgCommand.CommandText = $messageQuery
                    $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($msgCommand)
                    $dataSet = New-Object System.Data.DataSet
                    $adapter.Fill($dataSet) | Out-Null

                    foreach ($row in $dataSet.Tables[0].Rows) {
                        $messages += [PSCustomObject]@{
                            Id = $row.ROWID
                            Guid = $row.guid
                            Text = $row.text
                            PhoneNumber = $row.phone_number
                            DisplayName = $row.display_name
                            Service = $row.service
                            Date = [DateTime]::FromFileTimeUtc(($row.date + 978307200) * 10000000)  # Convert from Cocoa timestamp
                            DateRead = if ($row.date_read) { [DateTime]::FromFileTimeUtc(($row.date_read + 978307200) * 10000000) } else { $null }
                            DateDelivered = if ($row.date_delivered) { [DateTime]::FromFileTimeUtc(($row.date_delivered + 978307200) * 10000000) } else { $null }
                            IsFromMe = [bool]$row.is_from_me
                            IsRead = [bool]$row.is_read
                            IsSent = [bool]$row.is_sent
                            IsDelivered = [bool]$row.is_delivered
                        }
                    }

                    break  # Found the SMS database, no need to check other files
                }

                $connection.Close()
            }
            catch {
                # Not the SMS database, continue
                continue
            }
        }

        # Export results
        $result = [PSCustomObject]@{
            BackupPath = $BackupPath
            ExtractionDate = Get-Date
            Messages = $messages
            TotalMessages = $messages.Count
        }

        $result | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8

        Write-Host "iOS messages extraction completed. Found $($messages.Count) messages" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "Failed to extract iOS messages: $($_.Exception.Message)"
        return $null
    }
}

function Get-iOSContacts {
    <#
    .SYNOPSIS
        Extracts iOS contacts from backup

    .DESCRIPTION
        Retrieves contact information from iOS backup AddressBook database

    .PARAMETER BackupPath
        Path to iOS backup directory

    .PARAMETER OutputPath
        Path to save extracted contacts

    .EXAMPLE
        Get-iOSContacts -BackupPath "C:\Backup" -OutputPath "C:\Evidence\ios_contacts.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Extracting iOS contacts from backup..." -ForegroundColor Cyan

        # Find AddressBook database
        $abFiles = Get-ChildItem $BackupPath -File | Where-Object {
            $_.Name -match '^[a-f0-9]{40}$' -and $_.Length -gt 100000
        }

        $contacts = @()

        foreach ($file in $abFiles) {
            try {
                $connectionString = "Data Source=$($file.FullName);Version=3;Read Only=True;"
                $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
                $connection.Open()

                # Check if this is the AddressBook database
                $tableQuery = "SELECT name FROM sqlite_master WHERE type='table' AND name='ABPerson'"
                $command = $connection.CreateCommand()
                $command.CommandText = $tableQuery
                $reader = $command.ExecuteReader()

                if ($reader.HasRows) {
                    # This is the AddressBook database
                    $contactQuery = @"
SELECT
    p.ROWID,
    p.First,
    p.Last,
    p.Middle,
    p.Organization,
    p.Department,
    p.JobTitle,
    p.Note,
    p.Nickname,
    p.Birthday,
    p.CreationDate,
    p.ModificationDate
FROM ABPerson p
ORDER BY p.Last, p.First
"@

                    $contactCommand = $connection.CreateCommand()
                    $contactCommand.CommandText = $contactQuery
                    $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($contactCommand)
                    $dataSet = New-Object System.Data.DataSet
                    $adapter.Fill($dataSet) | Out-Null

                    foreach ($row in $dataSet.Tables[0].Rows) {
                        # Get phone numbers
                        $phoneQuery = "SELECT value FROM ABMultiValue WHERE record_id = $($row.ROWID) AND property = 3"  # Phone property
                        $phoneCommand = $connection.CreateCommand()
                        $phoneCommand.CommandText = $phoneQuery
                        $phoneAdapter = New-Object System.Data.SQLite.SQLiteDataAdapter($phoneCommand)
                        $phoneDataSet = New-Object System.Data.DataSet
                        $phoneAdapter.Fill($phoneDataSet) | Out-Null

                        $phoneNumbers = @()
                        foreach ($phoneRow in $phoneDataSet.Tables[0].Rows) {
                            $phoneNumbers += $phoneRow.value
                        }

                        # Get email addresses
                        $emailQuery = "SELECT value FROM ABMultiValue WHERE record_id = $($row.ROWID) AND property = 4"  # Email property
                        $emailCommand = $connection.CreateCommand()
                        $emailCommand.CommandText = $emailQuery
                        $emailAdapter = New-Object System.Data.SQLite.SQLiteDataAdapter($emailCommand)
                        $emailDataSet = New-Object System.Data.DataSet
                        $emailAdapter.Fill($emailDataSet) | Out-Null

                        $emails = @()
                        foreach ($emailRow in $emailDataSet.Tables[0].Rows) {
                            $emails += $emailRow.email
                        }

                        $contacts += [PSCustomObject]@{
                            Id = $row.ROWID
                            FirstName = $row.First
                            LastName = $row.Last
                            MiddleName = $row.Middle
                            Organization = $row.Organization
                            Department = $row.Department
                            JobTitle = $row.JobTitle
                            PhoneNumbers = $phoneNumbers
                            Emails = $emails
                            Note = $row.Note
                            Nickname = $row.Nickname
                            Birthday = if ($row.Birthday) { [DateTime]::FromFileTimeUtc(($row.Birthday + 978307200) * 10000000) } else { $null }
                            CreationDate = if ($row.CreationDate) { [DateTime]::FromFileTimeUtc(($row.CreationDate + 978307200) * 10000000) } else { $null }
                            ModificationDate = if ($row.ModificationDate) { [DateTime]::FromFileTimeUtc(($row.ModificationDate + 978307200) * 10000000) } else { $null }
                        }
                    }

                    break  # Found the AddressBook database
                }

                $connection.Close()
            }
            catch {
                continue
            }
        }

        # Export results
        $result = [PSCustomObject]@{
            BackupPath = $BackupPath
            ExtractionDate = Get-Date
            Contacts = $contacts
            TotalContacts = $contacts.Count
        }

        $result | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8

        Write-Host "iOS contacts extraction completed. Found $($contacts.Count) contacts" -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "Failed to extract iOS contacts: $($_.Exception.Message)"
        return $null
    }
}

function Export-MobileDeviceReport {
    <#
    .SYNOPSIS
        Generates comprehensive mobile device forensics report

    .DESCRIPTION
        Creates HTML report combining all mobile device evidence

    .PARAMETER DeviceData
        Array of mobile device data objects

    .PARAMETER OutputPath
        Path for the HTML report

    .EXAMPLE
        $androidData = Get-AndroidDeviceInfo
        $smsData = Get-AndroidSMSMessages -DeviceId $androidData.DeviceId -OutputPath "temp.json"
        Export-MobileDeviceReport -DeviceData @($androidData, $smsData) -OutputPath "C:\Evidence\mobile_report.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$DeviceData,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Generating mobile device forensics report..." -ForegroundColor Cyan

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>🔍 Mobile Device Forensics Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .section { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section-header { background: #667eea; color: white; padding: 15px; margin: 0; border-radius: 8px 8px 0 0; }
        .section-content { padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; color: #667eea; }
        .message-preview { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📱 Mobile Device Forensics Report</h1>
        <h2>Digital Evidence Analysis</h2>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>

    <div class="summary">
"@

        # Calculate summary metrics
        $totalMessages = 0
        $totalContacts = 0
        $totalCalls = 0
        $deviceType = "Unknown"

        foreach ($data in $DeviceData) {
            if ($data.PSObject.Properties.Name -contains "SMSMessages") {
                $totalMessages += $data.SMSMessages.Count
            }
            if ($data.PSObject.Properties.Name -contains "MMSMessages") {
                $totalMessages += $data.MMSMessages.Count
            }
            if ($data.PSObject.Properties.Name -contains "Messages") {
                $totalMessages += $data.Messages.Count
            }
            if ($data.PSObject.Properties.Name -contains "Contacts") {
                $totalContacts += $data.Contacts.Count
            }
            if ($data.PSObject.Properties.Name -contains "CallLogs") {
                $totalCalls += $data.CallLogs.Count
            }
            if ($data.PSObject.Properties.Name -contains "HardwareInfo") {
                $deviceType = "Android"
            }
            if ($data.PSObject.Properties.Name -contains "BackupPath") {
                $deviceType = "iOS"
            }
        }

        $html += @"
        <div class="metric">
            <h3>Device Type</h3>
            <div class="value">$deviceType</div>
        </div>
        <div class="metric">
            <h3>Messages</h3>
            <div class="value">$totalMessages</div>
        </div>
        <div class="metric">
            <h3>Contacts</h3>
            <div class="value">$totalContacts</div>
        </div>
        <div class="metric">
            <h3>Call Records</h3>
            <div class="value">$totalCalls</div>
        </div>
    </div>
"@

        # Device Information Section
        foreach ($data in $DeviceData) {
            if ($data.PSObject.Properties.Name -contains "HardwareInfo") {
                $html += @"

    <div class="section">
        <h2 class="section-header">📱 Device Information</h2>
        <div class="section-content">
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Device ID</td><td>$($data.DeviceId)</td></tr>
                <tr><td>Model</td><td>$($data.HardwareInfo.Model)</td></tr>
                <tr><td>Manufacturer</td><td>$($data.HardwareInfo.Manufacturer)</td></tr>
                <tr><td>Android Version</td><td>$($data.HardwareInfo.AndroidVersion)</td></tr>
                <tr><td>API Level</td><td>$($data.HardwareInfo.APILevel)</td></tr>
                <tr><td>Build Number</td><td>$($data.HardwareInfo.BuildNumber)</td></tr>
            </table>
        </div>
    </div>
"@
            }
        }

        # Messages Section
        foreach ($data in $DeviceData) {
            if ($data.PSObject.Properties.Name -contains "SMSMessages" -and $data.SMSMessages.Count -gt 0) {
                $html += @"

    <div class="section">
        <h2 class="section-header">💬 SMS Messages ($($data.SMSMessages.Count))</h2>
        <div class="section-content">
            <table>
                <tr>
                    <th>Date</th>
                    <th>Address</th>
                    <th>Type</th>
                    <th>Message</th>
                </tr>
"@

                foreach ($message in $data.SMSMessages | Select-Object -First 50) {
                    $typeText = switch ($message.Type) {
                        1 { "Received" }
                        2 { "Sent" }
                        default { "Unknown" }
                    }
                    $html += @"
                <tr>
                    <td>$($message.Date.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                    <td>$($message.Address)</td>
                    <td>$typeText</td>
                    <td class="message-preview">$($message.Body)</td>
                </tr>
"@
                }

                $html += @"
            </table>
        </div>
    </div>
"@
            }
        }

        # Contacts Section
        foreach ($data in $DeviceData) {
            if ($data.PSObject.Properties.Name -contains "Contacts" -and $data.Contacts.Count -gt 0) {
                $html += @"

    <div class="section">
        <h2 class="section-header">👥 Contacts ($($data.Contacts.Count))</h2>
        <div class="section-content">
            <table>
                <tr>
                    <th>Name</th>
                    <th>Phone Numbers</th>
                    <th>Emails</th>
                    <th>Last Contacted</th>
                </tr>
"@

                foreach ($contact in $data.Contacts | Select-Object -First 50) {
                    $phones = if ($contact.PhoneNumbers) { $contact.PhoneNumbers -join "; " } else { "" }
                    $emails = if ($contact.Emails) { $contact.Emails -join "; " } else { "" }
                    $name = if ($contact.DisplayName) { $contact.DisplayName } elseif ($contact.FirstName -or $contact.LastName) { "$($contact.FirstName) $($contact.LastName)".Trim() } else { "Unknown" }
                    $lastContact = if ($contact.LastTimeContacted) { $contact.LastTimeContacted.ToString('yyyy-MM-dd HH:mm:ss') } else { "Never" }

                    $html += @"
                <tr>
                    <td>$name</td>
                    <td>$phones</td>
                    <td>$emails</td>
                    <td>$lastContact</td>
                </tr>
"@
                }

                $html += @"
            </table>
        </div>
    </div>
"@
            }
        }

        $html += @"
</body>
</html>
"@

        $html | Out-File $OutputPath -Encoding UTF8

        Write-Host "Mobile device forensics report generated: $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to generate mobile device report: $($_.Exception.Message)"
        return $false
    }
}