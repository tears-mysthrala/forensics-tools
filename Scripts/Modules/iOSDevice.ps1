# iOSDeviceFunctions.ps1
# iOS device forensics functions

<#
.SYNOPSIS
    iOS Device Forensics Functions

.DESCRIPTION
    This module provides functions for analyzing iOS devices including
    backup analysis, messages, and contacts extraction.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: iTunes or iCloud access for iOS backups
#>

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