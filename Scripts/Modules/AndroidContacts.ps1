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
                    Type   = $phoneRow.type
                    Label  = $phoneRow.label
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
                    Type  = $emailRow.type
                    Label = $emailRow.label
                }
            }

            $contacts += [PSCustomObject]@{
                Id                = $row._id
                DisplayName       = $row.display_name
                DisplayNameAlt    = $row.display_name_alt
                PhoneNumbers      = $phoneNumbers
                Emails            = $emails
                TimesContacted    = $row.times_contacted
                LastTimeContacted = if ($row.last_time_contacted) { [DateTime]::FromFileTimeUtc($row.last_time_contacted) } else { $null }
                Starred           = [bool]$row.starred
                Pinned            = [bool]$row.pinned
                HasPhoneNumber    = [bool]$row.has_phone_number
                HasEmail          = [bool]$row.has_email
                LastUpdated       = if ($row.contact_last_updated_timestamp) { [DateTime]::FromFileTimeUtc($row.contact_last_updated_timestamp) } else { $null }
            }
        }

        $connection.Close()
        Remove-Item $localPath -Force

        # Export results
        $result = [PSCustomObject]@{
            DeviceId       = $DeviceId
            ExtractionDate = Get-Date
            Contacts       = $contacts
            TotalContacts  = $contacts.Count
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