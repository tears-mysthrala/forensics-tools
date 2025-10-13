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
                Id            = $row._id
                ThreadId      = $row.thread_id
                Address       = $row.address
                Person        = $row.person
                Date          = [DateTime]::FromFileTimeUtc($row.date)
                DateSent      = if ($row.date_sent) { [DateTime]::FromFileTimeUtc($row.date_sent) } else { $null }
                Protocol      = $row.protocol
                Read          = [bool]$row.read
                Status        = $row.status
                Type          = $row.type
                Subject       = $row.subject
                Body          = $row.body
                ServiceCenter = $row.service_center
                Locked        = [bool]$row.locked
                ErrorCode     = $row.error_code
                Seen          = [bool]$row.seen
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
                Id           = $row._id
                ThreadId     = $row.thread_id
                Date         = [DateTime]::FromFileTimeUtc($row.date)
                DateSent     = if ($row.date_sent) { [DateTime]::FromFileTimeUtc($row.date_sent) } else { $null }
                Read         = [bool]$row.read
                MessageBox   = $row.msg_box
                Subject      = $row.sub
                ContentType  = $row.ct_t
                MessageClass = $row.m_cls
                MessageId    = $row.m_id
                MessageSize  = $row.m_size
                Priority     = $row.pri
                Locked       = [bool]$row.locked
                Seen         = [bool]$row.seen
            }
        }

        $connection.Close()
        Remove-Item $localPath -Force

        # Combine and export
        $result = [PSCustomObject]@{
            DeviceId       = $DeviceId
            ExtractionDate = Get-Date
            SMSMessages    = $messages
            MMSMessages    = $mmsMessages
            TotalMessages  = $messages.Count + $mmsMessages.Count
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