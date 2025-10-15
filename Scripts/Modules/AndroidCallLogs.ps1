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
                Id               = $row._id
                Number           = $row.number
                Date             = [DateTime]::FromFileTimeUtc($row.date)
                Duration         = $row.duration
                Type             = switch ($row.type) {
                    1 { "Incoming" }
                    2 { "Outgoing" }
                    3 { "Missed" }
                    4 { "Voicemail" }
                    5 { "Rejected" }
                    6 { "Blocked" }
                    default { "Unknown" }
                }
                New              = [bool]$row.new
                Name             = $row.name
                NumberType       = $row.numbertype
                NumberLabel      = $row.numberlabel
                CountryISO       = $row.countryiso
                GeocodedLocation = $row.geocoded_location
                IsRead           = [bool]$row.is_read
            }
        }

        $connection.Close()
        Remove-Item $localPath -Force

        # Export results
        $result = [PSCustomObject]@{
            DeviceId       = $DeviceId
            ExtractionDate = Get-Date
            CallLogs       = $calls
            TotalCalls     = $calls.Count
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