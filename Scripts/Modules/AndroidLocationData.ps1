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
                        Latitude  = $row.latitude
                        Longitude = $row.longitude
                        Accuracy  = $row.accuracy
                        Altitude  = $row.altitude
                        Source    = "Google Location History"
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
                        SSID      = $matches[1]
                        Timestamp = Get-Date
                        Source    = "WiFi Scan"
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not retrieve WiFi scan data: $($_.Exception.Message)"
        }

        # Export results
        $result = [PSCustomObject]@{
            DeviceId        = $DeviceId
            ExtractionDate  = Get-Date
            LocationHistory = $locations
            WiFiData        = $wifiData
            TotalLocations  = $locations.Count
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