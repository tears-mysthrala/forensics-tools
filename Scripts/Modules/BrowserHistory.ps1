# BrowserHistoryFunctions.ps1
# Browser history analysis functions

function Get-BrowserHistory {
    <#
    .SYNOPSIS
        Extracts browser history from browser databases

    .DESCRIPTION
        Parses browser history databases and extracts URL visit information

    .PARAMETER Browser
        Browser to analyze (Chrome, Firefox, Edge)

    .PARAMETER ProfilePath
        Path to browser profile

    .PARAMETER DaysBack
        Number of days of history to retrieve

    .PARAMETER SearchTerm
        Filter results by search term in URL or title

    .EXAMPLE
        Get-BrowserHistory -Browser Chrome -ProfilePath "C:\Users\John\AppData\Local\Google\Chrome\User Data\Default"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Chrome", "Firefox", "Edge")]
        [string]$Browser,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 30,

        [Parameter(Mandatory = $false)]
        [string]$SearchTerm
    )

    try {
        Write-Host "Extracting $Browser history from $ProfilePath..." -ForegroundColor Cyan

        $historyItems = @()
        $cutoffDate = (Get-Date).AddDays(-$DaysBack)

        switch ($Browser) {
            "Chrome" {
                $historyFile = Join-Path $ProfilePath "History"
                if (Test-Path $historyFile) {
                    $historyItems = Get-ChromeHistory -HistoryFile $historyFile -CutoffDate $cutoffDate -SearchTerm $SearchTerm
                }
            }
            "Firefox" {
                $placesFile = Join-Path $ProfilePath "places.sqlite"
                if (Test-Path $placesFile) {
                    $historyItems = Get-FirefoxHistory -PlacesFile $placesFile -CutoffDate $cutoffDate -SearchTerm $SearchTerm
                }
            }
            "Edge" {
                $historyFile = Join-Path $ProfilePath "History"
                if (Test-Path $historyFile) {
                    $historyItems = Get-ChromeHistory -HistoryFile $historyFile -CutoffDate $cutoffDate -SearchTerm $SearchTerm
                }
            }
        }

        Write-Host "Extracted $($historyItems.Count) history items" -ForegroundColor Green
        return $historyItems
    }
    catch {
        Write-Error "Failed to extract browser history: $($_.Exception.Message)"
        return $null
    }
}

function Get-ChromeHistory {
    <#
    .SYNOPSIS
        Parses Chrome/Edge history database

    .DESCRIPTION
        Extracts history data from Chrome/Edge SQLite database

    .PARAMETER HistoryFile
        Path to History file

    .PARAMETER CutoffDate
        Only return items after this date

    .PARAMETER SearchTerm
        Filter by search term
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HistoryFile,

        [Parameter(Mandatory = $true)]
        [DateTime]$CutoffDate,

        [Parameter(Mandatory = $false)]
        [string]$SearchTerm
    )

    try {
        # Copy database to avoid locking issues
        $tempFile = [System.IO.Path]::GetTempFileName() + ".db"
        Copy-Item $HistoryFile $tempFile -Force

        # Connect to database
        $connectionString = "Data Source=$tempFile;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Query history
        $query = @"
SELECT
    urls.url,
    urls.title,
    urls.visit_count,
    urls.last_visit_time,
    visits.visit_time,
    visits.from_visit,
    visit_source.source
FROM urls
LEFT JOIN visits ON urls.id = visits.url
LEFT JOIN visit_source ON visits.id = visit_source.id
WHERE visits.visit_time > ?
ORDER BY visits.visit_time DESC
"@

        $command = $connection.CreateCommand()
        $command.CommandText = $query

        # Convert cutoff date to Chrome timestamp (microseconds since 1601-01-01)
        $chromeEpoch = Get-Date "1601-01-01"
        $cutoffTimestamp = [math]::Floor((($CutoffDate - $chromeEpoch).TotalSeconds) * 1000000)
        $command.Parameters.AddWithValue("@cutoff", $cutoffTimestamp) | Out-Null

        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $historyItems = @()

        foreach ($row in $dataSet.Tables[0].Rows) {
            # Convert Chrome timestamp to DateTime
            $visitTime = $chromeEpoch.AddSeconds($row.visit_time / 1000000)

            # Apply search filter
            if ($SearchTerm) {
                $matchesSearch = $row.url -like "*$SearchTerm*" -or $row.title -like "*$SearchTerm*"
                if (-not $matchesSearch) { continue }
            }

            $historyItems += [PSCustomObject]@{
                URL = $row.url
                Title = $row.title
                VisitCount = $row.visit_count
                LastVisitTime = $visitTime
                VisitTime = $visitTime
                FromVisit = $row.from_visit
                Source = $row.source
                Browser = "Chrome"
                Timestamp = Get-Date
            }
        }

        $connection.Close()
        Remove-Item $tempFile -Force

        return $historyItems
    }
    catch {
        Write-Warning "Failed to parse Chrome history: $($_.Exception.Message)"
        return @()
    }
}

function Get-FirefoxHistory {
    <#
    .SYNOPSIS
        Parses Firefox places.sqlite database

    .DESCRIPTION
        Extracts history data from Firefox SQLite database

    .PARAMETER PlacesFile
        Path to places.sqlite file

    .PARAMETER CutoffDate
        Only return items after this date

    .PARAMETER SearchTerm
        Filter by search term
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlacesFile,

        [Parameter(Mandatory = $true)]
        [DateTime]$CutoffDate,

        [Parameter(Mandatory = $false)]
        [string]$SearchTerm
    )

    try {
        # Copy database to avoid locking issues
        $tempFile = [System.IO.Path]::GetTempFileName() + ".db"
        Copy-Item $PlacesFile $tempFile -Force

        # Connect to database
        $connectionString = "Data Source=$tempFile;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Query history
        $query = @"
SELECT
    moz_places.url,
    moz_places.title,
    moz_places.visit_count,
    moz_places.last_visit_date,
    moz_historyvisits.visit_date,
    moz_historyvisits.from_visit,
    moz_historyvisits.visit_type
FROM moz_places
LEFT JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
WHERE moz_historyvisits.visit_date > ?
ORDER BY moz_historyvisits.visit_date DESC
"@

        $command = $connection.CreateCommand()
        $command.CommandText = $query

        # Convert cutoff date to Firefox timestamp (microseconds since 1970-01-01)
        $firefoxEpoch = Get-Date "1970-01-01"
        $cutoffTimestamp = [math]::Floor((($CutoffDate - $firefoxEpoch).TotalSeconds) * 1000000)
        $command.Parameters.AddWithValue("@cutoff", $cutoffTimestamp) | Out-Null

        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $historyItems = @()

        foreach ($row in $dataSet.Tables[0].Rows) {
            # Convert Firefox timestamp to DateTime
            $visitTime = $firefoxEpoch.AddSeconds($row.visit_date / 1000000)

            # Apply search filter
            if ($SearchTerm) {
                $matchesSearch = $row.url -like "*$SearchTerm*" -or $row.title -like "*$SearchTerm*"
                if (-not $matchesSearch) { continue }
            }

            $historyItems += [PSCustomObject]@{
                URL = $row.url
                Title = $row.title
                VisitCount = $row.visit_count
                LastVisitTime = $firefoxEpoch.AddSeconds($row.last_visit_date / 1000000)
                VisitTime = $visitTime
                FromVisit = $row.from_visit
                VisitType = $row.visit_type
                Browser = "Firefox"
                Timestamp = Get-Date
            }
        }

        $connection.Close()
        Remove-Item $tempFile -Force

        return $historyItems
    }
    catch {
        Write-Warning "Failed to parse Firefox history: $($_.Exception.Message)"
        return @()
    }
}