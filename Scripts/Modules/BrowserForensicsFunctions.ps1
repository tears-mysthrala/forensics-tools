# BrowserForensicsFunctions.ps1
# Browser forensics functions for digital investigations

<#
.SYNOPSIS
    Browser Forensics Functions

.DESCRIPTION
    This module provides comprehensive browser forensics capabilities including:
    - Browser history analysis from multiple browsers
    - Cache examination and artifact extraction
    - Cookie analysis and session data recovery
    - Bookmark and saved password analysis
    - Timeline reconstruction of browser activity

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: SQLite database access for browser databases
#>

# Browser Profile Detection Functions

function Get-BrowserProfiles {
    <#
    .SYNOPSIS
        Detects and enumerates browser profiles on the system

    .DESCRIPTION
        Scans for installed browsers and their user profiles containing forensic data

    .PARAMETER Browser
        Specific browser to scan (Chrome, Firefox, Edge, Safari, Opera)

    .PARAMETER UserProfiles
        Specific user profiles to scan

    .EXAMPLE
        Get-BrowserProfiles
        Get-BrowserProfiles -Browser Chrome
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Chrome", "Firefox", "Edge", "Safari", "Opera", "All")]
        [string]$Browser = "All",

        [Parameter(Mandatory = $false)]
        [string[]]$UserProfiles
    )

    try {
        Write-Host "Scanning for browser profiles..." -ForegroundColor Cyan

        $browserProfiles = @()
        $browsersToScan = if ($Browser -eq "All") { @("Chrome", "Firefox", "Edge", "Safari", "Opera") } else { @($Browser) }

        # Get user profiles to scan
        if (-not $UserProfiles) {
            $UserProfiles = Get-ChildItem "C:\Users" -Directory | Select-Object -ExpandProperty Name
        }

        foreach ($user in $UserProfiles) {
            $userPath = "C:\Users\$user"

            if (-not (Test-Path $userPath)) {
                continue
            }

            foreach ($browserName in $browsersToScan) {
                $profile = Get-BrowserProfilePath -Browser $browserName -UserPath $userPath

                if ($profile) {
                    $browserProfiles += [PSCustomObject]@{
                        Browser = $browserName
                        User = $user
                        ProfilePath = $profile.Path
                        ProfileName = $profile.Name
                        LastModified = $profile.LastModified
                        SizeMB = $profile.SizeMB
                        Timestamp = Get-Date
                    }
                }
            }
        }

        Write-Host "Found $($browserProfiles.Count) browser profiles" -ForegroundColor Green
        return $browserProfiles
    }
    catch {
        Write-Error "Failed to scan browser profiles: $($_.Exception.Message)"
        return $null
    }
}

function Get-BrowserProfilePath {
    <#
    .SYNOPSIS
        Gets the profile path for a specific browser

    .DESCRIPTION
        Returns the local application data path for browser profiles

    .PARAMETER Browser
        Browser name

    .PARAMETER UserPath
        User profile path

    .EXAMPLE
        Get-BrowserProfilePath -Browser Chrome -UserPath "C:\Users\John"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser,

        [Parameter(Mandatory = $true)]
        [string]$UserPath
    )

    $browserPaths = @{
        "Chrome" = @{
            Path = "$UserPath\AppData\Local\Google\Chrome\User Data"
            Profiles = "Default", "Profile 1", "Profile 2", "Profile 3"
        }
        "Firefox" = @{
            Path = "$UserPath\AppData\Roaming\Mozilla\Firefox\Profiles"
            Profiles = "*.default*", "*.default-release*"
        }
        "Edge" = @{
            Path = "$UserPath\AppData\Local\Microsoft\Edge\User Data"
            Profiles = "Default", "Profile 1", "Profile 2", "Profile 3"
        }
        "Safari" = @{
            Path = "$UserPath\AppData\Roaming\Apple Computer\Safari"
            Profiles = "."
        }
        "Opera" = @{
            Path = "$UserPath\AppData\Roaming\Opera Software\Opera Stable"
            Profiles = "."
        }
    }

    if (-not $browserPaths.ContainsKey($Browser)) {
        return $null
    }

    $browserConfig = $browserPaths[$Browser]

    if (-not (Test-Path $browserConfig.Path)) {
        return $null
    }

    # Handle different profile structures
    $profiles = @()

    if ($Browser -eq "Firefox") {
        # Firefox uses profile directories with specific naming
        $profileDirs = Get-ChildItem $browserConfig.Path -Directory | Where-Object {
            $_.Name -like "*.default*" -or $_.Name -like "*.default-release*"
        }
        foreach ($dir in $profileDirs) {
            $profiles += @{
                Path = $dir.FullName
                Name = $dir.Name
                LastModified = $dir.LastWriteTime
                SizeMB = [math]::Round((Get-ChildItem $dir.FullName -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
            }
        }
    }
    else {
        # Chrome, Edge, etc. use named profile directories
        foreach ($profileName in $browserConfig.Profiles) {
            $profilePath = Join-Path $browserConfig.Path $profileName
            if (Test-Path $profilePath) {
                $profiles += @{
                    Path = $profilePath
                    Name = $profileName
                    LastModified = (Get-Item $profilePath).LastWriteTime
                    SizeMB = [math]::Round((Get-ChildItem $profilePath -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
                }
            }
        }
    }

    return $profiles
}

# Browser History Analysis Functions

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

# Browser Cache Analysis Functions

function Get-BrowserCache {
    <#
    .SYNOPSIS
        Analyzes browser cache files

    .DESCRIPTION
        Extracts and analyzes cached files from browser cache directories

    .PARAMETER Browser
        Browser to analyze

    .PARAMETER ProfilePath
        Path to browser profile

    .PARAMETER OutputPath
        Path to save extracted cache files

    .EXAMPLE
        Get-BrowserCache -Browser Chrome -ProfilePath "C:\Users\John\AppData\Local\Google\Chrome\User Data\Default"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Chrome", "Firefox", "Edge")]
        [string]$Browser,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )

    try {
        Write-Host "Analyzing $Browser cache..." -ForegroundColor Cyan

        if (-not $OutputPath) {
            $OutputPath = Join-Path $env:TEMP "BrowserCache_$Browser_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
        }

        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath | Out-Null
        }

        $cacheItems = @()

        switch ($Browser) {
            "Chrome" {
                $cacheDir = Join-Path $ProfilePath "Cache"
                if (Test-Path $cacheDir) {
                    $cacheItems = Get-ChromeCache -CacheDir $cacheDir -OutputPath $OutputPath
                }
            }
            "Firefox" {
                $cacheDir = Join-Path $ProfilePath "cache2"
                if (Test-Path $cacheDir) {
                    $cacheItems = Get-FirefoxCache -CacheDir $cacheDir -OutputPath $OutputPath
                }
            }
            "Edge" {
                $cacheDir = Join-Path $ProfilePath "Cache"
                if (Test-Path $cacheDir) {
                    $cacheItems = Get-ChromeCache -CacheDir $cacheDir -OutputPath $OutputPath
                }
            }
        }

        Write-Host "Extracted $($cacheItems.Count) cache items to $OutputPath" -ForegroundColor Green
        return [PSCustomObject]@{
            CacheItems = $cacheItems
            OutputPath = $OutputPath
            Browser = $Browser
            Timestamp = Get-Date
        }
    }
    catch {
        Write-Error "Failed to analyze browser cache: $($_.Exception.Message)"
        return $null
    }
}

function Get-ChromeCache {
    <#
    .SYNOPSIS
        Extracts Chrome/Edge cache files

    .DESCRIPTION
        Parses Chrome cache directory and extracts cached content

    .PARAMETER CacheDir
        Path to cache directory

    .PARAMETER OutputPath
        Path to save extracted files
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CacheDir,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        $cacheItems = @()

        # Get cache files (data_0, data_1, etc.)
        $cacheFiles = Get-ChildItem $CacheDir -File -Filter "data_*" | Where-Object { $_.Name -match "^data_\d+$" }

        foreach ($cacheFile in $cacheFiles) {
            try {
                # Basic cache file parsing (simplified)
                $fileInfo = Get-Item $cacheFile.FullName

                $cacheItems += [PSCustomObject]@{
                    FileName = $cacheFile.Name
                    FullPath = $cacheFile.FullName
                    Size = $fileInfo.Length
                    LastModified = $fileInfo.LastWriteTime
                    CacheType = "Chrome Cache Block"
                    ExtractedPath = $null
                    Browser = "Chrome"
                    Timestamp = Get-Date
                }
            }
            catch {
                Write-Warning "Failed to process cache file $($cacheFile.Name): $($_.Exception.Message)"
            }
        }

        return $cacheItems
    }
    catch {
        Write-Warning "Failed to parse Chrome cache: $($_.Exception.Message)"
        return @()
    }
}

function Get-FirefoxCache {
    <#
    .SYNOPSIS
        Extracts Firefox cache files

    .DESCRIPTION
        Parses Firefox cache2 directory and extracts cached content

    .PARAMETER CacheDir
        Path to cache directory

    .PARAMETER OutputPath
        Path to save extracted files
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CacheDir,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        $cacheItems = @()

        # Get cache entries directory
        $entriesDir = Join-Path $CacheDir "entries"
        if (Test-Path $entriesDir) {
            $cacheFiles = Get-ChildItem $entriesDir -File -Recurse

            foreach ($cacheFile in $cacheFiles) {
                try {
                    $fileInfo = Get-Item $cacheFile.FullName

                    $cacheItems += [PSCustomObject]@{
                        FileName = $cacheFile.Name
                        FullPath = $cacheFile.FullName
                        Size = $fileInfo.Length
                        LastModified = $fileInfo.LastWriteTime
                        CacheType = "Firefox Cache Entry"
                        ExtractedPath = $null
                        Browser = "Firefox"
                        Timestamp = Get-Date
                    }
                }
                catch {
                    Write-Warning "Failed to process cache file $($cacheFile.Name): $($_.Exception.Message)"
                }
            }
        }

        return $cacheItems
    }
    catch {
        Write-Warning "Failed to parse Firefox cache: $($_.Exception.Message)"
        return @()
    }
}

# Cookie Analysis Functions

function Get-BrowserCookies {
    <#
    .SYNOPSIS
        Extracts and analyzes browser cookies

    .DESCRIPTION
        Parses browser cookie databases and extracts cookie information

    .PARAMETER Browser
        Browser to analyze

    .PARAMETER ProfilePath
        Path to browser profile

    .PARAMETER Domain
        Filter cookies by domain

    .EXAMPLE
        Get-BrowserCookies -Browser Chrome -ProfilePath "C:\Users\John\AppData\Local\Google\Chrome\User Data\Default"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Chrome", "Firefox", "Edge")]
        [string]$Browser,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [Parameter(Mandatory = $false)]
        [string]$Domain
    )

    try {
        Write-Host "Extracting $Browser cookies from $ProfilePath..." -ForegroundColor Cyan

        $cookies = @()

        switch ($Browser) {
            "Chrome" {
                $cookieFile = Join-Path $ProfilePath "Cookies"
                if (Test-Path $cookieFile) {
                    $cookies = Get-ChromeCookies -CookieFile $cookieFile -Domain $Domain
                }
            }
            "Firefox" {
                $cookieFile = Join-Path $ProfilePath "cookies.sqlite"
                if (Test-Path $cookieFile) {
                    $cookies = Get-FirefoxCookies -CookieFile $cookieFile -Domain $Domain
                }
            }
            "Edge" {
                $cookieFile = Join-Path $ProfilePath "Cookies"
                if (Test-Path $cookieFile) {
                    $cookies = Get-ChromeCookies -CookieFile $cookieFile -Domain $Domain
                }
            }
        }

        Write-Host "Extracted $($cookies.Count) cookies" -ForegroundColor Green
        return $cookies
    }
    catch {
        Write-Error "Failed to extract browser cookies: $($_.Exception.Message)"
        return $null
    }
}

function Get-ChromeCookies {
    <#
    .SYNOPSIS
        Parses Chrome/Edge Cookies database

    .DESCRIPTION
        Extracts cookie data from Chrome/Edge SQLite database

    .PARAMETER CookieFile
        Path to Cookies file

    .PARAMETER Domain
        Filter by domain
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CookieFile,

        [Parameter(Mandatory = $false)]
        [string]$Domain
    )

    try {
        # Copy database to avoid locking issues
        $tempFile = [System.IO.Path]::GetTempFileName() + ".db"
        Copy-Item $CookieFile $tempFile -Force

        # Connect to database
        $connectionString = "Data Source=$tempFile;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Query cookies
        $query = @"
SELECT
    host_key,
    name,
    value,
    path,
    expires_utc,
    is_secure,
    is_httponly,
    last_access_utc,
    creation_utc
FROM cookies
WHERE (? IS NULL OR host_key LIKE ?)
ORDER BY last_access_utc DESC
"@

        $command = $connection.CreateCommand()
        $command.CommandText = $query

        if ($Domain) {
            $command.Parameters.AddWithValue("@domain1", "%$Domain%") | Out-Null
            $command.Parameters.AddWithValue("@domain2", "%$Domain%") | Out-Null
        } else {
            $command.Parameters.AddWithValue("@domain1", $null) | Out-Null
            $command.Parameters.AddWithValue("@domain2", $null) | Out-Null
        }

        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $cookies = @()
        $chromeEpoch = Get-Date "1601-01-01"

        foreach ($row in $dataSet.Tables[0].Rows) {
            $cookies += [PSCustomObject]@{
                Domain = $row.host_key
                Name = $row.name
                Value = $row.value
                Path = $row.path
                Expires = if ($row.expires_utc -gt 0) { $chromeEpoch.AddSeconds($row.expires_utc / 1000000) } else { $null }
                Secure = [bool]$row.is_secure
                HttpOnly = [bool]$row.is_httponly
                LastAccess = $chromeEpoch.AddSeconds($row.last_access_utc / 1000000)
                Creation = $chromeEpoch.AddSeconds($row.creation_utc / 1000000)
                Browser = "Chrome"
                Timestamp = Get-Date
            }
        }

        $connection.Close()
        Remove-Item $tempFile -Force

        return $cookies
    }
    catch {
        Write-Warning "Failed to parse Chrome cookies: $($_.Exception.Message)"
        return @()
    }
}

function Get-FirefoxCookies {
    <#
    .SYNOPSIS
        Parses Firefox cookies.sqlite database

    .DESCRIPTION
        Extracts cookie data from Firefox SQLite database

    .PARAMETER CookieFile
        Path to cookies.sqlite file

    .PARAMETER Domain
        Filter by domain
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CookieFile,

        [Parameter(Mandatory = $false)]
        [string]$Domain
    )

    try {
        # Copy database to avoid locking issues
        $tempFile = [System.IO.Path]::GetTempFileName() + ".db"
        Copy-Item $CookieFile $tempFile -Force

        # Connect to database
        $connectionString = "Data Source=$tempFile;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Query cookies
        $query = @"
SELECT
    host,
    name,
    value,
    path,
    expiry,
    isSecure,
    isHttpOnly,
    lastAccessed,
    creationTime
FROM moz_cookies
WHERE (? IS NULL OR host LIKE ?)
ORDER BY lastAccessed DESC
"@

        $command = $connection.CreateCommand()
        $command.CommandText = $query

        if ($Domain) {
            $command.Parameters.AddWithValue("@domain1", "%$Domain%") | Out-Null
            $command.Parameters.AddWithValue("@domain2", "%$Domain%") | Out-Null
        } else {
            $command.Parameters.AddWithValue("@domain1", $null) | Out-Null
            $command.Parameters.AddWithValue("@domain2", $null) | Out-Null
        }

        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $cookies = @()
        $firefoxEpoch = Get-Date "1970-01-01"

        foreach ($row in $dataSet.Tables[0].Rows) {
            $cookies += [PSCustomObject]@{
                Domain = $row.host
                Name = $row.name
                Value = $row.value
                Path = $row.path
                Expires = if ($row.expiry -gt 0) { $firefoxEpoch.AddSeconds($row.expiry) } else { $null }
                Secure = [bool]$row.isSecure
                HttpOnly = [bool]$row.isHttpOnly
                LastAccess = $firefoxEpoch.AddSeconds($row.lastAccessed / 1000000)
                Creation = $firefoxEpoch.AddSeconds($row.creationTime / 1000000)
                Browser = "Firefox"
                Timestamp = Get-Date
            }
        }

        $connection.Close()
        Remove-Item $tempFile -Force

        return $cookies
    }
    catch {
        Write-Warning "Failed to parse Firefox cookies: $($_.Exception.Message)"
        return @()
    }
}

# Browser Bookmarks and Downloads Analysis

function Get-BrowserBookmarks {
    <#
    .SYNOPSIS
        Extracts browser bookmarks

    .DESCRIPTION
        Parses browser bookmark files and extracts bookmark information

    .PARAMETER Browser
        Browser to analyze

    .PARAMETER ProfilePath
        Path to browser profile

    .EXAMPLE
        Get-BrowserBookmarks -Browser Chrome -ProfilePath "C:\Users\John\AppData\Local\Google\Chrome\User Data\Default"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Chrome", "Firefox", "Edge")]
        [string]$Browser,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath
    )

    try {
        Write-Host "Extracting $Browser bookmarks from $ProfilePath..." -ForegroundColor Cyan

        $bookmarks = @()

        switch ($Browser) {
            "Chrome" {
                $bookmarkFile = Join-Path $ProfilePath "Bookmarks"
                if (Test-Path $bookmarkFile) {
                    $bookmarks = Get-ChromeBookmarks -BookmarkFile $bookmarkFile
                }
            }
            "Firefox" {
                $bookmarkFile = Join-Path $ProfilePath "places.sqlite"
                if (Test-Path $bookmarkFile) {
                    $bookmarks = Get-FirefoxBookmarks -PlacesFile $bookmarkFile
                }
            }
            "Edge" {
                $bookmarkFile = Join-Path $ProfilePath "Bookmarks"
                if (Test-Path $bookmarkFile) {
                    $bookmarks = Get-ChromeBookmarks -BookmarkFile $bookmarkFile
                }
            }
        }

        Write-Host "Extracted $($bookmarks.Count) bookmarks" -ForegroundColor Green
        return $bookmarks
    }
    catch {
        Write-Error "Failed to extract browser bookmarks: $($_.Exception.Message)"
        return $null
    }
}

function Get-ChromeBookmarks {
    <#
    .SYNOPSIS
        Parses Chrome/Edge Bookmarks JSON file

    .DESCRIPTION
        Extracts bookmark data from Chrome/Edge JSON bookmark file

    .PARAMETER BookmarkFile
        Path to Bookmarks file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BookmarkFile
    )

    try {
        $bookmarkData = Get-Content $BookmarkFile -Raw | ConvertFrom-Json
        $bookmarks = @()

        function Parse-ChromeBookmarkFolder {
            param($folder, $parentPath = "")

            foreach ($child in $folder.children) {
                $currentPath = if ($parentPath) { "$parentPath/$($folder.name)" } else { $folder.name }

                if ($child.type -eq "folder") {
                    Parse-ChromeBookmarkFolder -folder $child -parentPath $currentPath
                }
                elseif ($child.type -eq "url") {
                    $bookmarks += [PSCustomObject]@{
                        Title = $child.name
                        URL = $child.url
                        Folder = $currentPath
                        DateAdded = (Get-Date "1970-01-01").AddSeconds($child.date_added / 1000000)
                        Browser = "Chrome"
                        Timestamp = Get-Date
                    }
                }
            }
        }

        if ($bookmarkData.roots.bookmarks_bar) {
            Parse-ChromeBookmarkFolder -folder $bookmarkData.roots.bookmarks_bar
        }
        if ($bookmarkData.roots.other) {
            Parse-ChromeBookmarkFolder -folder $bookmarkData.roots.other
        }

        return $bookmarks
    }
    catch {
        Write-Warning "Failed to parse Chrome bookmarks: $($_.Exception.Message)"
        return @()
    }
}

function Get-FirefoxBookmarks {
    <#
    .SYNOPSIS
        Parses Firefox places.sqlite for bookmarks

    .DESCRIPTION
        Extracts bookmark data from Firefox places database

    .PARAMETER PlacesFile
        Path to places.sqlite file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlacesFile
    )

    try {
        # Copy database to avoid locking issues
        $tempFile = [System.IO.Path]::GetTempFileName() + ".db"
        Copy-Item $PlacesFile $tempFile -Force

        # Connect to database
        $connectionString = "Data Source=$tempFile;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Query bookmarks
        $query = @"
SELECT
    moz_bookmarks.title,
    moz_places.url,
    moz_bookmarks.dateAdded,
    moz_bookmarks.lastModified
FROM moz_bookmarks
LEFT JOIN moz_places ON moz_bookmarks.fk = moz_places.id
WHERE moz_bookmarks.type = 1 AND moz_places.url IS NOT NULL
ORDER BY moz_bookmarks.dateAdded DESC
"@

        $command = $connection.CreateCommand()
        $command.CommandText = $query

        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $bookmarks = @()
        $firefoxEpoch = Get-Date "1970-01-01"

        foreach ($row in $dataSet.Tables[0].Rows) {
            $bookmarks += [PSCustomObject]@{
                Title = $row.title
                URL = $row.url
                Folder = "Firefox Bookmarks"
                DateAdded = $firefoxEpoch.AddSeconds($row.dateAdded / 1000000)
                LastModified = $firefoxEpoch.AddSeconds($row.lastModified / 1000000)
                Browser = "Firefox"
                Timestamp = Get-Date
            }
        }

        $connection.Close()
        Remove-Item $tempFile -Force

        return $bookmarks
    }
    catch {
        Write-Warning "Failed to parse Firefox bookmarks: $($_.Exception.Message)"
        return @()
    }
}

# Browser Timeline Analysis

function Get-BrowserTimeline {
    <#
    .SYNOPSIS
        Creates a comprehensive browser activity timeline

    .DESCRIPTION
        Combines history, downloads, and other browser activity into a chronological timeline

    .PARAMETER Browser
        Browser to analyze

    .PARAMETER ProfilePath
        Path to browser profile

    .PARAMETER DaysBack
        Number of days to include in timeline

    .EXAMPLE
        Get-BrowserTimeline -Browser Chrome -ProfilePath "C:\Users\John\AppData\Local\Google\Chrome\User Data\Default"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Chrome", "Firefox", "Edge")]
        [string]$Browser,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 30
    )

    try {
        Write-Host "Creating $Browser activity timeline..." -ForegroundColor Cyan

        $timeline = @()
        $cutoffDate = (Get-Date).AddDays(-$DaysBack)

        # Get history
        $history = Get-BrowserHistory -Browser $Browser -ProfilePath $ProfilePath -DaysBack $DaysBack
        if ($history) {
            foreach ($item in $history) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $item.VisitTime
                    Activity = "Page Visit"
                    Details = "$($item.Title) - $($item.URL)"
                    Browser = $Browser
                    Category = "History"
                    Data = $item
                }
            }
        }

        # Get cookies (recent activity)
        $cookies = Get-BrowserCookies -Browser $Browser -ProfilePath $ProfilePath
        if ($cookies) {
            foreach ($cookie in $cookies | Where-Object { $_.LastAccess -gt $cutoffDate }) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $cookie.LastAccess
                    Activity = "Cookie Access"
                    Details = "$($cookie.Name) on $($cookie.Domain)"
                    Browser = $Browser
                    Category = "Cookies"
                    Data = $cookie
                }
            }
        }

        # Get bookmarks
        $bookmarks = Get-BrowserBookmarks -Browser $Browser -ProfilePath $ProfilePath
        if ($bookmarks) {
            foreach ($bookmark in $bookmarks | Where-Object { $_.DateAdded -gt $cutoffDate }) {
                $timeline += [PSCustomObject]@{
                    Timestamp = $bookmark.DateAdded
                    Activity = "Bookmark Added"
                    Details = "$($bookmark.Title) - $($bookmark.URL)"
                    Browser = $Browser
                    Category = "Bookmarks"
                    Data = $bookmark
                }
            }
        }

        # Sort timeline by timestamp
        $timeline = $timeline | Sort-Object Timestamp -Descending

        Write-Host "Created timeline with $($timeline.Count) activities" -ForegroundColor Green
        return [PSCustomObject]@{
            Timeline = $timeline
            Browser = $Browser
            DaysBack = $DaysBack
            TotalActivities = $timeline.Count
            Timestamp = Get-Date
        }
    }
    catch {
        Write-Error "Failed to create browser timeline: $($_.Exception.Message)"
        return $null
    }
}

# Browser Forensics Report Generation

function Export-BrowserForensicsReport {
    <#
    .SYNOPSIS
        Generates comprehensive browser forensics report

    .DESCRIPTION
        Creates HTML report with browser analysis results

    .PARAMETER Browser
        Browser that was analyzed

    .PARAMETER ProfilePath
        Profile path that was analyzed

    .PARAMETER History
        History analysis results

    .PARAMETER Cookies
        Cookie analysis results

    .PARAMETER Cache
        Cache analysis results

    .PARAMETER Bookmarks
        Bookmark analysis results

    .PARAMETER Timeline
        Timeline analysis results

    .PARAMETER OutputPath
        Path for the HTML report

    .EXAMPLE
        Export-BrowserForensicsReport -Browser Chrome -ProfilePath "C:\Profile" -History $history -OutputPath "report.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser,

        [Parameter(Mandatory = $true)]
        [string]$ProfilePath,

        [Parameter(Mandatory = $false)]
        $History,

        [Parameter(Mandatory = $false)]
        $Cookies,

        [Parameter(Mandatory = $false)]
        $Cache,

        [Parameter(Mandatory = $false)]
        $Bookmarks,

        [Parameter(Mandatory = $false)]
        $Timeline,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Generating browser forensics report..." -ForegroundColor Cyan

        $reportHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Browser Forensics Report - $Browser</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; color: #667eea; }
        .section { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section-header { background: #667eea; color: white; padding: 15px; margin: 0; border-radius: 8px 8px 0 0; }
        .section-content { padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .timeline-item { margin-bottom: 10px; padding: 10px; border-left: 4px solid #667eea; background: #f8f9fa; }
        .timeline-time { font-weight: bold; color: #667eea; }
        .timeline-activity { font-weight: bold; }
        .evidence-path { font-family: monospace; background: #f0f0f0; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Browser Forensics Report</h1>
        <h2>$Browser Analysis</h2>
        <p><strong>Profile:</strong> $ProfilePath</p>
        <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>

    <div class="summary">
        <div class="metric">
            <h3>History Items</h3>
            <div class="value">$($History ? $History.Count : 0)</div>
        </div>
        <div class="metric">
            <h3>Cookies Found</h3>
            <div class="value">$($Cookies ? $Cookies.Count : 0)</div>
        </div>
        <div class="metric">
            <h3>Cache Items</h3>
            <div class="value">$($Cache ? $Cache.CacheItems.Count : 0)</div>
        </div>
        <div class="metric">
            <h3>Bookmarks</h3>
            <div class="value">$($Bookmarks ? $Bookmarks.Count : 0)</div>
        </div>
        <div class="metric">
            <h3>Timeline Events</h3>
            <div class="value">$($Timeline ? $Timeline.TotalActivities : 0)</div>
        </div>
    </div>
"@

        # History Section
        if ($History -and $History.Count -gt 0) {
            $reportHtml += @"

    <div class="section">
        <h2 class="section-header">📚 Browser History</h2>
        <div class="section-content">
            <table>
                <tr>
                    <th>Visit Time</th>
                    <th>Title</th>
                    <th>URL</th>
                    <th>Visit Count</th>
                </tr>
"@
            foreach ($item in ($History | Select-Object -First 100)) {
                $reportHtml += @"
                <tr>
                    <td>$($item.VisitTime.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                    <td>$($item.Title)</td>
                    <td><a href="$($item.URL)" target="_blank">$($item.URL)</a></td>
                    <td>$($item.VisitCount)</td>
                </tr>
"@
            }
            $reportHtml += @"
            </table>
            <p><em>Showing first 100 history items. Total: $($History.Count)</em></p>
        </div>
    </div>
"@
        }

        # Cookies Section
        if ($Cookies -and $Cookies.Count -gt 0) {
            $reportHtml += @"

    <div class="section">
        <h2 class="section-header">🍪 Cookies Analysis</h2>
        <div class="section-content">
            <table>
                <tr>
                    <th>Domain</th>
                    <th>Name</th>
                    <th>Value</th>
                    <th>Expires</th>
                    <th>Secure</th>
                    <th>Last Access</th>
                </tr>
"@
            foreach ($cookie in ($Cookies | Select-Object -First 50)) {
                $reportHtml += @"
                <tr>
                    <td>$($cookie.Domain)</td>
                    <td>$($cookie.Name)</td>
                    <td>$($cookie.Value)</td>
                    <td>$($cookie.Expires ? $cookie.Expires.ToString('yyyy-MM-dd HH:mm:ss') : 'Session')</td>
                    <td>$($cookie.Secure ? 'Yes' : 'No')</td>
                    <td>$($cookie.LastAccess.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                </tr>
"@
            }
            $reportHtml += @"
            </table>
            <p><em>Showing first 50 cookies. Total: $($Cookies.Count)</em></p>
        </div>
    </div>
"@
        }

        # Timeline Section
        if ($Timeline -and $Timeline.Timeline.Count -gt 0) {
            $reportHtml += @"

    <div class="section">
        <h2 class="section-header">⏰ Activity Timeline</h2>
        <div class="section-content">
"@
            foreach ($activity in ($Timeline.Timeline | Select-Object -First 50)) {
                $reportHtml += @"
            <div class="timeline-item">
                <div class="timeline-time">$($activity.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</div>
                <div class="timeline-activity">$($activity.Activity)</div>
                <div>$($activity.Details)</div>
            </div>
"@
            }
            $reportHtml += @"
            <p><em>Showing first 50 timeline events. Total: $($Timeline.TotalActivities)</em></p>
        </div>
    </div>
"@
        }

        $reportHtml += @"
</body>
</html>
"@

        $reportHtml | Out-File $OutputPath -Encoding UTF8

        Write-Host "Browser forensics report saved to $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to generate browser forensics report: $($_.Exception.Message)"
        return $false
    }
}