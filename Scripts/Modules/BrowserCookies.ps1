# BrowserCookiesFunctions.ps1
# Browser cookie analysis functions

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