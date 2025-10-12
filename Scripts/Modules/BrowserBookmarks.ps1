# BrowserBookmarksFunctions.ps1
# Browser bookmark analysis functions

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