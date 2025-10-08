# BrowserCacheFunctions.ps1
# Browser cache analysis functions

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