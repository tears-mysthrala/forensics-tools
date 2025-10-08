# BrowserProfilesFunctions.ps1
# Browser profile detection functions

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