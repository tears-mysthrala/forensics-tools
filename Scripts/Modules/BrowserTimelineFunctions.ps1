# BrowserTimelineFunctions.ps1
# Browser timeline analysis functions

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