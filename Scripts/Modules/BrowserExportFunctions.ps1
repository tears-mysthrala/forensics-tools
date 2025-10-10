# BrowserExportFunctions.ps1
# Browser forensics report export functions

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

        # Calculate summary values
        if ($History) {
            $historyCount = $History.Count
        } else {
            $historyCount = 0
        }
        if ($Cookies) {
            $cookiesCount = $Cookies.Count
        } else {
            $cookiesCount = 0
        }
        if ($Cache) {
            $cacheCount = $Cache.CacheItems.Count
        } else {
            $cacheCount = 0
        }
        if ($Bookmarks) {
            $bookmarksCount = $Bookmarks.Count
        } else {
            $bookmarksCount = 0
        }
        if ($Timeline) {
            $timelineCount = $Timeline.TotalActivities
        } else {
            $timelineCount = 0
        }

        $reportHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Browser Forensics Report - $Browser</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
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
        <h1>Browser Forensics Report</h1>
        <h2>$Browser Analysis</h2>
        <p><strong>Profile:</strong> $ProfilePath</p>
        <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>

    <div class="summary">
        <div class="metric">
            <h3>History Items</h3>
            <div class="value">$historyCount</div>
        </div>
        <div class="metric">
            <h3>Cookies Found</h3>
            <div class="value">$cookiesCount</div>
        </div>
        <div class="metric">
            <h3>Cache Items</h3>
            <div class="value">$cacheCount</div>
        </div>
        <div class="metric">
            <h3>Bookmarks</h3>
            <div class="value">$bookmarksCount</div>
        </div>
        <div class="metric">
            <h3>Timeline Events</h3>
            <div class="value">$timelineCount</div>
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
                # Calculate cookie values
                if ($cookie.Expires) {
                    $expiresValue = $cookie.Expires.ToString('yyyy-MM-dd HH:mm:ss')
                } else {
                    $expiresValue = 'Session'
                }
                if ($cookie.Secure) {
                    $secureValue = 'Yes'
                } else {
                    $secureValue = 'No'
                }

                $reportHtml += @"
                <tr>
                    <td>$($cookie.Domain)</td>
                    <td>$($cookie.Name)</td>
                    <td>$($cookie.Value)</td>
                    <td>$expiresValue</td>
                    <td>$secureValue</td>
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