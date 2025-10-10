function New-ForensicHTMLReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisData,
        [string]$OutputPath = ".",
        [string]$Title = "Forensic Analysis Report"
    )

    Write-Host "New-ForensicHTMLReport called with $($AnalysisData.Keys.Count) sections"

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $OutputPath "ForensicReport_$timestamp.html"

    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Helper function to convert data to visual HTML
    function Convert-DataToVisualHTML {
        param($data)

        Write-Host "Convert-DataToVisualHTML called with type: $($data.GetType().Name)"

        if ($data -is [array]) {
            if ($data.Count -eq 0) {
                return "<div class='evidence-item'><em>No data available</em></div>"
            }

            # Check if array contains objects
            $firstItem = $data[0]
            if ($firstItem -is [PSCustomObject]) {
                # Create table for structured data
                $html = "<table><thead><tr>"
                $firstItem.PSObject.Properties.Name | ForEach-Object { $html += "<th>$_</th>" }
                $html += "</tr></thead><tbody>"

                foreach ($item in $data | Select-Object -First 50) {
                    # Limit to first 50 items
                    $html += "<tr>"
                    foreach ($prop in $firstItem.PSObject.Properties.Name) {
                        $value = $item.$prop
                        if ($value -is [DateTime]) {
                            $value = $value.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        elseif ($value -is [bool]) {
                            $value = $value ? "<span class='success'>✓</span>" : "<span class='warning'>✗</span>"
                        }
                        elseif ($null -eq $value -or $value -eq "") {
                            $value = "<em>N/A</em>"
                        }
                        elseif ($value -is [string] -and $value.Length -gt 50) {
                            $value = $value.Substring(0, [Math]::Min(47, $value.Length)) + "..."
                        }
                        $html += "<td>$value</td>"
                    }
                    $html += "</tr>"
                }
                $propCount = ($firstItem.PSObject.Properties | Measure-Object).Count
                if ($data.Count -gt 50) {
                    $html += "<tr><td colspan='$propCount'><em>... and $($data.Count - 50) more items</em></td></tr>"
                }
                $html += "</tbody></table>"
                return $html
            }
            else {
                # Simple array
                $html = "<div class='evidence-item'><ul>"
                foreach ($item in $data | Select-Object -First 20) {
                    $html += "<li>$item</li>"
                }
                if ($data.Count -gt 20) {
                    $html += "<li><em>... and $($data.Count - 20) more items</em></li>"
                }
                $html += "</ul></div>"
                return $html
            }
        }
        elseif ($data -is [PSCustomObject]) {
            # For objects, show properties
            $html = "<div class='evidence-item'>"
            $properties = $data.PSObject.Properties

            # Separate simple properties from arrays and nested objects
            $simpleProps = @()
            $arrayProps = @()
            $objectProps = @()

            foreach ($prop in $properties) {
                if ($prop.Value -is [array]) {
                    $arrayProps += $prop
                }
                elseif ($prop.Name -eq "SystemInfo" -or $prop.Value -is [PSCustomObject] -or $prop.Name -like "*Info*") {
                    $objectProps += $prop
                }
                elseif ($prop.Name -eq "Uptime" -and $prop.Value -is [PSCustomObject]) {
                    # Special handling for Uptime
                    $objectProps += $prop
                }
                else {
                    $simpleProps += $prop
                }
            }

            # Show simple properties as metrics
            if ($simpleProps.Count -gt 0) {
                $html += "<div class='metric-grid'>"
                foreach ($prop in $simpleProps) {
                    $value = $prop.Value
                    if ($value -is [DateTime]) {
                        $value = $value.ToString("yyyy-MM-dd HH:mm:ss")
                    }
                    elseif ($value -is [bool]) {
                        $value = $value ? "<span class='success'>True</span>" : "<span class='warning'>False</span>"
                    }
                    elseif ($null -eq $value -or $value -eq "") {
                        $value = "<em>N/A</em>"
                    }
                    elseif ($value -is [PSCustomObject]) {
                        # Handle nested objects like TimeSpan
                        if ($prop.Name -eq "Uptime" -and $value.PSObject.Properties.Name -contains "Ticks" -and $value.PSObject.Properties.Name -contains "Days") {
                            # Format TimeSpan-like objects
                            $days = $value.Days
                            $hours = $value.Hours
                            $minutes = $value.Minutes
                            $value = "$days days, $hours hours, $minutes minutes"
                        }
                        else {
                            # For other nested objects, show key properties
                            $nestedProps = $value.PSObject.Properties | Select-Object -First 3
                            $value = ($nestedProps | ForEach-Object { "$($_.Name): $($_.Value)" }) -join "; "
                            if ($value.PSObject.Properties.Count -gt 3) {
                                $value += "; ..."
                            }
                        }
                    }
                    $html += "<div class='metric'><strong>$($prop.Name)</strong><div>$value</div></div>"
                }
                $html += "</div>"
            }

            # Show nested object properties
            foreach ($objectProp in $objectProps) {
                $html += "<h3>$($objectProp.Name)</h3>"
                $html += Convert-DataToVisualHTML -data $objectProp.Value
            }

            # Show array properties
            foreach ($arrayProp in $arrayProps) {
                $html += "<h3>$($arrayProp.Name) ($($arrayProp.Value.Count) items)</h3>"
                $html += Convert-DataToVisualHTML -data $arrayProp.Value
            }

            $html += "</div>"
            return $html
        }
        else {
            # Simple values
            return "<div class='evidence-item'><div class='metric'><strong>Value</strong><div>$data</div></div></div>"
        }
    }

    # Generate HTML content
    $sections = ""
    foreach ($key in $AnalysisData.Keys) {
        $data = $AnalysisData[$key]
        $visualHtml = Convert-DataToVisualHTML -data $data

        # Add appropriate icon for each section
        $iconClass = switch ($key.ToLower()) {
            "filesystem_analysis" { "fas fa-folder-open" }
            "system_analysis" { "fas fa-cogs" }
            "security_analysis" { "fas fa-shield-alt" }
            "system_status" { "fas fa-server" }
            "network_analysis" { "fas fa-network-wired" }
            "processes" { "fas fa-tasks" }
            "registry" { "fas fa-database" }
            "event_logs" { "fas fa-file-alt" }
            "memory" { "fas fa-memory" }
            "usb" { "fas fa-usb" }
            default { "fas fa-chart-bar" }
        }

        $sections += "<section class='evidence-section'><h2><i class='$iconClass'></i>$key</h2>$visualHtml</section>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #1e40af 100%);
            min-height: 100vh;
            color: #1f2937;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1), 0 0 0 1px rgba(255,255,255,0.05);
            border: 1px solid rgba(0,0,0,0.05);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #dc2626, #ea580c, #ca8a04, #16a34a, #2563eb, #7c3aed);
        }

        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }

        .header-logo {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .header-logo i {
            font-size: 2.5em;
            color: #dc2626;
            background: linear-gradient(135deg, #dc2626, #ef4444);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header-text h1 {
            color: #1f2937;
            font-size: 2.2em;
            font-weight: 700;
            margin-bottom: 5px;
            letter-spacing: -0.025em;
        }

        .header-text p {
            color: #6b7280;
            font-size: 1em;
            font-weight: 400;
        }

        .header-meta {
            background: #f8fafc;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #e5e7eb;
        }

        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .meta-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .meta-item i {
            color: #6b7280;
            font-size: 1.1em;
        }

        .meta-item span {
            font-weight: 500;
            color: #374151;
        }

        .evidence-section {
            background: #ffffff;
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.05);
            border: 1px solid #e5e7eb;
            position: relative;
        }

        .evidence-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #3b82f6, #1d4ed8);
            border-radius: 16px 16px 0 0;
        }

        .evidence-section h2 {
            color: #1f2937;
            font-size: 1.5em;
            font-weight: 600;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e5e7eb;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .evidence-section h2 i {
            color: #3b82f6;
        }

        .evidence-item {
            margin-bottom: 25px;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }

        .metric {
            background: linear-gradient(135deg, #f8fafc 0%, #ffffff 100%);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #e5e7eb;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .metric::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(180deg, #3b82f6, #1d4ed8);
        }

        .metric:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(59, 130, 246, 0.15);
            border-color: #3b82f6;
        }

        .metric strong {
            display: block;
            color: #6b7280;
            font-size: 0.85em;
            font-weight: 600;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .metric div {
            color: #1f2937;
            font-size: 1.1em;
            font-weight: 500;
            word-break: break-word;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: #ffffff;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            border: 1px solid #e5e7eb;
        }

        th, td {
            padding: 15px 20px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }

        th {
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
            color: #ffffff;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
            position: sticky;
            top: 0;
        }

        tr:nth-child(even) {
            background: #f8fafc;
        }

        tr:hover {
            background: #eff6ff;
            transition: background-color 0.2s ease;
        }

        .success {
            color: #16a34a;
            font-weight: 600;
        }

        .warning {
            color: #dc2626;
            font-weight: 600;
        }

        .evidence-section h3 {
            color: #1f2937;
            font-size: 1.2em;
            font-weight: 600;
            margin: 30px 0 15px 0;
            padding-left: 15px;
            border-left: 4px solid #3b82f6;
        }

        ul {
            padding-left: 25px;
            margin: 15px 0;
        }

        li {
            margin-bottom: 8px;
            color: #374151;
            position: relative;
        }

        li::marker {
            color: #3b82f6;
        }

        em {
            color: #9ca3af;
            font-style: italic;
        }

        .footer {
            background: #1f2937;
            color: #9ca3af;
            text-align: center;
            padding: 30px;
            border-radius: 16px;
            margin-top: 40px;
            border: 1px solid #374151;
        }

        .footer p {
            margin-bottom: 10px;
            font-size: 0.9em;
        }

        .footer .copyright {
            font-size: 0.8em;
            opacity: 0.7;
        }

        @media print {
            body {
                background: white !important;
            }
            .evidence-section {
                break-inside: avoid;
                margin-bottom: 20px;
            }
            .metric:hover {
                transform: none;
                box-shadow: none;
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            .header-content {
                flex-direction: column;
                text-align: center;
                gap: 20px;
            }
            .metric-grid {
                grid-template-columns: 1fr;
            }
            .meta-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="header-logo">
                    <i class="fas fa-shield-alt"></i>
                    <div class="header-text">
                        <h1>$Title</h1>
                        <p>Digital Forensics & Incident Response</p>
                    </div>
                </div>
                <div class="header-meta">
                    <div class="meta-grid">
                        <div class="meta-item">
                            <i class="fas fa-calendar"></i>
                            <span>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-server"></i>
                            <span>System: $env:COMPUTERNAME</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-user"></i>
                            <span>Analyst: $env:USERNAME</span>
                        </div>
                        <div class="meta-item">
                            <i class="fas fa-database"></i>
                            <span>Sections: $($AnalysisData.Keys.Count)</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        $sections
        <div class="footer">
            <p><i class="fas fa-shield-alt"></i> Forensic Analysis Report - Confidential</p>
            <p class="copyright">Generated by PowerShell Forensic Toolkit | $(Get-Date -Format "yyyy")</p>
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File $reportFile -Encoding UTF8
    Write-Host "HTML report created: $reportFile" -ForegroundColor Green

    return $reportFile
}