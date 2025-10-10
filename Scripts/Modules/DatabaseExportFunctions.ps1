# DatabaseExportFunctions.ps1
# Database schema export functions

<#
.SYNOPSIS
    Database Export Functions

.DESCRIPTION
    This file contains functions for exporting database schemas including:
    - Export-DatabaseSchema: Exports database schema to SQL, JSON, or HTML formats

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function Export-DatabaseSchema {
    <#
    .SYNOPSIS
        Exports database schema to various formats

    .DESCRIPTION
        Generates database schema documentation in SQL, JSON, or HTML formats

    .PARAMETER DatabaseInfo
        Database information object from Get-SQLiteDatabaseInfo or Get-SQLServerDatabaseInfo

    .PARAMETER Format
        Export format (SQL, JSON, HTML)

    .PARAMETER OutputPath
        Path for the exported schema

    .EXAMPLE
        $dbInfo = Get-SQLiteDatabaseInfo -DatabasePath "C:\Evidence\database.db"
        Export-DatabaseSchema -DatabaseInfo $dbInfo -Format HTML -OutputPath "schema.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DatabaseInfo,

        [Parameter(Mandatory = $true)]
        [ValidateSet("SQL", "JSON", "HTML")]
        [string]$Format,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Exporting database schema to $Format format..." -ForegroundColor Cyan

        switch ($Format) {
            "SQL" {
                $sql = @()

                # Generate CREATE TABLE statements
                foreach ($table in $DatabaseInfo.Tables) {
                    $sql += "CREATE TABLE $($table.Name) ("

                    $columnDefs = @()
                    foreach ($column in $table.Columns) {
                        $colDef = "  $($column.Name) $($column.Type)"
                        if (-not $column.Nullable) { $colDef += " NOT NULL" }
                        if ($column.DefaultValue) { $colDef += " DEFAULT $($column.DefaultValue)" }
                        $columnDefs += $colDef
                    }

                    $sql += $columnDefs -join ",`n"
                    $sql += ");`n"
                }

                # Generate CREATE INDEX statements
                foreach ($index in $DatabaseInfo.Indexes) {
                    $sql += "$($index.SQL);`n"
                }

                # Generate CREATE VIEW statements
                foreach ($view in $DatabaseInfo.Views) {
                    $sql += "$($view.SQL);`n"
                }

                # Generate CREATE TRIGGER statements
                foreach ($trigger in $DatabaseInfo.Triggers) {
                    $sql += "$($trigger.SQL);`n"
                }

                $sql | Out-File $OutputPath -Encoding UTF8
            }

            "JSON" {
                $DatabaseInfo | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
            }

            "HTML" {
                $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Database Schema Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .section { background: white; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section-header { background: #667eea; color: white; padding: 15px; margin: 0; border-radius: 8px 8px 0 0; }
        .section-content { padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; color: #667eea; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Database Schema Report</h1>
        <h2>$($DatabaseInfo.Database)</h2>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>

    <div class="summary">
        <div class="metric">
            <h3>Tables</h3>
            <div class="value">$($DatabaseInfo.Tables.Count)</div>
        </div>
        <div class="metric">
            <h3>Indexes</h3>
            <div class="value">$($DatabaseInfo.Indexes.Count)</div>
        </div>
        <div class="metric">
            <h3>Views</h3>
            <div class="value">$($DatabaseInfo.Views.Count)</div>
        </div>
        <div class="metric">
            <h3>Triggers</h3>
            <div class="value">$($DatabaseInfo.Triggers.Count)</div>
        </div>
    </div>
"@

                # Tables section
                if ($DatabaseInfo.Tables -and $DatabaseInfo.Tables.Count -gt 0) {
                    $html += @"

    <div class="section">
        <h2 class="section-header">📋 Tables</h2>
        <div class="section-content">
"@
                    foreach ($table in $DatabaseInfo.Tables) {
                        $html += @"
            <h3>$($table.Name)</h3>
            <p><strong>Columns:</strong> $($table.Columns.Count) | <strong>Rows:</strong> $($table.RowCount)</p>
            <table>
                <tr>
                    <th>Column Name</th>
                    <th>Data Type</th>
                    <th>Nullable</th>
                    <th>Default</th>
                </tr>
"@
                        foreach ($column in $table.Columns) {
                            # Calculate nullable value
                            if ($column.NotNull) {
                                $nullableValue = 'No'
                            } else {
                                $nullableValue = 'Yes'
                            }

                            $html += @"
                <tr>
                    <td>$($column.Name)</td>
                    <td>$($column.Type)</td>
                    <td>$nullableValue</td>
                    <td>$($column.DefaultValue)</td>
                </tr>
"@
                        }
                        $html += @"
            </table>
"@
                    }
                    $html += @"
        </div>
    </div>
"@
                }

                $html += @"
</body>
</html>
"@

                $html | Out-File $OutputPath -Encoding UTF8
            }
        }

        Write-Host "Database schema exported to $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to export database schema: $($_.Exception.Message)"
        return $false
    }
}