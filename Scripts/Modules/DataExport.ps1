# DataExport.ps1
# Data export functions for converting forensic data to external formats

<#
.SYNOPSIS
    Data Export Functions

.DESCRIPTION
    This module provides functions for exporting forensic data to various external formats.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function Export-DataToExternalFormat {
    <#
    .SYNOPSIS
        Exports forensic data to external tool formats

    .DESCRIPTION
        Converts internal data structures to formats compatible with external tools

    .PARAMETER Data
        Data to export

    .PARAMETER Format
        Export format (CSV, JSON, XML, SQLite)

    .PARAMETER OutputPath
        Path for exported file

    .EXAMPLE
        $evidence = Get-FileHashes -Path "C:\Evidence"
        Export-DataToExternalFormat -Data $evidence -Format CSV -OutputPath "evidence.csv"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Data,

        [Parameter(Mandatory = $true)]
        [ValidateSet("CSV", "JSON", "XML", "SQLite")]
        [string]$Format,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        Write-Host "Exporting data to $Format format..." -ForegroundColor Cyan

        switch ($Format) {
            "CSV" {
                $Data | Export-Csv -Path $OutputPath -NoTypeInformation
            }
            "JSON" {
                $Data | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
            }
            "XML" {
                $Data | Export-Clixml -Path $OutputPath
            }
            "SQLite" {
                # Create SQLite database and insert data
                $connectionString = "Data Source=$OutputPath;Version=3;"
                try {
                    $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
                    $connection.Open()

                    # Create table based on data properties
                    $properties = $Data | Get-Member -MemberType Properties | Select-Object -First 1
                    if ($properties) {
                        $columns = $Data | Get-Member -MemberType Properties | ForEach-Object {
                            "$($_.Name) TEXT"
                        }
                        $createTableSql = "CREATE TABLE IF NOT EXISTS ExportedData ($(columns -join ', '))"
                        $command = $connection.CreateCommand()
                        $command.CommandText = $createTableSql
                        $command.ExecuteNonQuery()

                        # Insert data
                        foreach ($item in $Data) {
                            $columns = $item | Get-Member -MemberType Properties | ForEach-Object { $_.Name }
                            $values = $columns | ForEach-Object { "'$($item.$_ -replace "'", "''")'" }
                            $insertSql = "INSERT INTO ExportedData ($(columns -join ', ')) VALUES ($(values -join ', '))"
                            $command.CommandText = $insertSql
                            $command.ExecuteNonQuery()
                        }
                    }

                    $connection.Close()
                }
                catch {
                    Write-Warning "SQLite export requires System.Data.SQLite. Falling back to CSV."
                    $Data | Export-Csv -Path ($OutputPath -replace '\.db$', '.csv') -NoTypeInformation
                }
            }
        }

        Write-Host "Data exported successfully to $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Data export failed: $($_.Exception.Message)"
        return $false
    }
}