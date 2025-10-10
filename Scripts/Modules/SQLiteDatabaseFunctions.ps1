# SQLiteDatabaseFunctions.ps1
# SQLite database forensics functions for digital investigations

<#
.SYNOPSIS
    SQLite Database Forensics Functions

.DESCRIPTION
    This file contains functions for analyzing SQLite databases including:
    - Get-SQLiteDatabaseInfo: Analyzes database structure and metadata
    - Get-SQLiteTableInfo: Analyzes specific table schema and data
    - Search-SQLiteDatabase: Searches database content

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: SQLite ADO.NET provider for full functionality
#>

function Get-SQLiteDatabaseInfo {
    <#
    .SYNOPSIS
        Analyzes SQLite database structure and metadata

    .DESCRIPTION
        Extracts comprehensive information about SQLite database files including schema, tables, and metadata

    .PARAMETER DatabasePath
        Path to the SQLite database file

    .PARAMETER IncludeData
        Whether to include sample data from tables

    .PARAMETER MaxRows
        Maximum number of rows to sample per table

    .EXAMPLE
        Get-SQLiteDatabaseInfo -DatabasePath "C:\Evidence\database.db"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeData,

        [Parameter(Mandatory = $false)]
        [int]$MaxRows = 10
    )

    try {
        Write-Host "Analyzing SQLite database: $DatabasePath..." -ForegroundColor Cyan

        if (-not (Test-Path $DatabasePath)) {
            throw "Database file not found: $DatabasePath"
        }

        # Copy database to avoid locking issues
        $tempFile = [System.IO.Path]::GetTempFileName() + ".db"
        Copy-Item $DatabasePath $tempFile -Force

        # Connect to database
        $connectionString = "Data Source=$tempFile;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        # Get database metadata
        $dbInfo = [PSCustomObject]@{
            DatabasePath = $DatabasePath
            FileSize = (Get-Item $DatabasePath).Length
            LastModified = (Get-Item $DatabasePath).LastWriteTime
            Tables = @()
            Indexes = @()
            Triggers = @()
            Views = @()
            Timestamp = Get-Date
        }

        # Get tables
        $tableQuery = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        $command = $connection.CreateCommand()
        $command.CommandText = $tableQuery
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $tableName = $row.name
            $tableInfo = Get-SQLiteTableInfo -Connection $connection -TableName $tableName -IncludeData:$IncludeData -MaxRows $MaxRows
            $dbInfo.Tables += $tableInfo
        }

        # Get indexes
        $indexQuery = "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' ORDER BY name;"
        $command.CommandText = $indexQuery
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $dbInfo.Indexes += [PSCustomObject]@{
                Name = $row.name
                Table = $row.tbl_name
                SQL = $row.sql
            }
        }

        # Get triggers
        $triggerQuery = "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name;"
        $command.CommandText = $triggerQuery
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $dbInfo.Triggers += [PSCustomObject]@{
                Name = $row.name
                Table = $row.tbl_name
                SQL = $row.sql
            }
        }

        # Get views
        $viewQuery = "SELECT name, sql FROM sqlite_master WHERE type='view' ORDER BY name;"
        $command.CommandText = $viewQuery
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $dbInfo.Views += [PSCustomObject]@{
                Name = $row.name
                SQL = $row.sql
            }
        }

        $connection.Close()
        Remove-Item $tempFile -Force

        Write-Host "Database analysis completed. Found $($dbInfo.Tables.Count) tables, $($dbInfo.Indexes.Count) indexes, $($dbInfo.Triggers.Count) triggers, $($dbInfo.Views.Count) views" -ForegroundColor Green
        return $dbInfo
    }
    catch {
        Write-Error "Failed to analyze SQLite database: $($_.Exception.Message)"
        return $null
    }
}

function Get-SQLiteTableInfo {
    <#
    .SYNOPSIS
        Analyzes a specific SQLite table

    .DESCRIPTION
        Extracts detailed information about a SQLite table including schema and sample data

    .PARAMETER Connection
        SQLite database connection

    .PARAMETER TableName
        Name of the table to analyze

    .PARAMETER IncludeData
        Whether to include sample data

    .PARAMETER MaxRows
        Maximum number of rows to sample
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Connection,

        [Parameter(Mandatory = $true)]
        [string]$TableName,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeData,

        [Parameter(Mandatory = $false)]
        [int]$MaxRows = 10
    )

    try {
        $tableInfo = [PSCustomObject]@{
            Name = $TableName
            Columns = @()
            RowCount = 0
            SampleData = @()
        }

        # Get table schema
        $pragmaQuery = "PRAGMA table_info($TableName);"
        $command = $Connection.CreateCommand()
        $command.CommandText = $pragmaQuery
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $tableInfo.Columns += [PSCustomObject]@{
                Name = $row.name
                Type = $row.type
                NotNull = [bool]$row.notnull
                DefaultValue = $row.dflt_value
                PrimaryKey = [bool]$row.pk
            }
        }

        # Get row count
        $countQuery = "SELECT COUNT(*) FROM $TableName;"
        $command.CommandText = $countQuery
        $tableInfo.RowCount = $command.ExecuteScalar()

        # Get sample data
        if ($IncludeData -and $tableInfo.RowCount -gt 0) {
            $dataQuery = "SELECT * FROM $TableName LIMIT $MaxRows;"
            $command.CommandText = $dataQuery
            $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
            $dataSet = New-Object System.Data.DataSet
            $adapter.Fill($dataSet) | Out-Null

            foreach ($row in $dataSet.Tables[0].Rows) {
                $rowData = @{}
                foreach ($col in $tableInfo.Columns) {
                    $rowData[$col.Name] = $row[$col.Name]
                }
                $tableInfo.SampleData += [PSCustomObject]$rowData
            }
        }

        return $tableInfo
    }
    catch {
        Write-Warning "Failed to analyze table $TableName : $($_.Exception.Message)"
        return [PSCustomObject]@{
            Name = $TableName
            Columns = @()
            RowCount = 0
            SampleData = @()
            Error = $_.Exception.Message
        }
    }
}

function Search-SQLiteDatabase {
    <#
    .SYNOPSIS
        Searches SQLite database for specific content

    .DESCRIPTION
        Performs comprehensive search across SQLite database tables and columns

    .PARAMETER DatabasePath
        Path to the SQLite database file

    .PARAMETER SearchTerm
        Term to search for

    .PARAMETER TableName
        Specific table to search (optional)

    .PARAMETER CaseSensitive
        Whether search should be case sensitive

    .EXAMPLE
        Search-SQLiteDatabase -DatabasePath "C:\Evidence\database.db" -SearchTerm "password"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath,

        [Parameter(Mandatory = $true)]
        [string]$SearchTerm,

        [Parameter(Mandatory = $false)]
        [string]$TableName,

        [Parameter(Mandatory = $false)]
        [switch]$CaseSensitive
    )

    try {
        Write-Host "Searching SQLite database for '$SearchTerm'..." -ForegroundColor Cyan

        # Copy database to avoid locking issues
        $tempFile = [System.IO.Path]::GetTempFileName() + ".db"
        Copy-Item $DatabasePath $tempFile -Force

        # Connect to database
        $connectionString = "Data Source=$tempFile;Version=3;Read Only=True;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        $results = @()

        # Get tables to search
        $tables = if ($TableName) { @($TableName) } else {
            $tableQuery = "SELECT name FROM sqlite_master WHERE type='table';"
            $command = $connection.CreateCommand()
            $command.CommandText = $tableQuery
            $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
            $dataSet = New-Object System.Data.DataSet
            $adapter.Fill($dataSet) | Out-Null
            $dataSet.Tables[0].Rows | ForEach-Object { $_.name }
        }

        foreach ($table in $tables) {
            try {
                # Get column information
                $pragmaQuery = "PRAGMA table_info($table);"
                $command = $connection.CreateCommand()
                $command.CommandText = $pragmaQuery
                $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
                $dataSet = New-Object System.Data.DataSet
                $adapter.Fill($dataSet) | Out-Null

                $columns = $dataSet.Tables[0].Rows | ForEach-Object { $_.name }

                # Search each column
                foreach ($column in $columns) {
                    $searchQuery = "SELECT * FROM $table WHERE $column LIKE ?;"
                    $command = $connection.CreateCommand()
                    $command.CommandText = $searchQuery
                    $command.Parameters.AddWithValue("@search", "%$SearchTerm%") | Out-Null

                    try {
                        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
                        $dataSet = New-Object System.Data.DataSet
                        $adapter.Fill($dataSet) | Out-Null

                        foreach ($row in $dataSet.Tables[0].Rows) {
                            $results += [PSCustomObject]@{
                                Database = $DatabasePath
                                Table = $table
                                Column = $column
                                RowData = ($row | ConvertTo-Json -Compress)
                                FoundValue = $row[$column]
                                Timestamp = Get-Date
                            }
                        }
                    }
                    catch {
                        # Column might not be searchable (e.g., BLOB data)
                        continue
                    }
                }
            }
            catch {
                Write-Warning "Failed to search table $table : $($_.Exception.Message)"
                continue
            }
        }

        $connection.Close()
        Remove-Item $tempFile -Force

        Write-Host "Search completed. Found $($results.Count) matches" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Error "Failed to search SQLite database: $($_.Exception.Message)"
        return $null
    }
}