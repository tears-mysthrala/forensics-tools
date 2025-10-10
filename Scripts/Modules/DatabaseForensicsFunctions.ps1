# DatabaseForensicsFunctions.ps1
# Database forensics tools for digital investigations

<#
.SYNOPSIS
    Database Forensics Functions

.DESCRIPTION
    This module provides comprehensive database forensics capabilities including:
    - SQLite database analysis and artifact extraction
    - SQL Server database forensics and log analysis
    - Database carving and recovery from raw data
    - Schema analysis and metadata extraction
    - Timeline reconstruction from database artifacts

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: SQLite ADO.NET provider for full functionality
#>

# SQLite Forensics Functions

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

# SQL Server Forensics Functions

function Get-SQLServerDatabaseInfo {
    <#
    .SYNOPSIS
        Analyzes SQL Server database structure and metadata

    .DESCRIPTION
        Extracts comprehensive information about SQL Server databases including schema, tables, and metadata

    .PARAMETER Server
        SQL Server instance name

    .PARAMETER Database
        Database name

    .PARAMETER Credential
        SQL Server credentials

    .PARAMETER IncludeData
        Whether to include sample data from tables

    .PARAMETER MaxRows
        Maximum number of rows to sample per table

    .EXAMPLE
        Get-SQLServerDatabaseInfo -Server "localhost" -Database "EvidenceDB"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$Database,

        [Parameter(Mandatory = $false)]
        [pscredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeData,

        [Parameter(Mandatory = $false)]
        [int]$MaxRows = 10
    )

    try {
        Write-Host "Analyzing SQL Server database: $Database on $Server..." -ForegroundColor Cyan

        # Build connection string
        $connectionString = "Server=$Server;Database=$Database;Integrated Security=True;"
        if ($Credential) {
            $connectionString = "Server=$Server;Database=$Database;User Id=$($Credential.UserName);Password=$($Credential.GetNetworkCredential().Password);"
        }

        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()

        # Get database metadata
        $dbInfo = [PSCustomObject]@{
            Server = $Server
            Database = $Database
            Tables = @()
            Views = @()
            StoredProcedures = @()
            Functions = @()
            Users = @()
            Timestamp = Get-Date
        }

        # Get tables
        $tableQuery = @"
SELECT
    t.TABLE_SCHEMA,
    t.TABLE_NAME,
    t.TABLE_TYPE,
    p.rows as RowCount
FROM INFORMATION_SCHEMA.TABLES t
LEFT JOIN sys.tables st ON t.TABLE_NAME = st.name
LEFT JOIN sys.partitions p ON st.object_id = p.object_id AND p.index_id IN (0,1)
WHERE t.TABLE_TYPE = 'BASE TABLE'
ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;
"@

        $command = $connection.CreateCommand()
        $command.CommandText = $tableQuery
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $tableInfo = Get-SQLServerTableInfo -Connection $connection -Schema $row.TABLE_SCHEMA -TableName $row.TABLE_NAME -IncludeData:$IncludeData -MaxRows $MaxRows
            $tableInfo.RowCount = $row.RowCount
            $dbInfo.Tables += $tableInfo
        }

        # Get views
        $viewQuery = "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.VIEWS ORDER BY TABLE_SCHEMA, TABLE_NAME;"
        $command.CommandText = $viewQuery
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $dbInfo.Views += [PSCustomObject]@{
                Schema = $row.TABLE_SCHEMA
                Name = $row.TABLE_NAME
            }
        }

        # Get stored procedures
        $spQuery = "SELECT SPECIFIC_SCHEMA, SPECIFIC_NAME FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_TYPE = 'PROCEDURE' ORDER BY SPECIFIC_SCHEMA, SPECIFIC_NAME;"
        $command.CommandText = $spQuery
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $dbInfo.StoredProcedures += [PSCustomObject]@{
                Schema = $row.SPECIFIC_SCHEMA
                Name = $row.SPECIFIC_NAME
            }
        }

        # Get functions
        $funcQuery = "SELECT SPECIFIC_SCHEMA, SPECIFIC_NAME FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_TYPE = 'FUNCTION' ORDER BY SPECIFIC_SCHEMA, SPECIFIC_NAME;"
        $command.CommandText = $funcQuery
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $dbInfo.Functions += [PSCustomObject]@{
                Schema = $row.SPECIFIC_SCHEMA
                Name = $row.SPECIFIC_NAME
            }
        }

        # Get users
        $userQuery = "SELECT name, type_desc, create_date, modify_date FROM sys.database_principals WHERE type IN ('S', 'U', 'G') ORDER BY name;"
        $command.CommandText = $userQuery
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $dbInfo.Users += [PSCustomObject]@{
                Name = $row.name
                Type = $row.type_desc
                Created = $row.create_date
                Modified = $row.modify_date
            }
        }

        $connection.Close()

        Write-Host "SQL Server database analysis completed. Found $($dbInfo.Tables.Count) tables, $($dbInfo.Views.Count) views, $($dbInfo.StoredProcedures.Count) procedures, $($dbInfo.Functions.Count) functions" -ForegroundColor Green
        return $dbInfo
    }
    catch {
        Write-Error "Failed to analyze SQL Server database: $($_.Exception.Message)"
        return $null
    }
}

function Get-SQLServerTableInfo {
    <#
    .SYNOPSIS
        Analyzes a specific SQL Server table

    .DESCRIPTION
        Extracts detailed information about a SQL Server table including schema and sample data

    .PARAMETER Connection
        SQL Server database connection

    .PARAMETER Schema
        Table schema name

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
        [string]$Schema,

        [Parameter(Mandatory = $true)]
        [string]$TableName,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeData,

        [Parameter(Mandatory = $false)]
        [int]$MaxRows = 10
    )

    try {
        $tableInfo = [PSCustomObject]@{
            Schema = $Schema
            Name = $TableName
            Columns = @()
            Indexes = @()
            Constraints = @()
            SampleData = @()
        }

        # Get column information
        $columnQuery = @"
SELECT
    COLUMN_NAME,
    DATA_TYPE,
    CHARACTER_MAXIMUM_LENGTH,
    NUMERIC_PRECISION,
    NUMERIC_SCALE,
    IS_NULLABLE,
    COLUMN_DEFAULT
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = '$Schema' AND TABLE_NAME = '$TableName'
ORDER BY ORDINAL_POSITION;
"@

        $command = $Connection.CreateCommand()
        $command.CommandText = $columnQuery
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        foreach ($row in $dataSet.Tables[0].Rows) {
            $tableInfo.Columns += [PSCustomObject]@{
                Name = $row.COLUMN_NAME
                DataType = $row.DATA_TYPE
                MaxLength = $row.CHARACTER_MAXIMUM_LENGTH
                Precision = $row.NUMERIC_PRECISION
                Scale = $row.NUMERIC_SCALE
                Nullable = ($row.IS_NULLABLE -eq "YES")
                DefaultValue = $row.COLUMN_DEFAULT
            }
        }

        # Get indexes
        $indexQuery = @"
SELECT
    i.name as IndexName,
    i.type_desc as IndexType,
    c.name as ColumnName,
    ic.key_ordinal as KeyOrdinal
FROM sys.indexes i
INNER JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
INNER JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
WHERE i.object_id = OBJECT_ID('$Schema.$TableName')
ORDER BY i.name, ic.key_ordinal;
"@

        $command.CommandText = $indexQuery
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        $indexes = @{}
        foreach ($row in $dataSet.Tables[0].Rows) {
            if (-not $indexes.ContainsKey($row.IndexName)) {
                $indexes[$row.IndexName] = @{
                    Name = $row.IndexName
                    Type = $row.IndexType
                    Columns = @()
                }
            }
            $indexes[$row.IndexName].Columns += $row.ColumnName
        }

        foreach ($index in $indexes.Values) {
            $tableInfo.Indexes += [PSCustomObject]@{
                Name = $index.Name
                Type = $index.Type
                Columns = $index.Columns -join ", "
            }
        }

        # Get sample data
        if ($IncludeData) {
            $dataQuery = "SELECT TOP $MaxRows * FROM [$Schema].[$TableName];"
            $command.CommandText = $dataQuery
            $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
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
        Write-Warning "Failed to analyze table $Schema.$TableName : $($_.Exception.Message)"
        return [PSCustomObject]@{
            Schema = $Schema
            Name = $TableName
            Columns = @()
            Indexes = @()
            Constraints = @()
            SampleData = @()
            Error = $_.Exception.Message
        }
    }
}

# Database Carving and Recovery Functions

function Find-DatabaseFiles {
    <#
    .SYNOPSIS
        Searches for database files in a directory or drive

    .DESCRIPTION
        Scans for SQLite, SQL Server, and other database files using file signatures and extensions

    .PARAMETER Path
        Path to search for database files

    .PARAMETER IncludeSignatures
        Whether to scan for file signatures (slower but more thorough)

    .PARAMETER Extensions
        File extensions to search for

    .EXAMPLE
        Find-DatabaseFiles -Path "C:\Evidence" -IncludeSignatures
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeSignatures,

        [Parameter(Mandatory = $false)]
        [string[]]$Extensions = @("*.db", "*.sqlite", "*.sqlite3", "*.mdf", "*.ldf", "*.ndf")
    )

    try {
        Write-Host "Searching for database files in $Path..." -ForegroundColor Cyan

        $databaseFiles = @()

        # Search by extensions
        foreach ($ext in $Extensions) {
            $files = Get-ChildItem -Path $Path -Filter $ext -Recurse -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                $dbType = Get-DatabaseFileType -FilePath $file.FullName
                $databaseFiles += [PSCustomObject]@{
                    Path = $file.FullName
                    Name = $file.Name
                    Size = $file.Length
                    LastModified = $file.LastWriteTime
                    DatabaseType = $dbType
                    FoundBy = "Extension"
                    Timestamp = Get-Date
                }
            }
        }

        # Search by file signatures if requested
        if ($IncludeSignatures) {
            Write-Host "Scanning for database file signatures..." -ForegroundColor Gray

            $allFiles = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue
            $processedFiles = 0

            foreach ($file in $allFiles) {
                $processedFiles++
                if ($processedFiles % 100 -eq 0) {
                    Write-Host "Processed $processedFiles files..." -ForegroundColor Gray
                }

                try {
                    $dbType = Get-DatabaseFileType -FilePath $file.FullName -CheckSignature
                    if ($dbType -ne "Unknown") {
                        # Check if already found by extension
                        $alreadyFound = $databaseFiles | Where-Object { $_.Path -eq $file.FullName }
                        if (-not $alreadyFound) {
                            $databaseFiles += [PSCustomObject]@{
                                Path = $file.FullName
                                Name = $file.Name
                                Size = $file.Length
                                LastModified = $file.LastWriteTime
                                DatabaseType = $dbType
                                FoundBy = "Signature"
                                Timestamp = Get-Date
                            }
                        }
                    }
                }
                catch {
                    # Skip files that can't be read
                    continue
                }
            }
        }

        Write-Host "Database file search completed. Found $($databaseFiles.Count) database files" -ForegroundColor Green
        return $databaseFiles
    }
    catch {
        Write-Error "Failed to search for database files: $($_.Exception.Message)"
        return $null
    }
}

function Get-DatabaseFileType {
    <#
    .SYNOPSIS
        Determines the type of database file

    .DESCRIPTION
        Identifies database file types using extensions and file signatures

    .PARAMETER FilePath
        Path to the file to analyze

    .PARAMETER CheckSignature
        Whether to check file signature (first few bytes)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [switch]$CheckSignature
    )

    try {
        $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()

        # Check by extension first
        switch ($extension) {
            ".db" { return "SQLite" }
            ".sqlite" { return "SQLite" }
            ".sqlite3" { return "SQLite" }
            ".mdf" { return "SQL Server" }
            ".ldf" { return "SQL Server Log" }
            ".ndf" { return "SQL Server Secondary" }
            ".accdb" { return "Access" }
            ".mdb" { return "Access" }
        }

        # Check file signature if requested
        if ($CheckSignature) {
            $fileStream = [System.IO.File]::OpenRead($FilePath)
            $buffer = New-Object byte[] 16
            $bytesRead = $fileStream.Read($buffer, 0, 16)
            $fileStream.Close()

            if ($bytesRead -ge 16) {
                # SQLite signature: "SQLite format 3" + null terminator
                $sqliteSig = [System.Text.Encoding]::ASCII.GetBytes("SQLite format 3")
                if ($buffer[0..14] -eq $sqliteSig) {
                    return "SQLite"
                }
            }
        }

        return "Unknown"
    }
    catch {
        return "Unknown"
    }
}

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