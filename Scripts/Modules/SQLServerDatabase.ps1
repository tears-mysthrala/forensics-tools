# SQLServerDatabaseFunctions.ps1
# SQL Server database forensics functions for digital investigations

<#
.SYNOPSIS
    SQL Server Database Forensics Functions

.DESCRIPTION
    This file contains functions for analyzing SQL Server databases including:
    - Get-SQLServerDatabaseInfo: Analyzes database structure and metadata
    - Get-SQLServerTableInfo: Analyzes specific table schema and data

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: SQL Server connectivity for full functionality
#>

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