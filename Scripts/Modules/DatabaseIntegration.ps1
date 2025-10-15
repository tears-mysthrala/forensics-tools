# DatabaseIntegration.ps1
# Database access functions for SQL Server, SQLite, and other databases

<#
.SYNOPSIS
    Database Integration Functions

.DESCRIPTION
    This module provides functions for connecting to and querying various database types for forensic data access.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function Connect-Database {
    <#
    .SYNOPSIS
        Establishes database connections for forensic data access

    .DESCRIPTION
        Creates connections to various database types for evidence collection and analysis

    .PARAMETER Server
        Database server name or IP

    .PARAMETER Database
        Database name

    .PARAMETER Type
        Database type (SQLServer, SQLite, MySQL, PostgreSQL)

    .PARAMETER Credential
        Database credentials

    .PARAMETER ConnectionString
        Custom connection string

    .EXAMPLE
        Connect-Database -Server "localhost" -Database "EvidenceDB" -Type SQLServer
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [string]$Database,

        [Parameter(Mandatory = $true)]
        [ValidateSet("SQLServer", "SQLite", "MySQL", "PostgreSQL")]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [pscredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$ConnectionString
    )

    try {
        Write-Host "Connecting to $Type database..." -ForegroundColor Cyan

        $connection = $null

        switch ($Type) {
            "SQLServer" {
                if (-not $ConnectionString) {
                    $ConnectionString = "Server=$Server;Database=$Database;Integrated Security=True;"
                    if ($Credential) {
                        $ConnectionString = "Server=$Server;Database=$Database;User Id=$($Credential.UserName);Password=$($Credential.GetNetworkCredential().Password);"
                    }
                }
                $connection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
            }
            "SQLite" {
                if (-not $ConnectionString) {
                    $ConnectionString = "Data Source=$Database;Version=3;"
                }
                # Note: SQLite requires System.Data.SQLite assembly
                try {
                    $connection = New-Object System.Data.SQLite.SQLiteConnection($ConnectionString)
                }
                catch {
                    throw "SQLite provider not available. Install System.Data.SQLite package."
                }
            }
            "MySQL" {
                if (-not $ConnectionString) {
                    $ConnectionString = "Server=$Server;Database=$Database;Uid=$($Credential.UserName);Pwd=$($Credential.GetNetworkCredential().Password);"
                }
                # Note: MySQL requires MySql.Data assembly
                try {
                    $connection = New-Object MySql.Data.MySqlClient.MySqlConnection($ConnectionString)
                }
                catch {
                    throw "MySQL provider not available. Install MySql.Data package."
                }
            }
            "PostgreSQL" {
                if (-not $ConnectionString) {
                    $ConnectionString = "Host=$Server;Database=$Database;Username=$($Credential.UserName);Password=$($Credential.GetNetworkCredential().Password);"
                }
                # Note: PostgreSQL requires Npgsql assembly
                try {
                    $connection = New-Object Npgsql.NpgsqlConnection($ConnectionString)
                }
                catch {
                    throw "PostgreSQL provider not available. Install Npgsql package."
                }
            }
        }

        $connection.Open()
        Write-Host "Database connection established successfully" -ForegroundColor Green

        return [PSCustomObject]@{
            Connection       = $connection
            Type             = $Type
            ConnectionString = $ConnectionString
            Connected        = $true
            Timestamp        = Get-Date
        }
    }
    catch {
        Write-Error "Failed to connect to database: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Connection = $null
            Type       = $Type
            Connected  = $false
            Error      = $_.Exception.Message
            Timestamp  = Get-Date
        }
    }
}

function Invoke-DatabaseQuery {
    <#
    .SYNOPSIS
        Executes database queries for evidence collection

    .DESCRIPTION
        Runs SQL queries against connected databases and returns results

    .PARAMETER Connection
        Database connection object from Connect-Database

    .PARAMETER Query
        SQL query to execute

    .PARAMETER Parameters
        Query parameters for parameterized queries

    .EXAMPLE
        $conn = Connect-Database -Type SQLite -Database "evidence.db"
        Invoke-DatabaseQuery -Connection $conn -Query "SELECT * FROM evidence"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Connection,

        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{}
    )

    try {
        if (-not $Connection.Connected) {
            throw "Database connection is not active"
        }

        Write-Host "Executing database query..." -ForegroundColor Cyan

        $command = $Connection.Connection.CreateCommand()
        $command.CommandText = $Query

        # Add parameters if provided
        foreach ($param in $Parameters.GetEnumerator()) {
            $dbParam = $command.CreateParameter()
            $dbParam.ParameterName = $param.Key
            $dbParam.Value = $param.Value
            $command.Parameters.Add($dbParam) | Out-Null
        }

        $adapter = $null
        switch ($Connection.Type) {
            "SQLServer" {
                $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
            }
            "SQLite" {
                $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
            }
            "MySQL" {
                $adapter = New-Object MySql.Data.MySqlClient.MySqlDataAdapter($command)
            }
            "PostgreSQL" {
                $adapter = New-Object Npgsql.NpgsqlDataAdapter($command)
            }
        }

        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet) | Out-Null

        Write-Host "Query executed successfully. Returned $($dataSet.Tables[0].Rows.Count) rows" -ForegroundColor Green

        return [PSCustomObject]@{
            Success   = $true
            Data      = $dataSet.Tables[0]
            RowCount  = $dataSet.Tables[0].Rows.Count
            Timestamp = Get-Date
        }
    }
    catch {
        Write-Error "Database query failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Success   = $false
            Error     = $_.Exception.Message
            Data      = $null
            RowCount  = 0
            Timestamp = Get-Date
        }
    }
}