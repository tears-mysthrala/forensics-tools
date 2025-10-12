# ExternalToolIntegrationsFunctions.ps1
# External tool integrations for API connectivity, database access, and third-party tools

<#
.SYNOPSIS
    External Tool Integration Functions

.DESCRIPTION
    This module provides integrations with external tools and services including:
    - API connectivity for REST services and web APIs
    - Database access for SQL Server, SQLite, and other databases
    - Third-party tool integration for running external forensics tools

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

# API Integration Functions

function Invoke-RestApiCall {
    <#
    .SYNOPSIS
        Makes REST API calls for external service integration

    .DESCRIPTION
        Performs HTTP requests to REST APIs with proper error handling and authentication

    .PARAMETER Uri
        The API endpoint URI

    .PARAMETER Method
        HTTP method (GET, POST, PUT, DELETE)

    .PARAMETER Headers
        Custom headers for the request

    .PARAMETER Body
        Request body content

    .PARAMETER ContentType
        Content type for the request

    .PARAMETER TimeoutSec
        Request timeout in seconds

    .EXAMPLE
        Invoke-RestApiCall -Uri "https://api.example.com/data" -Method GET
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH")]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers = @{},

        [Parameter(Mandatory = $false)]
        [string]$Body,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/json",

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 30
    )

    try {
        Write-Host "Making $Method request to $Uri..." -ForegroundColor Cyan

        $params = @{
            Uri = $Uri
            Method = $Method
            TimeoutSec = $TimeoutSec
            ContentType = $ContentType
        }

        if ($Headers.Count -gt 0) {
            $params.Headers = $Headers
        }

        if ($Body) {
            $params.Body = $Body
        }

        $response = Invoke-RestMethod @params

        Write-Host "API call completed successfully" -ForegroundColor Green
        return [PSCustomObject]@{
            Success = $true
            Data = $response
            StatusCode = 200
            Timestamp = Get-Date
        }
    }
    catch {
        Write-Warning "API call failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Success = $false
            Error = $_.Exception.Message
            StatusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 0 }
            Timestamp = Get-Date
        }
    }
}

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
            Connection = $connection
            Type = $Type
            ConnectionString = $ConnectionString
            Connected = $true
            Timestamp = Get-Date
        }
    }
    catch {
        Write-Error "Failed to connect to database: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Connection = $null
            Type = $Type
            Connected = $false
            Error = $_.Exception.Message
            Timestamp = Get-Date
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
            Success = $true
            Data = $dataSet.Tables[0]
            RowCount = $dataSet.Tables[0].Rows.Count
            Timestamp = Get-Date
        }
    }
    catch {
        Write-Error "Database query failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Success = $false
            Error = $_.Exception.Message
            Data = $null
            RowCount = 0
            Timestamp = Get-Date
        }
    }
}

# Third-Party Tool Integration Functions

function Invoke-ExternalTool {
    <#
    .SYNOPSIS
        Runs external forensics tools and captures output

    .DESCRIPTION
        Executes third-party forensics tools and parses their output for integration

    .PARAMETER ToolPath
        Path to the external tool executable

    .PARAMETER Arguments
        Command-line arguments for the tool

    .PARAMETER WorkingDirectory
        Working directory for tool execution

    .PARAMETER Timeout
        Maximum execution time in seconds

    .PARAMETER ParseOutput
        Script block to parse tool output

    .EXAMPLE
        Invoke-ExternalTool -ToolPath "C:\Tools\autopsy.exe" -Arguments "--help"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolPath,

        [Parameter(Mandatory = $false)]
        [string]$Arguments = "",

        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory = ".",

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 300,

        [Parameter(Mandatory = $false)]
        [scriptblock]$ParseOutput
    )

    try {
        if (-not (Test-Path $ToolPath)) {
            throw "Tool not found: $ToolPath"
        }

        Write-Host "Running external tool: $ToolPath..." -ForegroundColor Cyan

        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $ToolPath
        $processInfo.Arguments = $Arguments
        $processInfo.WorkingDirectory = $WorkingDirectory
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo

        $output = ""
        $errorOutput = ""

        # Event handlers for output
        $outputEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
            $global:output += $Event.SourceEventArgs.Data + "`n"
        }
        $errorEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action {
            $global:errorOutput += $Event.SourceEventArgs.Data + "`n"
        }

        $process.Start() | Out-Null
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()

        # Wait for completion or timeout
        $completed = $process.WaitForExit($Timeout * 1000)

        if (-not $completed) {
            $process.Kill()
            throw "Tool execution timed out after $Timeout seconds"
        }

        # Clean up event handlers
        Unregister-Event -SourceIdentifier $outputEvent.Name
        Unregister-Event -SourceIdentifier $errorEvent.Name

        $exitCode = $process.ExitCode
        $process.Dispose()

        # Parse output if parser provided
        $parsedData = $null
        if ($ParseOutput -and $output) {
            try {
                $parsedData = & $ParseOutput $output
            }
            catch {
                Write-Warning "Output parsing failed: $($_.Exception.Message)"
            }
        }

        Write-Host "External tool completed with exit code: $exitCode" -ForegroundColor Green

        return [PSCustomObject]@{
            Success = $exitCode -eq 0
            ExitCode = $exitCode
            Output = $output.Trim()
            ErrorOutput = $errorOutput.Trim()
            ParsedData = $parsedData
            ExecutionTime = $Timeout
            Timestamp = Get-Date
        }
    }
    catch {
        Write-Error "External tool execution failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Success = $false
            ExitCode = -1
            Output = ""
            ErrorOutput = $_.Exception.Message
            ParsedData = $null
            ExecutionTime = 0
            Timestamp = Get-Date
        }
    }
}

function Get-ExternalToolInfo {
    <#
    .SYNOPSIS
        Gets information about available external forensics tools

    .DESCRIPTION
        Scans for installed forensics tools and provides integration information

    .PARAMETER ToolName
        Specific tool to check (optional)

    .EXAMPLE
        Get-ExternalToolInfo
        Get-ExternalToolInfo -ToolName "Wireshark"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ToolName
    )

    $tools = @(
        @{
            Name = "Wireshark"
            Executable = "wireshark.exe"
            Paths = @("$env:ProgramFiles\Wireshark", "$env:ProgramFiles(x86)\Wireshark")
            Description = "Network protocol analyzer"
            Capabilities = @("Packet Capture", "Protocol Analysis")
        },
        @{
            Name = "Autopsy"
            Executable = "autopsy.exe"
            Paths = @("$env:ProgramFiles\Autopsy", "$env:ProgramFiles(x86)\Autopsy")
            Description = "Digital forensics platform"
            Capabilities = @("File Analysis", "Timeline Analysis", "Keyword Search")
        },
        @{
            Name = "FTK Imager"
            Executable = "FTK Imager.exe"
            Paths = @("$env:ProgramFiles\AccessData\FTK Imager", "$env:ProgramFiles(x86)\AccessData\FTK Imager")
            Description = "Forensic image acquisition tool"
            Capabilities = @("Disk Imaging", "Memory Acquisition")
        },
        @{
            Name = "Volatility"
            Executable = "volatility.exe"
            Paths = @("$env:ProgramFiles\Volatility", "$env:ProgramFiles(x86)\Volatility", "$env:USERPROFILE\volatility")
            Description = "Memory forensics framework"
            Capabilities = @("Memory Analysis", "Process Dumping")
        },
        @{
            Name = "YARA"
            Executable = "yara.exe"
            Paths = @("$env:ProgramFiles\YARA", "$env:ProgramFiles(x86)\YARA")
            Description = "Pattern matching tool for malware analysis"
            Capabilities = @("Malware Detection", "Signature Matching")
        }
    )

    try {
        $results = @()

        foreach ($tool in $tools) {
            if ($ToolName -and $tool.Name -ne $ToolName) {
                continue
            }

            $found = $false
            $actualPath = $null

            # Check if tool is in PATH
            try {
                $pathResult = Get-Command $tool.Executable -ErrorAction Stop
                $found = $true
                $actualPath = $pathResult.Source
            }
            catch {
                # Check known installation paths
                foreach ($path in $tool.Paths) {
                    $fullPath = Join-Path $path $tool.Executable
                    if (Test-Path $fullPath) {
                        $found = $true
                        $actualPath = $fullPath
                        break
                    }
                }
            }

            $results += [PSCustomObject]@{
                Name = $tool.Name
                Executable = $tool.Executable
                Found = $found
                Path = $actualPath
                Description = $tool.Description
                Capabilities = $tool.Capabilities
                Timestamp = Get-Date
            }
        }

        if ($ToolName) {
            return $results | Where-Object { $_.Name -eq $ToolName }
        }

        return $results
    }
    catch {
        Write-Error "Failed to get external tool information: $($_.Exception.Message)"
        return $null
    }
}

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