# DatabaseDiscoveryFunctions.ps1
# Database discovery and file type identification functions

<#
.SYNOPSIS
    Database Discovery Functions

.DESCRIPTION
    This file contains functions for discovering and identifying database files including:
    - Find-DatabaseFiles: Searches for database files by extension and signature
    - Get-DatabaseFileType: Identifies database file types

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

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