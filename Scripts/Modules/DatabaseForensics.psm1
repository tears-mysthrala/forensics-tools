# DatabaseForensics.psm1
# Database Forensics Module

<#
.SYNOPSIS
    Database Forensics Module

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

# Import required modules
. $PSScriptRoot\SQLiteDatabaseFunctions.ps1
. $PSScriptRoot\SQLServerDatabaseFunctions.ps1
. $PSScriptRoot\DatabaseDiscoveryFunctions.ps1
. $PSScriptRoot\DatabaseExportFunctions.ps1

# Export functions
Export-ModuleMember -Function Get-SQLiteDatabaseInfo, Get-SQLiteTableInfo, Search-SQLiteDatabase, Get-SQLServerDatabaseInfo, Get-SQLServerTableInfo, Find-DatabaseFiles, Get-DatabaseFileType, Export-DatabaseSchema