# ExternalToolIntegrations.ps1
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

# Import split modules
. "$PSScriptRoot\APIIntegration.ps1"
. "$PSScriptRoot\DatabaseIntegration.ps1"
. "$PSScriptRoot\ExternalTools.ps1"
. "$PSScriptRoot\DataExport.ps1"

# Note: This file has been split into smaller modules for better maintainability:
# - APIIntegration.ps1: Invoke-RestApiCall
# - DatabaseIntegration.ps1: Connect-Database, Invoke-DatabaseQuery
# - ExternalTools.ps1: Invoke-ExternalTool, Get-ExternalToolInfo
# - DataExport.ps1: Export-DataToExternalFormat
