# APIIntegration.ps1
# API connectivity functions for REST services and web APIs

<#
.SYNOPSIS
    API Integration Functions

.DESCRIPTION
    This module provides functions for making REST API calls and external service integration.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

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
            Uri         = $Uri
            Method      = $Method
            TimeoutSec  = $TimeoutSec
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
            Success    = $true
            Data       = $response
            StatusCode = 200
            Timestamp  = Get-Date
        }
    }
    catch {
        Write-Warning "API call failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Success    = $false
            Error      = $_.Exception.Message
            StatusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 0 }
            Timestamp  = Get-Date
        }
    }
}