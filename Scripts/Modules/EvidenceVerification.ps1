# EvidenceVerification.ps1
# Functions for verifying evidence integrity

<#
.SYNOPSIS
    Evidence Verification Functions

.DESCRIPTION
    This file contains functions for verifying evidence integrity including:
    - Verify-EvidenceIntegrity: Checks hash integrity of evidence files

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7+ for full functionality
    Depends on: EvidenceClasses.ps1
#>

function Verify-EvidenceIntegrity {
    <#
    .SYNOPSIS
        Verifies the integrity of evidence files

    .DESCRIPTION
        Recalculates hashes and compares with stored values to ensure evidence hasn't been tampered with

    .PARAMETER Evidence
        The evidence item to verify

    .PARAMETER UpdateVerification
        Whether to update the verification timestamp

    .EXAMPLE
        $isValid = Verify-EvidenceIntegrity -Evidence $evidence
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [EvidenceItem]$Evidence,

        [Parameter(Mandatory = $false)]
        [switch]$UpdateVerification
    )

    try {
        Write-Host "Verifying evidence integrity: $($Evidence.EvidenceId)" -ForegroundColor Cyan

        # Check if evidence file exists
        if (-not (Test-Path $Evidence.Path)) {
            Write-Warning "Evidence file not found: $($Evidence.Path)"
            $Evidence.IsVerified = $false
            return $false
        }

        # Recalculate hashes
        $currentSHA256 = (Get-FileHash -Path $Evidence.Path -Algorithm SHA256).Hash
        $currentSHA1 = (Get-FileHash -Path $Evidence.Path -Algorithm SHA1).Hash
        $currentMD5 = (Get-FileHash -Path $Evidence.Path -Algorithm MD5).Hash

        # Compare hashes
        $isValid = ($currentSHA256 -eq $Evidence.HashSHA256) -and
                   ($currentSHA1 -eq $Evidence.HashSHA1) -and
                   ($currentMD5 -eq $Evidence.HashMD5)

        if ($isValid) {
            Write-Host "Evidence integrity verified successfully" -ForegroundColor Green
            $Evidence.IsVerified = $true
            if ($UpdateVerification) {
                $Evidence.LastVerified = Get-Date
            }
        } else {
            Write-Warning "Evidence integrity check FAILED!"
            $Evidence.IsVerified = $false

            # Log the discrepancy
            $discrepancy = [PSCustomObject]@{
                Timestamp = Get-Date
                EvidenceId = $Evidence.EvidenceId
                StoredSHA256 = $Evidence.HashSHA256
                CurrentSHA256 = $currentSHA256
                StoredSHA1 = $Evidence.HashSHA1
                CurrentSHA1 = $currentSHA1
                StoredMD5 = $Evidence.HashMD5
                CurrentMD5 = $currentMD5
            }

            Write-Warning "Hash discrepancy detected. Evidence may have been tampered with."
        }

        return $isValid
    }
    catch {
        Write-Error "Failed to verify evidence integrity: $($_.Exception.Message)"
        $Evidence.IsVerified = $false
        return $false
    }
}