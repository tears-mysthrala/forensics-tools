# DNSAnalysisFunctions.ps1 - DNS query and cache analysis

function Get-DNSAnalysis {
    <#
    .SYNOPSIS
        Analyzes DNS queries and responses for forensic insights.
    .DESCRIPTION
        Examines DNS cache, recent queries, and suspicious domain lookups.
    .PARAMETER OutputPath
        Directory to save DNS analysis results.
    .EXAMPLE
        Get-DNSAnalysis -OutputPath C:\Evidence
    #>
    param(
        [string]$OutputPath = "."
    )

    Write-Host "Analyzing DNS activity..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "DNSAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $dnsAnalysis = @{
        Timestamp = Get-Date
        Analysis = @{}
    }

    # DNS Cache
    Write-Host "Collecting DNS cache..." -ForegroundColor Yellow
    try {
        $dnsCache = Get-DnsClientCache | Select-Object Name, Type, TTL, Data
        $dnsCache | Export-Csv (Join-Path $analysisDir "dns_cache.csv") -NoTypeInformation
        $dnsAnalysis.Analysis.DNSCache = "Collected $($dnsCache.Count) entries"
        Write-Host "[OK] DNS cache collected" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to collect DNS cache: $($_.Exception.Message)"
        $dnsAnalysis.Analysis.DNSCache = "Error: $($_.Exception.Message)"
    }

    # DNS Client Configuration
    Write-Host "Analyzing DNS client configuration..." -ForegroundColor Yellow
    try {
        $dnsConfig = Get-DnsClient | Select-Object InterfaceAlias, ConnectionSpecificSuffix, DNSServer
        $dnsConfig | Export-Csv (Join-Path $analysisDir "dns_configuration.csv") -NoTypeInformation
        $dnsAnalysis.Analysis.DNSConfig = "Collected configuration"
        Write-Host "[OK] DNS configuration analyzed" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to analyze DNS config: $($_.Exception.Message)"
        $dnsAnalysis.Analysis.DNSConfig = "Error: $($_.Exception.Message)"
    }

    # Recent DNS Queries (from event logs if available)
    Write-Host "Checking DNS event logs..." -ForegroundColor Yellow
    try {
        $dnsEvents = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message |
            Where-Object { $_.Message -match "query|response" }

        if ($dnsEvents) {
            $dnsEvents | Export-Csv (Join-Path $analysisDir "dns_events.csv") -NoTypeInformation
            $dnsAnalysis.Analysis.DNSEvents = "Collected $($dnsEvents.Count) events"
            Write-Host "[OK] DNS events collected" -ForegroundColor Green
        } else {
            $dnsAnalysis.Analysis.DNSEvents = "No DNS events found"
        }
    } catch {
        Write-Warning "Failed to collect DNS events: $($_.Exception.Message)"
        $dnsAnalysis.Analysis.DNSEvents = "Error: $($_.Exception.Message)"
    }

    # Suspicious Domains Check
    Write-Host "Checking for suspicious domains..." -ForegroundColor Yellow
    try {
        $suspiciousDomains = @(
            "pastebin\.com", "raw\.githubusercontent\.com", "transfer\.sh",
            "temp-mail\.org", "guerrillamail\.com", "protonmail\.com",
            "onion", "tor", "darkweb"
        )

        $suspiciousFound = $dnsCache | Where-Object {
            $domain = $_.Name
            $suspiciousDomains | Where-Object { $domain -match $_ }
        }

        if ($suspiciousFound) {
            $suspiciousFound | Export-Csv (Join-Path $analysisDir "suspicious_domains.csv") -NoTypeInformation
            $dnsAnalysis.Analysis.SuspiciousDomains = "Found $($suspiciousFound.Count) suspicious domains"
            Write-Host "⚠ Found suspicious domains in DNS cache" -ForegroundColor Red
        } else {
            $dnsAnalysis.Analysis.SuspiciousDomains = "No suspicious domains found"
            Write-Host "[OK] No suspicious domains found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check suspicious domains: $($_.Exception.Message)"
        $dnsAnalysis.Analysis.SuspiciousDomains = "Error: $($_.Exception.Message)"
    }

    # Save analysis summary
    $summaryFile = Join-Path $analysisDir "dns_analysis_summary.json"
    $dnsAnalysis | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "DNS analysis complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}