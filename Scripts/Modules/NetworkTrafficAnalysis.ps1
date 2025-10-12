# NetworkTrafficAnalysisFunctions.ps1 - Network traffic parsing and analysis

function Get-NetworkTrafficAnalysis {
    <#
    .SYNOPSIS
        Analyzes captured network traffic for forensic insights.
    .DESCRIPTION
        Parses network capture files to extract connections, protocols, and suspicious activity.
    .PARAMETER CaptureFile
        Path to the network capture file (.pcap, .etl, or .csv).
    .PARAMETER OutputPath
        Directory to save analysis results.
    .EXAMPLE
        Get-NetworkTrafficAnalysis -CaptureFile C:\Evidence\network_capture.pcap
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CaptureFile,
        [string]$OutputPath = "."
    )

    if (-not (Test-Path $CaptureFile)) {
        Write-Error "Capture file not found: $CaptureFile"
        return
    }

    Write-Host "Analyzing network traffic..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "NetworkAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $analysis = @{
        Timestamp = Get-Date
        CaptureFile = $CaptureFile
        Analysis = @{}
    }

    $fileExtension = [System.IO.Path]::GetExtension($CaptureFile).ToLower()

    switch ($fileExtension) {
        ".pcap" {
            # Analyze PCAP file
            Write-Host "Analyzing PCAP file..." -ForegroundColor Yellow

            # Check for tshark
            $tshark = Get-Command tshark -ErrorAction SilentlyContinue
            if ($tshark) {
                try {
                    # Extract conversations
                    $conversations = & tshark -r $CaptureFile -q -z conv,tcp 2>$null
                    $conversations | Out-File (Join-Path $analysisDir "tcp_conversations.txt")

                    # Extract HTTP requests
                    $http = & tshark -r $CaptureFile -Y "http.request" -T fields -e http.request.method -e http.request.uri -e http.host 2>$null
                    $http | Out-File (Join-Path $analysisDir "http_requests.txt")

                    # Extract DNS queries
                    $dns = & tshark -r $CaptureFile -Y "dns" -T fields -e dns.qry.name -e dns.a 2>$null
                    $dns | Out-File (Join-Path $analysisDir "dns_queries.txt")

                    # Extract suspicious ports
                    $suspiciousPorts = & tshark -r $CaptureFile -Y "tcp.port < 1024 and tcp.port != 80 and tcp.port != 443" -T fields -e tcp.srcport -e tcp.dstport -e ip.src -e ip.dst 2>$null
                    $suspiciousPorts | Out-File (Join-Path $analysisDir "suspicious_ports.txt")

                    $analysis.Analysis.PCAP = "Analyzed with tshark"
                    Write-Host "[OK] PCAP analysis completed" -ForegroundColor Green
                } catch {
                    Write-Warning "PCAP analysis failed: $($_.Exception.Message)"
                    $analysis.Analysis.PCAP = "Analysis failed: $($_.Exception.Message)"
                }
            } else {
                Write-Warning "tshark not found. Install Wireshark for PCAP analysis."
                $analysis.Analysis.PCAP = "tshark not available"
            }
        }
        ".etl" {
            # Analyze ETL file (netsh trace)
            Write-Host "Analyzing ETL trace file..." -ForegroundColor Yellow
            try {
                # Use netsh to convert ETL to text
                $textFile = Join-Path $analysisDir "trace_text.txt"
                & netsh trace convert input="$CaptureFile" output="$textFile" 2>$null

                if (Test-Path $textFile) {
                    $analysis.Analysis.ETL = "Converted to text format"
                    Write-Host "[OK] ETL analysis completed" -ForegroundColor Green
                } else {
                    $analysis.Analysis.ETL = "Conversion failed"
                }
            } catch {
                Write-Warning "ETL analysis failed: $($_.Exception.Message)"
                $analysis.Analysis.ETL = "Analysis failed: $($_.Exception.Message)"
            }
        }
        ".csv" {
            # Analyze CSV connection data
            Write-Host "Analyzing CSV connection data..." -ForegroundColor Yellow
            try {
                $connections = Import-Csv $CaptureFile

                # Analyze by remote addresses
                $remoteHosts = $connections | Group-Object RemoteAddress | Sort-Object Count -Descending
                $remoteHosts | Export-Csv (Join-Path $analysisDir "remote_hosts.csv") -NoTypeInformation

                # Analyze by ports
                $ports = $connections | Group-Object RemotePort | Sort-Object Count -Descending
                $ports | Export-Csv (Join-Path $analysisDir "ports_used.csv") -NoTypeInformation

                # Find suspicious connections
                $suspicious = $connections | Where-Object {
                    $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)" -and
                    $_.RemotePort -match "^(21|22|23|25|53|110|143|993|995|3389|5900)$"
                }
                $suspicious | Export-Csv (Join-Path $analysisDir "suspicious_connections.csv") -NoTypeInformation

                $analysis.Analysis.CSV = "Analyzed $($connections.Count) connections"
                Write-Host "[OK] CSV analysis completed" -ForegroundColor Green
            } catch {
                Write-Warning "CSV analysis failed: $($_.Exception.Message)"
                $analysis.Analysis.CSV = "Analysis failed: $($_.Exception.Message)"
            }
        }
    }

    # Save analysis summary
    $summaryFile = Join-Path $analysisDir "network_analysis_summary.json"
    $analysis | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "Network traffic analysis complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}