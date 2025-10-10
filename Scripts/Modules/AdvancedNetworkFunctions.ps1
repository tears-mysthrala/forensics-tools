# AdvancedNetworkFunctions.ps1 - Advanced network forensics and analysis

function Start-NetworkCapture {
    <#
    .SYNOPSIS
        Starts network packet capture for forensic analysis.
    .DESCRIPTION
        Uses available tools (Wireshark/tshark, netsh, or PowerShell) to capture network traffic.
    .PARAMETER Interface
        Network interface to capture on (default: auto-detect).
    .PARAMETER Duration
        Capture duration in seconds.
    .PARAMETER OutputPath
        Directory to save capture files.
    .PARAMETER Filter
        Capture filter (BPF syntax for tshark, or simple keywords).
    .EXAMPLE
        Start-NetworkCapture -Duration 60 -OutputPath C:\Evidence
        Start-NetworkCapture -Interface "Ethernet" -Filter "port 80 or port 443"
    #>
    param(
        [string]$Interface,
        [int]$Duration = 30,
        [string]$OutputPath = ".",
        [string]$Filter = ""
    )

    Write-Host "Starting network capture (Duration: $Duration seconds)..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $captureFile = Join-Path $OutputPath "network_capture_$timestamp.pcap"

    # Try different capture methods in order of preference
    $captureMethods = @(
        @{Name = "tshark"; Command = "tshark" },
        @{Name = "Wireshark"; Command = "dumpcap" },
        @{Name = "netsh"; Command = "netsh" },
        @{Name = "PowerShell"; Command = "powershell" }
    )

    foreach ($method in $captureMethods) {
        Write-Host "Attempting capture with $($method.Name)..." -ForegroundColor Gray

        switch ($method.Name) {
            "tshark" {
                # Check if tshark is available
                $tshark = Get-Command tshark -ErrorAction SilentlyContinue
                if ($tshark) {
                    try {
                        $cmd = "& tshark -i $Interface -a duration:$Duration -w '$captureFile'"
                        if ($Filter) { $cmd += " -f '$Filter'" }
                        Invoke-Expression $cmd
                        if (Test-Path $captureFile) {
                            Write-Host "[OK] Network capture completed with tshark: $captureFile" -ForegroundColor Green
                            return $captureFile
                        }
                    } catch {
                        Write-Warning "tshark capture failed: $($_.Exception.Message)"
                    }
                }
            }
            "Wireshark" {
                # Check if dumpcap is available
                $dumpcap = Get-Command dumpcap -ErrorAction SilentlyContinue
                if ($dumpcap) {
                    try {
                        $cmd = "& dumpcap -i $Interface -a duration:$Duration -w '$captureFile'"
                        if ($Filter) { $cmd += " -f '$Filter'" }
                        Invoke-Expression $cmd
                        if (Test-Path $captureFile) {
                            Write-Host "[OK] Network capture completed with dumpcap: $captureFile" -ForegroundColor Green
                            return $captureFile
                        }
                    } catch {
                        Write-Warning "dumpcap capture failed: $($_.Exception.Message)"
                    }
                }
            }
            "netsh" {
                # Use netsh trace (Windows built-in)
                try {
                    $traceFile = Join-Path $OutputPath "netsh_trace_$timestamp.etl"
                    & netsh trace start capture=yes tracefile="$traceFile" maxsize=1024 filemode=circular 2>$null
                    Start-Sleep $Duration
                    & netsh trace stop 2>$null

                    if (Test-Path $traceFile) {
                        Write-Host "[OK] Network trace completed with netsh: $traceFile" -ForegroundColor Green
                        return $traceFile
                    }
                } catch {
                    Write-Warning "netsh trace failed: $($_.Exception.Message)"
                }
            }
            "PowerShell" {
                # Basic PowerShell network monitoring (limited)
                Write-Host "Using PowerShell for basic network monitoring..." -ForegroundColor Yellow
                try {
                    $startTime = Get-Date
                    $connections = @()

                    while (((Get-Date) - $startTime).TotalSeconds -lt $Duration) {
                        $currentConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
                        $connections += $currentConnections | ForEach-Object {
                            [PSCustomObject]@{
                                Timestamp = Get-Date
                                LocalAddress = $_.LocalAddress
                                LocalPort = $_.LocalPort
                                RemoteAddress = $_.RemoteAddress
                                RemotePort = $_.RemotePort
                                State = $_.State
                                ProcessId = $_.OwningProcess
                            }
                        }
                        Start-Sleep -Seconds 1
                    }

                    $connections | Export-Csv "$captureFile.csv" -NoTypeInformation
                    Write-Host "[OK] Basic network monitoring completed: $captureFile.csv" -ForegroundColor Green
                    return "$captureFile.csv"
                } catch {
                    Write-Warning "PowerShell monitoring failed: $($_.Exception.Message)"
                }
            }
        }
    }

    Write-Error "All network capture methods failed. Install Wireshark/tshark for proper packet capture."
    return $null
}

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

function Get-FirewallLogAnalysis {
    <#
    .SYNOPSIS
        Analyzes Windows Firewall logs for security insights.
    .DESCRIPTION
        Parses firewall logs to identify blocked connections and security events.
    .PARAMETER LogPath
        Path to firewall log file (default: standard Windows location).
    .PARAMETER OutputPath
        Directory to save analysis results.
    .EXAMPLE
        Get-FirewallLogAnalysis -OutputPath C:\Evidence
    #>
    param(
        [string]$LogPath,
        [string]$OutputPath = "."
    )

    # Default firewall log location
    if (-not $LogPath) {
        $LogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    }

    Write-Host "Analyzing firewall logs..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "FirewallAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $firewallAnalysis = @{
        Timestamp = Get-Date
        LogFile = $LogPath
        Analysis = @{}
    }

    if (-not (Test-Path $LogPath)) {
        Write-Warning "Firewall log not found: $LogPath"
        Write-Host "Enable firewall logging:" -ForegroundColor Yellow
        Write-Host "1. Open Windows Firewall with Advanced Security" -ForegroundColor Yellow
        Write-Host "2. Right-click 'Windows Firewall with Advanced Security' > Properties" -ForegroundColor Yellow
        Write-Host "3. Go to 'Logging' tab > Enable logging" -ForegroundColor Yellow
        $firewallAnalysis.Analysis.Status = "Log file not found"
        return $analysisDir
    }

    Write-Host "Parsing firewall log..." -ForegroundColor Yellow
    try {
        # Read firewall log (skip comments and empty lines)
        $logEntries = Get-Content $LogPath | Where-Object {
            $_ -notmatch "^#" -and $_.Trim() -ne ""
        } | ConvertFrom-Csv -Delimiter " " -Header @("Date", "Time", "Action", "Protocol", "SrcIP", "DstIP", "SrcPort", "DstPort", "Size", "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path")

        # Analyze blocked connections
        $blocked = $logEntries | Where-Object { $_.Action -eq "DROP" }
        $blocked | Export-Csv (Join-Path $analysisDir "blocked_connections.csv") -NoTypeInformation

        # Analyze by destination ports
        $ports = $blocked | Group-Object DstPort | Sort-Object Count -Descending | Select-Object Name, Count
        $ports | Export-Csv (Join-Path $analysisDir "blocked_ports.csv") -NoTypeInformation

        # Analyze by source IPs
        $sources = $blocked | Group-Object SrcIP | Sort-Object Count -Descending | Select-Object Name, Count
        $sources | Export-Csv (Join-Path $analysisDir "blocked_sources.csv") -NoTypeInformation

        # Find suspicious activity
        $suspicious = $blocked | Where-Object {
            $_.DstPort -match "^(21|22|23|25|53|110|143|993|995|3389|5900)$" -or
            $_.SrcIP -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
        }
        $suspicious | Export-Csv (Join-Path $analysisDir "suspicious_blocks.csv") -NoTypeInformation

        $firewallAnalysis.Analysis.Status = "Analyzed $($logEntries.Count) log entries"
        $firewallAnalysis.Analysis.BlockedConnections = $blocked.Count
        $firewallAnalysis.Analysis.SuspiciousBlocks = $suspicious.Count

        Write-Host "[OK] Firewall log analysis completed" -ForegroundColor Green
        Write-Host "  Total entries: $($logEntries.Count)" -ForegroundColor Cyan
        Write-Host "  Blocked connections: $($blocked.Count)" -ForegroundColor Cyan
        Write-Host "  Suspicious blocks: $($suspicious.Count)" -ForegroundColor Cyan

    } catch {
        Write-Warning "Failed to analyze firewall log: $($_.Exception.Message)"
        $firewallAnalysis.Analysis.Status = "Analysis failed: $($_.Exception.Message)"
    }

    # Save analysis summary
    $summaryFile = Join-Path $analysisDir "firewall_analysis_summary.json"
    $firewallAnalysis | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "Firewall analysis complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}

function Get-NetworkAnomalies {
    <#
    .SYNOPSIS
        Detects network anomalies and suspicious activity.
    .DESCRIPTION
        Analyzes current network state for unusual connections, ports, and traffic patterns.
    .PARAMETER OutputPath
        Directory to save anomaly analysis results.
    .EXAMPLE
        Get-NetworkAnomalies -OutputPath C:\Evidence
    #>
    param(
        [string]$OutputPath = "."
    )

    Write-Host "Detecting network anomalies..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "NetworkAnomalies_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $anomalies = @{
        Timestamp = Get-Date
        Anomalies = @{}
    }

    # Unusual listening ports
    Write-Host "Checking for unusual listening ports..." -ForegroundColor Yellow
    try {
        $listeningPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" }
        $unusualPorts = $listeningPorts | Where-Object {
            $_.LocalPort -notin @(80, 443, 3389, 5985, 5986, 22, 21, 25, 53, 110, 143, 993, 995, 135, 139, 445, 3389)
        }

        if ($unusualPorts) {
            $unusualPorts | Select-Object LocalAddress, LocalPort, OwningProcess |
                Export-Csv (Join-Path $analysisDir "unusual_listening_ports.csv") -NoTypeInformation
            $anomalies.Anomalies.UnusualPorts = "Found $($unusualPorts.Count) unusual listening ports"
            Write-Host "⚠ Found $($unusualPorts.Count) unusual listening ports" -ForegroundColor Red
        } else {
            $anomalies.Anomalies.UnusualPorts = "No unusual listening ports found"
            Write-Host "[OK] No unusual listening ports found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check listening ports: $($_.Exception.Message)"
        $anomalies.Anomalies.UnusualPorts = "Error: $($_.Exception.Message)"
    }

    # External connections
    Write-Host "Checking external connections..." -ForegroundColor Yellow
    try {
        $externalConnections = Get-NetTCPConnection | Where-Object {
            $_.State -eq "Established" -and
            $_.RemoteAddress -notmatch "^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
        }

        if ($externalConnections) {
            $externalConnections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
                Export-Csv (Join-Path $analysisDir "external_connections.csv") -NoTypeInformation
            $anomalies.Anomalies.ExternalConnections = "Found $($externalConnections.Count) external connections"
            Write-Host "[OK] Found $($externalConnections.Count) external connections" -ForegroundColor Green
        } else {
            $anomalies.Anomalies.ExternalConnections = "No external connections found"
        }
    } catch {
        Write-Warning "Failed to check external connections: $($_.Exception.Message)"
        $anomalies.Anomalies.ExternalConnections = "Error: $($_.Exception.Message)"
    }

    # Suspicious processes with network activity
    Write-Host "Checking suspicious processes..." -ForegroundColor Yellow
    try {
        $networkProcesses = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } |
            Group-Object OwningProcess | Sort-Object Count -Descending

        $suspiciousProcesses = $networkProcesses | Where-Object { $_.Count -gt 10 } |
            ForEach-Object {
                $proc = Get-Process -Id $_.Name -ErrorAction SilentlyContinue
                if ($proc) {
                    [PSCustomObject]@{
                        ProcessId = $_.Name
                        ProcessName = $proc.ProcessName
                        ConnectionCount = $_.Count
                        StartTime = $proc.StartTime
                    }
                }
            }

        if ($suspiciousProcesses) {
            $suspiciousProcesses | Export-Csv (Join-Path $analysisDir "suspicious_processes.csv") -NoTypeInformation
            $anomalies.Anomalies.SuspiciousProcesses = "Found $($suspiciousProcesses.Count) processes with high connection counts"
            Write-Host "⚠ Found processes with high network activity" -ForegroundColor Yellow
        } else {
            $anomalies.Anomalies.SuspiciousProcesses = "No suspicious processes found"
            Write-Host "[OK] No suspicious processes found" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check suspicious processes: $($_.Exception.Message)"
        $anomalies.Anomalies.SuspiciousProcesses = "Error: $($_.Exception.Message)"
    }

    # Save anomalies summary
    $summaryFile = Join-Path $analysisDir "network_anomalies_summary.json"
    $anomalies | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "Network anomaly detection complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}

function Invoke-AdvancedNetworkAnalysis {
    <#
    .SYNOPSIS
        Performs comprehensive advanced network forensics analysis.
    .DESCRIPTION
        Combines network capture, traffic analysis, DNS analysis, firewall logs, and anomaly detection.
    .PARAMETER CaptureDuration
        Duration for network capture in seconds.
    .PARAMETER OutputPath
        Directory to save all analysis results.
    .EXAMPLE
        Invoke-AdvancedNetworkAnalysis -CaptureDuration 60 -OutputPath C:\NetworkAnalysis
    #>
    param(
        [int]$CaptureDuration = 30,
        [string]$OutputPath = "."
    )

    Write-Host "=== ADVANCED NETWORK FORENSICS ANALYSIS ===" -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "AdvancedNetworkAnalysis_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    $workflow = @{
        Timestamp = Get-Date
        Steps = @()
        Results = @{}
    }

    # Step 1: Network Capture
    Write-Host "`nStep 1: Capturing Network Traffic" -ForegroundColor Yellow
    try {
        $captureFile = Start-NetworkCapture -Duration $CaptureDuration -OutputPath $analysisDir
        if ($captureFile) {
            $workflow.Results.NetworkCapture = $captureFile
            $workflow.Steps += "Network Capture: Success - $captureFile"
            Write-Host "[OK] Network capture completed" -ForegroundColor Green
        } else {
            $workflow.Steps += "Network Capture: Failed - No capture tool available"
            Write-Warning "Network capture failed"
        }
    } catch {
        $workflow.Steps += "Network Capture: Error - $($_.Exception.Message)"
        Write-Warning "Network capture error: $($_.Exception.Message)"
    }

    # Step 2: Traffic Analysis
    if ($captureFile) {
        Write-Host "`nStep 2: Analyzing Network Traffic" -ForegroundColor Yellow
        try {
            $trafficAnalysis = Get-NetworkTrafficAnalysis -CaptureFile $captureFile -OutputPath $analysisDir
            $workflow.Results.TrafficAnalysis = $trafficAnalysis
            $workflow.Steps += "Traffic Analysis: Success - $trafficAnalysis"
            Write-Host "[OK] Traffic analysis completed" -ForegroundColor Green
        } catch {
            $workflow.Steps += "Traffic Analysis: Error - $($_.Exception.Message)"
            Write-Warning "Traffic analysis error: $($_.Exception.Message)"
        }
    }

    # Step 3: DNS Analysis
    Write-Host "`nStep 3: Analyzing DNS Activity" -ForegroundColor Yellow
    try {
        $dnsAnalysis = Get-DNSAnalysis -OutputPath $analysisDir
        $workflow.Results.DNSAnalysis = $dnsAnalysis
        $workflow.Steps += "DNS Analysis: Success - $dnsAnalysis"
        Write-Host "[OK] DNS analysis completed" -ForegroundColor Green
    } catch {
        $workflow.Steps += "DNS Analysis: Error - $($_.Exception.Message)"
        Write-Warning "DNS analysis error: $($_.Exception.Message)"
    }

    # Step 4: Firewall Analysis
    Write-Host "`nStep 4: Analyzing Firewall Logs" -ForegroundColor Yellow
    try {
        $firewallAnalysis = Get-FirewallLogAnalysis -OutputPath $analysisDir
        $workflow.Results.FirewallAnalysis = $firewallAnalysis
        $workflow.Steps += "Firewall Analysis: Success - $firewallAnalysis"
        Write-Host "[OK] Firewall analysis completed" -ForegroundColor Green
    } catch {
        $workflow.Steps += "Firewall Analysis: Error - $($_.Exception.Message)"
        Write-Warning "Firewall analysis error: $($_.Exception.Message)"
    }

    # Step 5: Anomaly Detection
    Write-Host "`nStep 5: Detecting Network Anomalies" -ForegroundColor Yellow
    try {
        $anomalies = Get-NetworkAnomalies -OutputPath $analysisDir
        $workflow.Results.AnomalyDetection = $anomalies
        $workflow.Steps += "Anomaly Detection: Success - $anomalies"
        Write-Host "[OK] Anomaly detection completed" -ForegroundColor Green
    } catch {
        $workflow.Steps += "Anomaly Detection: Error - $($_.Exception.Message)"
        Write-Warning "Anomaly detection error: $($_.Exception.Message)"
    }

    # Save workflow summary
    $summaryFile = Join-Path $analysisDir "advanced_network_analysis_workflow.json"
    $workflow | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "`n=== ADVANCED NETWORK ANALYSIS COMPLETE ===" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan
    Write-Host "Summary: $summaryFile" -ForegroundColor Cyan

    return $analysisDir
}