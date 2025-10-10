# NetworkCaptureFunctions.ps1 - Network packet capture and monitoring

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