# Advanced Network Forensics

Advanced network forensics with packet capture and traffic analysis.

## Functions

### Start-NetworkCapture

Captures network traffic using Wireshark/tshark, netsh, or PowerShell.

```powershell
Start-NetworkCapture -Duration 60 -OutputPath "C:\Evidence"
```

**Parameters:**

- `Duration`: Capture duration in seconds
- `OutputPath`: Directory for capture files
- `Interface`: Network interface to capture on

**Returns:**

- Packet capture files
- Capture statistics and metadata

### Get-NetworkTrafficAnalysis

Analyzes captured traffic for connections, protocols, and suspicious activity.

```powershell
Get-NetworkTrafficAnalysis -CaptureFile "C:\Evidence\network_capture.pcap" -OutputPath "C:\Analysis"
```

**Parameters:**

- `CaptureFile`: Path to capture file
- `OutputPath`: Directory for analysis results

**Returns:**

- Connection analysis, protocol breakdown
- Suspicious traffic patterns

### Get-DNSAnalysis

Examines DNS cache, queries, and suspicious domain lookups.

```powershell
Get-DNSAnalysis -OutputPath "C:\Evidence"
```

**Parameters:**

- `OutputPath`: Directory for DNS analysis

**Returns:**

- DNS cache contents, recent queries
- Suspicious domain analysis

### Get-FirewallLogAnalysis

Parses Windows Firewall logs for blocked connections and security events.

```powershell
Get-FirewallLogAnalysis -OutputPath "C:\Evidence"
```

**Parameters:**

- `OutputPath`: Directory for firewall analysis

**Returns:**

- Blocked connection attempts
- Firewall rule violations

### Get-NetworkAnomalies

Detects unusual network activity and suspicious connections.

```powershell
Get-NetworkAnomalies -OutputPath "C:\Evidence"
```

**Parameters:**

- `OutputPath`: Directory for anomaly detection

**Returns:**

- Anomalous connection patterns
- Suspicious network behavior

### Invoke-AdvancedNetworkAnalysis

Complete network forensics workflow.

```powershell
Invoke-AdvancedNetworkAnalysis -CaptureDuration 60 -OutputPath "C:\NetworkAnalysis"
```

**Parameters:**

- `CaptureDuration`: Duration for traffic capture
- `OutputPath`: Directory for complete analysis

**Returns:**

- Comprehensive network analysis
- Traffic patterns and anomalies