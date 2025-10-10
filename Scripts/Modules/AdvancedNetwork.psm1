# AdvancedNetwork.psm1 - Advanced Network Forensics Module

# Import all network analysis functions
. $PSScriptRoot\NetworkCaptureFunctions.ps1
. $PSScriptRoot\NetworkTrafficAnalysisFunctions.ps1
. $PSScriptRoot\DNSAnalysisFunctions.ps1
. $PSScriptRoot\FirewallAnalysisFunctions.ps1
. $PSScriptRoot\NetworkAnomalyFunctions.ps1
. $PSScriptRoot\AdvancedNetworkAnalysisFunctions.ps1

# Module exports
Export-ModuleMember -Function @(
    'Start-NetworkCapture',
    'Get-NetworkTrafficAnalysis',
    'Get-DNSAnalysis',
    'Get-FirewallLogAnalysis',
    'Get-NetworkAnomalies',
    'Invoke-AdvancedNetworkAnalysis'
)