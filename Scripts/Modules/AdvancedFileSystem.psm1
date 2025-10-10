# AdvancedFileSystem.psm1 - Advanced File System Forensics Module

# Import all advanced file system functions
. "$PSScriptRoot\FileSignatureFunctions.ps1"
. "$PSScriptRoot\FileCarvingFunctions.ps1"
. "$PSScriptRoot\FileSystemTimelineFunctions.ps1"
. "$PSScriptRoot\DeletedFilesFunctions.ps1"
. "$PSScriptRoot\FileAnomalyFunctions.ps1"
. "$PSScriptRoot\AdvancedFileSystemAnalysisFunctions.ps1"

# Export functions
Export-ModuleMember -Function @(
    'Get-FileSignatures',
    'Get-FileCarving',
    'Get-FileSystemTimeline',
    'Get-DeletedFilesAnalysis',
    'Get-FileAnomalyDetection',
    'Invoke-AdvancedFileSystemAnalysis'
)