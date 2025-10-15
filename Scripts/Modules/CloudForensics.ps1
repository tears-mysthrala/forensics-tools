# CloudForensics.ps1 - Azure Cloud Forensics Module
# This module imports all Azure forensics functions from separate modules

# Import Azure forensics modules
. "$PSScriptRoot\AzureInventory.ps1"
. "$PSScriptRoot\AzureLogs.ps1"
. "$PSScriptRoot\AzureStorage.ps1"
. "$PSScriptRoot\AzureVM.ps1"
. "$PSScriptRoot\AzureForensics.ps1"