# AndroidDeviceFunctions.ps1
# Android device forensics functions

<#
.SYNOPSIS
    Android Device Forensics Functions

.DESCRIPTION
    This module provides functions for analyzing Android devices including
    device information, SMS messages, call logs, contacts, and location data.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: ADB (Android Debug Bridge) for device communication
#>

# Import Android forensics modules
. "$PSScriptRoot\AndroidDeviceInfo.ps1"
. "$PSScriptRoot\AndroidSMSMessages.ps1"
. "$PSScriptRoot\AndroidCallLogs.ps1"
. "$PSScriptRoot\AndroidContacts.ps1"
. "$PSScriptRoot\AndroidLocationData.ps1"