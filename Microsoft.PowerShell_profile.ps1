# Microsoft.PowerShell_profile.ps1
# PowerShell Profile with modular functions

<#
.SYNOPSIS
    PowerShell Profile for Forensics and Development

.DESCRIPTION
    This profile loads various utilities and functions for PowerShell usage
    including forensics tools, development utilities, and shell enhancements.

.NOTES
    Author: Profile Configuration Team
    Version: 1.0.0
#>

# Import profile modules
. "$PSScriptRoot\Scripts\Modules\ProfileInitialization.ps1"
. "$PSScriptRoot\Scripts\Modules\BackgroundJobUtils.ps1"
. "$PSScriptRoot\Scripts\Modules\CustomPrompt.ps1"
. "$PSScriptRoot\Scripts\Modules\PSReadLineUtils.ps1"
. "$PSScriptRoot\Scripts\Modules\ThemeUtils.ps1"
. "$PSScriptRoot\Scripts\Modules\DependencyInstaller.ps1"