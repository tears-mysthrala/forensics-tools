function prompt {
    # Get current timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Get user and computer info
    $user = $env:USERNAME
    $computer = $env:COMPUTERNAME

    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $adminIndicator = if ($isAdmin) { "[ADMIN]" } else { "" }

    # Get current directory (shorten if too long)
    $currentDir = $PWD.Path
    if ($currentDir.Length -gt 40) {
        $currentDir = "..." + $currentDir.Substring($currentDir.Length - 37)
    }

    # Show last exit code if non-zero
    $exitCode = if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { " [Exit:$LASTEXITCODE]" } else { "" }

    # Build the prompt
    $promptString = "[$timestamp] $user@$computer$adminIndicator $currentDir$exitCode`nPS> "

    # Set window title for additional traceability
    $Host.UI.RawUI.WindowTitle = "PowerShell - $user@$computer - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    # Return the prompt
    $promptString
}