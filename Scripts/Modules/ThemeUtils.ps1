function Test-CatppuccinPresent {
    $module = Get-Module -ListAvailable Catppuccin | Sort-Object Version -Descending | Select-Object -First 1
    if ($module) { return $true }
    $customPaths = @(
        "$env:USERPROFILE\\Documents\\PowerShell\\Modules\\Catppuccin",
        "$env:USERPROFILE\\Documents\\WindowsPowerShell\\Modules\\Catppuccin",
        "$env:USERPROFILE\\OneDrive\\Documents\\PowerShell\\Modules\\Catppuccin"
    )
    foreach ($path in $customPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Include *.psd1, *.psm1 -File -ErrorAction SilentlyContinue
            if ($files) {
                return $true
            }
        }
    }
    return $false
}