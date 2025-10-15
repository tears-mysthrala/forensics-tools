# Search utilities for PowerShell profile

function Find-Files {
    param(
        [Parameter(Position=0)]
        [string]$pattern = "*",
        [string]$path = ".",
        [switch]$recurse
    )
    
    Get-ChildItem -Path $path -Filter $pattern -Recurse:$recurse | 
        Select-Object FullName, LastWriteTime, Length | 
        Sort-Object LastWriteTime -Descending
}

function Search-FileContent {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$searchPattern,
        [string]$searchPath = ".",
        [string]$fileFilter = "*.*",
        [switch]$caseSensitiveSearch
    )
    
    Get-ChildItem -Path $searchPath -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like $fileFilter } |
        Select-String -Pattern $searchPattern -CaseSensitive:$caseSensitiveSearch |
        Select-Object Path, Line, LineNumber
}

function Find-Command {
    param([string]$name)
    Get-Command -Name "*$name*" | 
        Select-Object Name, CommandType, Version, Source |
        Format-Table -AutoSize
}

# Set aliases
Set-Alias -Name ff -Value Find-Files
Set-Alias -Name search -Value Search-FileContent
Set-Alias -Name which -Value Find-Command


