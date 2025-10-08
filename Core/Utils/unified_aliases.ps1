﻿# PowerShell Unified Alias Configuration

# Ensure Test-CommandExists is available
function Test-CommandExists {
  param($command)
  $oldPreference = $ErrorActionPreference
  # Suppress errors for command existence check (log this action)
  $ErrorActionPreference = 'SilentlyContinue'
  try {
    if (Get-Command $command) {
      return $true
    }
  }
  catch {
    Write-Host "$command does not exist"
    return $false
  }
  finally {
    $ErrorActionPreference = $oldPreference
  }
}

# Navigation aliases and utilities
function .. { Set-Location .\.. }
function ... { Set-Location .\..\..\ }
function .3 { Set-Location .\..\..\..\.. }
function .4 { Set-Location .\..\..\..\..\ }
function .5 { Set-Location .\..\..\..\..\..\.. }

# Editor detection and configuration - lazy loaded
function Initialize-Editor {
    if ($script:EditorInitialized) { return }
    $script:EditorInitialized = $true
    
    $editors = @('nvim', 'code', 'notepad', 'pvim', 'vim', 'vi', 'notepad++', 'sublime_text')
    foreach ($editor in $editors) {
        if (Test-CommandExists $editor) {
            $script:EDITOR = $editor
            if ($editor -eq 'nvim' -and (Test-Path "$env:LOCALAPPDATA/$env:DEFAULT_NVIM_CONFIG" -PathType Container)) {
                $env:NVIM_APPNAME = $env:DEFAULT_NVIM_CONFIG
            }
            break
        }
    }
}

# Lazy editor alias that initializes on first use
function v {
    if (-not $script:EditorInitialized) { Initialize-Editor }
    if ($script:EDITOR) { & $script:EDITOR @args } else { Write-Host "No editor found" }
}

# System aliases
# Note: 'v' alias is now a function that lazy-loads the editor
Set-Alias -Name e -Value explorer.exe
Set-Alias -Name c -Value cls
Set-Alias -Name csl -Value cls
Set-Alias -Name ss -Value Select-String
Set-Alias -Name grep -Value Select-String
Set-Alias -Name shutdownnow -Value Stop-Computer
Set-Alias -Name rebootnow -Value Restart-Computer

# Git aliases
Set-Alias -Name g -Value git
function git-status { git status }
function git-pull { git pull }
function git-push { git push }
Set-Alias -Name gst -Value git-status
Set-Alias -Name pull -Value git-pull
Set-Alias -Name push -Value git-push

# Docker aliases
Set-Alias -Name d -Value docker
Set-Alias -Name dc -Value docker-compose

# Conditional aliases
if (Get-Command lazygit -ErrorAction SilentlyContinue) {
  Set-Alias -Name lg -Value lazygit
}

# Configure bat if available
if (Get-Command bat -ErrorAction SilentlyContinue) {
  $env:BAT_THEME = 'Nord'
  Remove-Item Alias:cat -Force -ErrorAction SilentlyContinue
  Set-Alias -Name cat -Value bat -Force -Option AllScope -Scope Global
}

# Configure exa if available
if (Get-Command exa -ErrorAction SilentlyContinue) {
  function ls_with_exa {
    param([Parameter(ValueFromRemainingArguments = $true)]$params)
    $exaOutput = $(if ($params) {
        exa --icons --git --color=always --group-directories-first $params
      }
      else {
        exa --icons --git --color=always --group-directories-first
      })
    if (Get-Command bat -ErrorAction SilentlyContinue) {
      $exaOutput | Out-String | bat --plain --paging=never
    }
    else {
      $exaOutput
    }
  }
  function ll_with_exa {
    $exaOutput = exa --icons --git --color=always --group-directories-first --long --header
    if (Get-Command bat -ErrorAction SilentlyContinue) {
      $exaOutput | Out-String | bat --plain --paging=never
    }
    else {
      $exaOutput
    }
  }
  Set-Alias -Name ls -Value ls_with_exa -Force -Option AllScope -Scope Global
  Set-Alias -Name ll -Value ll_with_exa -Force -Option AllScope -Scope Global
}
else {
  function ll {
    Get-ChildItem | Format-Table -AutoSize -Property Mode, LastWriteTime, Length, Name
  }
  Set-Alias -Name ll -Value ll -Force -Option AllScope -Scope Global
}

# File and directory management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }
function New-File($file) { "" | Out-File $file -Encoding ASCII }
Set-Alias -Name touch -Value New-File

# System information and utilities
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip ).Content }
function Get-FormatedUptime {
  $bootuptime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
  $CurrentDate = Get-Date
  $uptime = $CurrentDate - $bootuptime
  Write-Output "Uptime: $($uptime.Days) Days, $($uptime.Hours) Hours, $($uptime.Minutes) Minutes"
}

function uptime {
  If ($PSVersionTable.PSVersion.Major -eq 5) {
    Get-WmiObject win32_operatingsystem |
    Select-Object @{EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } } | Format-Table -HideTableHeaders
  }
  Else {
    Get-FormatedUptime
    net statistics workstation | Select-String "since" | foreach-object { $_.ToString().Replace('Statistics since ', 'Since: ') }
  }
}

# Search and find utilities
function find-file($name) {
  Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
    $place_path = $_.directory
    Write-Output "${place_path}\${_}"
  }
}

function Find-String($regex, $dir) {
  if ($dir) {
    Get-ChildItem $dir | Select-String $regex
    return
  }
  $input | Select-String $regex
}
Set-Alias -Name grep -Value Find-String

# System utilities
function df { get-volume }
function which($name) { Get-Command $name | Select-Object -ExpandProperty Definition }
function Set-EnvironmentVariable($name, $value) { set-item -force -path "env:$name" -value $value }
Set-Alias -Name export -Value Set-EnvironmentVariable

function Stop-ProcessByName($name) { Get-Process $name -ErrorAction SilentlyContinue | Stop-Process }
Set-Alias -Name pkill -Value Stop-ProcessByName

function Get-ProcessByName($name) { Get-Process $name }
Set-Alias -Name pgrep -Value Get-ProcessByName

# Profile management
# This is now handled by the ProfileManagement module

# Export all aliases and functions
# Export-ModuleMember -Function * -Alias * -Variable EDITOR

# ref: https://github.com/ChrisTitusTech/powershell-profile/blob/main/Microsoft.PowerShell_profile.ps1

function Get-AvailableModules {
  Get-Module -ListAvailable
}

function Update-PowerShell {
  if (-not $global:canConnectToGitHub) {
    Write-Host "Skipping PowerShell update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
    return
  }

  try {
    Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
    $updateNeeded = $false
    $currentVersion = $PSVersionTable.PSVersion.ToString()
    $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
    $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
    $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
    if ($currentVersion -lt $latestVersion) {
      $updateNeeded = $true
    }

    if ($updateNeeded) {
      Write-Host "Updating PowerShell..." -ForegroundColor Yellow
      winget upgrade "Microsoft.PowerShell" --accept-source-agreements --accept-package-agreements
      Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
    }
    else {
      Write-Host "Your PowerShell is up to date." -ForegroundColor Green
    }
  }
  catch {
    Write-Error "Failed to update PowerShell. Error: $_"
  }
}

function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-BIOS {
  if (Test-IsAdmin) {
    shutdown /r /fw /f /t 0
  }
  else {
    if (Test-CommandExists sudo) {
      sudo shutdown /r /fw /f /t 0
    }
    else {
      Write-Host "Please run with administrator privilege"
    }
  }
}

function Get-PubIP {
  (Invoke-WebRequest http://ifconfig.me/ip ).Content
}

function Get-FormatedUptime {
  $bootuptime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
  $CurrentDate = Get-Date
  $uptime = $CurrentDate - $bootuptime
  Write-Output "Uptime: $($uptime.Days) Days, $($uptime.Hours) Hours, $($uptime.Minutes) Minutes"
}

function uptime {
  #Windows Powershell only
  If ($PSVersionTable.PSVersion.Major -eq 5 ) {
    Get-WmiObject win32_operatingsystem |
    Select-Object @{EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } } | Format-Table -HideTableHeaders
  }
  Else {
    Get-FormatedUptime
    net statistics workstation | Select-String "since" | foreach-object { $_.ToString().Replace('Statistics since ', 'Since: ') }
  }
}

function find-file($name) {
  Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
    $place_path = $_.directory
    Write-Output "${place_path}\${_}"
  }
}

function Expand-ZipFile($file) {
  Write-Output("Extracting", $file, "to", $pwd)
  $fullFile = Get-ChildItem -Path $pwd -Filter .\cove.zip | ForEach-Object { $_.FullName }
  Expand-Archive -Path $fullFile -DestinationPath $pwd
}
Set-Alias -Name unzip -Value Expand-ZipFile

function hb {
  if ($args.Length -eq 0) {
    Write-Error "No file path specified."
    return
  }

  $FilePath = $args[0]

  if (Test-Path $FilePath) {
    $Content = Get-Content $FilePath -Raw
  }
  else {
    Write-Error "File path does not exist."
    return
  }

  $uri = "http://bin.christitus.com/documents"
  try {
    $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop
    $hasteKey = $response.key
    $url = "http://bin.christitus.com/$hasteKey"
    Write-Output $url
  }
  catch {
    Write-Error "Failed to upload the document. Error: $_"
  }
}

function head {
  param($Path, $n = 10)
  Get-Content $Path -Head $n
}

function tail {
  param($Path, $n = 10)
  Get-Content $Path -Tail $n
}

function mkcd {
  param($dir) mkdir $dir -Force; Set-Location $dir 
}

# Quick Access to System Information
function sysinfo {
  Get-ComputerInfo 
}

# Networking Utilities
function Clear-DnsCache {
  Clear-DnsClientCache 
}
Set-Alias -Name flushdns -Value Clear-DnsCache

# Clipboard Utilities
function Set-ClipboardContent {
  Set-Clipboard $args[0] 
}
Set-Alias -Name cpy -Value Set-ClipboardContent

function Get-ClipboardContent {
  Get-Clipboard 
}
Set-Alias -Name pst -Value Get-ClipboardContent

function ix ($file) {
  curl.exe -F "f:1=@$file" ix.io
}

function grep($regex, $dir) {
  if ( $dir ) {
    Get-ChildItem $dir | select-string $regex
    return
  }
  $input | select-string $regex
}

function touch($file) {
  "" | Out-File $file -Encoding ASCII
}

function df {
  get-volume
}

function Edit-FileContent($file, $find, $replace) {
  (Get-Content $file).replace("$find", $replace) | Set-Content $file
}
Set-Alias -Name sed -Value Edit-FileContent

function Get-CommandPath($command) {
  Get-Command -Name $command -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue
}
Set-Alias -Name which -Value Get-CommandPath

function export($name, $value) {
  set-item -force -path "env:$name" -value $value;
}

function pkill($name) {
  Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pgrep($name) {
  Get-Process $name
}

# Powershell profile from https://github.com/craftzdog/dotfiles-public/blob/master/.config/powershell/user_profile.ps1

[console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-BIOS {
  if (Test-IsAdmin) {
    shutdown /r /fw /f /t 0
  }
  else {
    if (Test-CommandExists sudo) {
      sudo shutdown /r /fw /f /t 0
    }
    else {
      Write-Host "Please run with administrator privilege"
    }
  }
}

# Ref: https://gist.github.com/mikepruett3/7ca6518051383ee14f9cf8ae63ba18a7
function Expand-CustomArchive {
  param (
    [string]$File,
    [string]$Folder
  )

  if (-not $Folder) {
    $FileName = [System.IO.Path]::GetFileNameWithoutExtension($File)
    $Folder = Join-Path -Path (Split-Path -Path $File -Parent) -ChildPath "$FileName"
  }

  if (-not (Test-Path -Path $Folder -PathType Container)) {
    New-Item -Path $Folder -ItemType Directory | Out-Null
  }

  if (Test-Path -Path "$File" -PathType Leaf) {
    switch ($File.Split(".") | Select-Object -Last 1) {
      "rar" {
        Start-Process -FilePath "UnRar.exe" -ArgumentList "x", "-op'$Folder'", "-y", "$File" -WorkingDirectory "$Env:ProgramFiles\WinRAR\" -Wait | Out-Null 
      }
      "zip" {
        7z x -o"$Folder" -y "$File" | Out-Null 
      }
      "7z" {
        7z x -o"$Folder" -y "$File" | Out-Null 
      }
      "exe" {
        7z x -o"$Folder" -y "$File" | Out-Null 
      }
      Default {
        Write-Error "No way to Extract $File !!!"; return;
      }
    }
    Write-Host "Extracted "$FILE" to "$($Folder)""
  }
}
Set-Alias -Name extract -Value Expand-CustomArchive

function Expand-MultipleArchives {
  $CurrentDate = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
  $Folder = "extracted_$($CurrentDate)"
  New-Item -Path $Folder -ItemType Directory | Out-Null
  foreach ($File in $args) {
    Expand-CustomArchive -File $File -Folder "$($Folder)\$([System.IO.Path]::GetFileNameWithoutExtension($File))"
  }
}
Set-Alias -Name extract_multi -Value Expand-MultipleArchives

function Get-Fonts {
  param (
    $regex
  )
  $AllFonts = (New-Object System.Drawing.Text.InstalledFontCollection).Families.Name
  if ($null -ne $regex) {
    $FilteredFonts = $($AllFonts | Select-String -Pattern ".*${regex}.*")
    return $FilteredFonts
  }
  return $AllFonts
}

function Upgrade {
  # Function to check if pwsh is installed
  function Get-PwshInstalled {
    return Get-Command pwsh -ErrorAction SilentlyContinue
  }

  # Function to install PowerShell 7 using winget
  function Install-Pwsh {
    Write-Host "Installing PowerShell 7..."
    winget install --id Microsoft.Powershell --source winget -y
  }

  # Check if pwsh is installed
  if (-not (Get-PwshInstalled)) {
    Install-Pwsh
    # Optionally, you can exit the function or script here
    Write-Host "Please restart your shell to use PowerShell 7."
    return
  }

  # Check if the script is running with administrative privileges
  $isAdmin = [bool](New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

  if (-not $isAdmin) {
    # If not running as admin, try to run with sudo (if available)
    if (Get-Command sudo -ErrorAction SilentlyContinue) {
      Write-Host "Running with sudo..."
      sudo pwsh -ExecutionPolicy Bypass -File "$PSScriptRoot\..\Core\Apps\UpdateApps.ps1"
    }
    else {
      # If sudo is not available, use runas
      Write-Host "Running with runas..."
      Start-Process pwsh -ArgumentList "-ExecutionPolicy Bypass -File `"$PSScriptRoot\..\Core\Apps\UpdateApps.ps1`"" -Verb RunAs
    }
  }
  else {
    # If running as admin, execute the update script directly
    . "$PSScriptRoot\..\Apps\UpdateApps.ps1"
  }
}
