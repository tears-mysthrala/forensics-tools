# ExternalTools.ps1
# Third-party tool integration functions for running external forensics tools

<#
.SYNOPSIS
    External Tools Integration Functions

.DESCRIPTION
    This module provides functions for running and managing external forensics tools.

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
#>

function Invoke-ExternalTool {
    <#
    .SYNOPSIS
        Runs external forensics tools and captures output

    .DESCRIPTION
        Executes third-party forensics tools and parses their output for integration

    .PARAMETER ToolPath
        Path to the external tool executable

    .PARAMETER Arguments
        Command-line arguments for the tool

    .PARAMETER WorkingDirectory
        Working directory for tool execution

    .PARAMETER Timeout
        Maximum execution time in seconds

    .PARAMETER ParseOutput
        Script block to parse tool output

    .EXAMPLE
        Invoke-ExternalTool -ToolPath "C:\Tools\autopsy.exe" -Arguments "--help"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolPath,

        [Parameter(Mandatory = $false)]
        [string]$Arguments = "",

        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory = ".",

        [Parameter(Mandatory = $false)]
        [int]$Timeout = 300,

        [Parameter(Mandatory = $false)]
        [scriptblock]$ParseOutput
    )

    try {
        if (-not (Test-Path $ToolPath)) {
            throw "Tool not found: $ToolPath"
        }

        Write-Host "Running external tool: $ToolPath..." -ForegroundColor Cyan

        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $ToolPath
        $processInfo.Arguments = $Arguments
        $processInfo.WorkingDirectory = $WorkingDirectory
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo

        $output = ""
        $errorOutput = ""

        # Event handlers for output
        $outputEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
            $global:output += $Event.SourceEventArgs.Data + "`n"
        }
        $errorEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action {
            $global:errorOutput += $Event.SourceEventArgs.Data + "`n"
        }

        $process.Start() | Out-Null
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()

        # Wait for completion or timeout
        $completed = $process.WaitForExit($Timeout * 1000)

        if (-not $completed) {
            $process.Kill()
            throw "Tool execution timed out after $Timeout seconds"
        }

        # Clean up event handlers
        Unregister-Event -SourceIdentifier $outputEvent.Name
        Unregister-Event -SourceIdentifier $errorEvent.Name

        $exitCode = $process.ExitCode
        $process.Dispose()

        # Parse output if parser provided
        $parsedData = $null
        if ($ParseOutput -and $output) {
            try {
                $parsedData = & $ParseOutput $output
            }
            catch {
                Write-Warning "Output parsing failed: $($_.Exception.Message)"
            }
        }

        Write-Host "External tool completed with exit code: $exitCode" -ForegroundColor Green

        return [PSCustomObject]@{
            Success       = $exitCode -eq 0
            ExitCode      = $exitCode
            Output        = $output.Trim()
            ErrorOutput   = $errorOutput.Trim()
            ParsedData    = $parsedData
            ExecutionTime = $Timeout
            Timestamp     = Get-Date
        }
    }
    catch {
        Write-Error "External tool execution failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Success       = $false
            ExitCode      = -1
            Output        = ""
            ErrorOutput   = $_.Exception.Message
            ParsedData    = $null
            ExecutionTime = 0
            Timestamp     = Get-Date
        }
    }
}

function Get-ExternalToolInfo {
    <#
    .SYNOPSIS
        Gets information about available external forensics tools

    .DESCRIPTION
        Scans for installed forensics tools and provides integration information

    .PARAMETER ToolName
        Specific tool to check (optional)

    .EXAMPLE
        Get-ExternalToolInfo
        Get-ExternalToolInfo -ToolName "Wireshark"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ToolName
    )

    $tools = @(
        @{
            Name         = "Wireshark"
            Executable   = "wireshark.exe"
            Paths        = @("$env:ProgramFiles\Wireshark", "$env:ProgramFiles(x86)\Wireshark")
            Description  = "Network protocol analyzer"
            Capabilities = @("Packet Capture", "Protocol Analysis")
        },
        @{
            Name         = "Autopsy"
            Executable   = "autopsy.exe"
            Paths        = @("$env:ProgramFiles\Autopsy", "$env:ProgramFiles(x86)\Autopsy")
            Description  = "Digital forensics platform"
            Capabilities = @("File Analysis", "Timeline Analysis", "Keyword Search")
        },
        @{
            Name         = "FTK Imager"
            Executable   = "FTK Imager.exe"
            Paths        = @("$env:ProgramFiles\AccessData\FTK Imager", "$env:ProgramFiles(x86)\AccessData\FTK Imager")
            Description  = "Forensic image acquisition tool"
            Capabilities = @("Disk Imaging", "Memory Acquisition")
        },
        @{
            Name         = "Volatility"
            Executable   = "volatility.exe"
            Paths        = @("$env:ProgramFiles\Volatility", "$env:ProgramFiles(x86)\Volatility", "$env:USERPROFILE\volatility")
            Description  = "Memory forensics framework"
            Capabilities = @("Memory Analysis", "Process Dumping")
        },
        @{
            Name         = "YARA"
            Executable   = "yara.exe"
            Paths        = @("$env:ProgramFiles\YARA", "$env:ProgramFiles(x86)\YARA")
            Description  = "Pattern matching tool for malware analysis"
            Capabilities = @("Malware Detection", "Signature Matching")
        }
    )

    try {
        $results = @()

        foreach ($tool in $tools) {
            if ($ToolName -and $tool.Name -ne $ToolName) {
                continue
            }

            $found = $false
            $actualPath = $null

            # Check if tool is in PATH
            try {
                $pathResult = Get-Command $tool.Executable -ErrorAction Stop
                $found = $true
                $actualPath = $pathResult.Source
            }
            catch {
                # Check known installation paths
                foreach ($path in $tool.Paths) {
                    $fullPath = Join-Path $path $tool.Executable
                    if (Test-Path $fullPath) {
                        $found = $true
                        $actualPath = $fullPath
                        break
                    }
                }
            }

            $results += [PSCustomObject]@{
                Name         = $tool.Name
                Executable   = $tool.Executable
                Found        = $found
                Path         = $actualPath
                Description  = $tool.Description
                Capabilities = $tool.Capabilities
                Timestamp    = Get-Date
            }
        }

        if ($ToolName) {
            return $results | Where-Object { $_.Name -eq $ToolName }
        }

        return $results
    }
    catch {
        Write-Error "Failed to get external tool information: $($_.Exception.Message)"
        return $null
    }
}