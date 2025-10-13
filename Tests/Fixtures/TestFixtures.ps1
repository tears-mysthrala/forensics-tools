# Test Fixtures for Forensics Tools Testing Framework
# Sample data and mock objects for testing

# Sample file system data
$script:SampleFileSystemData = @{
    TestFiles       = @(
        @{
            Name          = "test.txt"
            Content       = "This is a test file"
            Size          = 19
            LastWriteTime = Get-Date "2023-10-01 10:00:00"
        },
        @{
            Name          = "largefile.dat"
            Content       = "A" * 10000  # 10KB file
            Size          = 10000
            LastWriteTime = Get-Date "2023-10-02 15:30:00"
        },
        @{
            Name          = "hidden.txt"
            Content       = "Hidden file content"
            Size          = 19
            LastWriteTime = Get-Date "2023-10-03 08:15:00"
            Attributes    = [System.IO.FileAttributes]::Hidden
        }
    )

    TestDirectories = @(
        @{
            Name          = "TestFolder"
            LastWriteTime = Get-Date "2023-10-01 09:00:00"
        },
        @{
            Name          = "EmptyFolder"
            LastWriteTime = Get-Date "2023-10-04 12:00:00"
        }
    )
}

# Sample registry data
$script:SampleRegistryData = @{
    TestKeys = @(
        @{
            Path       = "HKCU:\Software\ForensicsTest\App1"
            Properties = @{
                "Version"     = "1.0.0"
                "InstallDate" = "2023-10-01"
                "LicenseKey"  = "ABC123"
            }
        },
        @{
            Path       = "HKCU:\Software\ForensicsTest\App2"
            Properties = @{
                "Version"     = "2.1.0"
                "InstallPath" = "C:\Program Files\App2"
                "AutoStart"   = "1"
            }
        }
    )
}

# Sample event log data
$script:SampleEventLogData = @{
    TestEvents = @(
        @{
            EventID      = 4624
            Level        = "Information"
            Message      = "An account was successfully logged on"
            TimeCreated  = Get-Date "2023-10-01 08:00:00"
            ProviderName = "Microsoft-Windows-Security-Auditing"
        },
        @{
            EventID      = 4625
            Level        = "Warning"
            Message      = "An account failed to log on"
            TimeCreated  = Get-Date "2023-10-01 08:05:00"
            ProviderName = "Microsoft-Windows-Security-Auditing"
        },
        @{
            EventID      = 4688
            Level        = "Information"
            Message      = "A new process has been created"
            TimeCreated  = Get-Date "2023-10-01 08:10:00"
            ProviderName = "Microsoft-Windows-Security-Auditing"
        }
    )
}

# Sample network data
$script:SampleNetworkData = @{
    TestConnections = @(
        @{
            LocalAddress  = "192.168.1.100"
            LocalPort     = 3389
            RemoteAddress = "192.168.1.200"
            RemotePort    = 54321
            State         = "ESTABLISHED"
            ProcessId     = 1234
            ProcessName   = "rdp.exe"
        },
        @{
            LocalAddress  = "192.168.1.100"
            LocalPort     = 80
            RemoteAddress = "0.0.0.0"
            RemotePort    = 0
            State         = "LISTENING"
            ProcessId     = 5678
            ProcessName   = "httpd.exe"
        }
    )
}

# Sample process data
$script:SampleProcessData = @{
    TestProcesses = @(
        @{
            Id        = 1234
            Name      = "notepad.exe"
            Path      = "C:\Windows\System32\notepad.exe"
            StartTime = Get-Date "2023-10-01 08:00:00"
            CPU       = 5.2
            Memory    = 25.6
            UserName  = "DOMAIN\User"
        },
        @{
            Id        = 5678
            Name      = "chrome.exe"
            Path      = "C:\Program Files\Google\Chrome\Application\chrome.exe"
            StartTime = Get-Date "2023-10-01 08:15:00"
            CPU       = 15.8
            Memory    = 150.2
            UserName  = "DOMAIN\User"
        }
    )
}

# Function to create sample test files on disk
function New-SampleTestFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BasePath = $TestDrive
    )

    foreach ($file in $script:SampleFileSystemData.TestFiles) {
        $filePath = Join-Path $BasePath $file.Name
        $file.Content | Out-File -FilePath $filePath -Encoding UTF8 -Force

        # Set file attributes if specified
        if ($file.ContainsKey('Attributes')) {
            Set-ItemProperty -Path $filePath -Name Attributes -Value $file.Attributes
        }

        # Set last write time
        Set-ItemProperty -Path $filePath -Name LastWriteTime -Value $file.LastWriteTime
    }

    foreach ($dir in $script:SampleFileSystemData.TestDirectories) {
        $dirPath = Join-Path $BasePath $dir.Name
        New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
        Set-ItemProperty -Path $dirPath -Name LastWriteTime -Value $dir.LastWriteTime
    }
}

# Function to create sample registry entries
function New-SampleRegistryData {
    [CmdletBinding()]
    param()

    foreach ($key in $script:SampleRegistryData.TestKeys) {
        if (-not (Test-Path $key.Path)) {
            New-Item -Path $key.Path -Force | Out-Null
        }

        foreach ($property in $key.Properties.GetEnumerator()) {
            New-ItemProperty -Path $key.Path -Name $property.Key -Value $property.Value -PropertyType String -Force | Out-Null
        }
    }
}

# Export sample data and functions
# Note: Export-ModuleMember removed since this file is dot-sourced, not imported as a module