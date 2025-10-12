# PerformanceFunctions.ps1
# Performance and scalability improvements for forensic analysis

<#
.SYNOPSIS
    Performance and Scalability Functions

.DESCRIPTION
    This module provides performance optimizations for forensic analysis including:
    - Parallel processing for large-scale operations
    - Memory-efficient data handling
    - Caching mechanisms for repeated operations
    - Resource monitoring and optimization
    - Batch processing capabilities

.NOTES
    Author: Forensic Analysis Team
    Version: 1.0.0
    Requires: PowerShell 7.0+ for parallel processing features
#>

# Performance monitoring and optimization variables
$script:PerformanceCache = @{}
$script:ResourceMonitor = @{
    StartTime = $null
    MemoryUsage = @()
    CpuUsage = @()
    DiskIO = @()
}

# Parallel Processing Functions

function Invoke-ParallelFileHashing {
    <#
    .SYNOPSIS
        Performs parallel file hashing for improved performance

    .DESCRIPTION
        Uses PowerShell's parallel processing to hash multiple files simultaneously,
        significantly improving performance for large file sets

    .PARAMETER Path
        Directory path to hash files from

    .PARAMETER Algorithm
        Hash algorithm (MD5, SHA1, SHA256, SHA384, SHA512)

    .PARAMETER MaxThreads
        Maximum number of parallel threads (default: number of CPU cores)

    .PARAMETER IncludeHidden
        Include hidden files in hashing

    .EXAMPLE
        Invoke-ParallelFileHashing -Path "C:\LargeDirectory" -Algorithm SHA256
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [string]$Algorithm = "SHA256",

        [Parameter(Mandatory = $false)]
        [int]$MaxThreads = $env:NUMBER_OF_PROCESSORS,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeHidden
    )

    try {
        Write-Host "Starting parallel file hashing with $MaxThreads threads..." -ForegroundColor Cyan

        # Get files to process
        $files = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue
        if (-not $IncludeHidden) {
            $files = $files | Where-Object { -not $_.Attributes.HasFlag([System.IO.FileAttributes]::Hidden) }
        }

        $totalFiles = $files.Count
        Write-Host "Found $totalFiles files to hash" -ForegroundColor Yellow

        # Process files in parallel
        $results = $files | ForEach-Object -ThrottleLimit $MaxThreads -Parallel {
            $file = $_
            $hashAlgorithm = $using:Algorithm

            try {
                $hash = Get-FileHash -Path $file.FullName -Algorithm $hashAlgorithm -ErrorAction Stop
                [PSCustomObject]@{
                    Path = $file.FullName
                    Name = $file.Name
                    Size = $file.Length
                    Algorithm = $hashAlgorithm
                    Hash = $hash.Hash
                    Status = "Success"
                }
            }
            catch {
                [PSCustomObject]@{
                    Path = $file.FullName
                    Name = $file.Name
                    Size = $file.Length
                    Algorithm = $hashAlgorithm
                    Hash = $null
                    Status = "Error: $($_.Exception.Message)"
                }
            }
        }

        Write-Host "Completed parallel hashing of $totalFiles files" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Error "Failed parallel file hashing: $_"
        return $null
    }
}

# Memory Optimization Functions

function Optimize-MemoryUsage {
    <#
    .SYNOPSIS
        Optimizes memory usage for large forensic operations

    .DESCRIPTION
        Implements memory optimization techniques including garbage collection,
        large object heap management, and memory-efficient data structures

    .PARAMETER Operation
        Operation to optimize (Collect, Compact, Monitor)

    .EXAMPLE
        Optimize-MemoryUsage -Operation Collect
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Collect", "Compact", "Monitor")]
        [string]$Operation
    )

    try {
        switch ($Operation) {
            "Collect" {
                Write-Host "Performing garbage collection..." -ForegroundColor Cyan
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
                Write-Host "Garbage collection completed" -ForegroundColor Green
            }
            "Compact" {
                Write-Host "Compacting large object heap..." -ForegroundColor Cyan
                if ([System.GC]::TryStartNoGCRegion(100MB)) {
                    try {
                        [System.GC]::Collect()
                    }
                    finally {
                        [System.GC]::EndNoGCRegion()
                    }
                }
                Write-Host "LOH compaction completed" -ForegroundColor Green
            }
            "Monitor" {
                $memoryInfo = Get-Process -Id $PID | Select-Object -Property *
                return [PSCustomObject]@{
                    ProcessId = $PID
                    WorkingSet = $memoryInfo.WorkingSet
                    PrivateMemorySize = $memoryInfo.PrivateMemorySize
                    VirtualMemorySize = $memoryInfo.VirtualMemorySize
                    GCTotalMemory = [System.GC]::GetTotalMemory($false)
                    Timestamp = Get-Date
                }
            }
        }
    }
    catch {
        Write-Error "Failed memory optimization: $_"
    }
}

# Caching and Performance Optimization

function New-PerformanceCache {
    <#
    .SYNOPSIS
        Creates a performance cache for repeated operations

    .DESCRIPTION
        Implements caching for expensive operations to improve performance
        on repeated forensic analysis tasks

    .PARAMETER CacheKey
        Unique key for cache entry

    .PARAMETER Operation
        Script block containing the operation to cache

    .PARAMETER ExpiryMinutes
        Cache expiry time in minutes

    .EXAMPLE
        New-PerformanceCache -CacheKey "SystemInfo" -Operation { Get-SystemInfo } -ExpiryMinutes 60
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CacheKey,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation,

        [Parameter(Mandatory = $false)]
        [int]$ExpiryMinutes = 30
    )

    try {
        # Check if cached result exists and is not expired
        if ($script:PerformanceCache.ContainsKey($CacheKey)) {
            $cachedItem = $script:PerformanceCache[$CacheKey]
            if ((Get-Date) - $cachedItem.Timestamp -lt [TimeSpan]::FromMinutes($ExpiryMinutes)) {
                Write-Host "Using cached result for $CacheKey" -ForegroundColor Yellow
                return $cachedItem.Data
            }
            else {
                # Remove expired cache entry
                $script:PerformanceCache.Remove($CacheKey)
            }
        }

        # Execute operation and cache result
        Write-Host "Executing and caching operation for $CacheKey" -ForegroundColor Cyan
        $result = & $Operation

        $script:PerformanceCache[$CacheKey] = @{
            Data = $result
            Timestamp = Get-Date
            ExpiryMinutes = $ExpiryMinutes
        }

        return $result
    }
    catch {
        Write-Error "Failed performance caching: $_"
        return $null
    }
}

function Clear-PerformanceCache {
    <#
    .SYNOPSIS
        Clears the performance cache

    .DESCRIPTION
        Removes all cached results to free memory or force fresh data

    .PARAMETER CacheKey
        Specific cache key to clear (optional)

    .EXAMPLE
        Clear-PerformanceCache
        Clear-PerformanceCache -CacheKey "SystemInfo"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$CacheKey
    )

    try {
        if ($CacheKey) {
            if ($script:PerformanceCache.ContainsKey($CacheKey)) {
                $script:PerformanceCache.Remove($CacheKey)
                Write-Host "Cleared cache entry: $CacheKey" -ForegroundColor Green
            }
            else {
                Write-Host "Cache key not found: $CacheKey" -ForegroundColor Yellow
            }
        }
        else {
            $script:PerformanceCache.Clear()
            Write-Host "Cleared all performance cache entries" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to clear performance cache: $_"
    }
}

# Resource Monitoring Functions

function Start-ResourceMonitoring {
    <#
    .SYNOPSIS
        Starts resource monitoring for forensic operations

    .DESCRIPTION
        Monitors system resources during forensic analysis to identify
        performance bottlenecks and optimization opportunities

    .EXAMPLE
        Start-ResourceMonitoring
    #>
    [CmdletBinding()]
    param()

    try {
        $script:ResourceMonitor.StartTime = Get-Date
        $script:ResourceMonitor.MemoryUsage = @()
        $script:ResourceMonitor.CpuUsage = @()
        $script:ResourceMonitor.DiskIO = @()

        Write-Host "Started resource monitoring" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to start resource monitoring: $_"
    }
}

function Get-ResourceMonitoringData {
    <#
    .SYNOPSIS
        Gets current resource monitoring data

    .DESCRIPTION
        Retrieves current system resource usage data for analysis

    .EXAMPLE
        Get-ResourceMonitoringData
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not $script:ResourceMonitor.StartTime) {
            throw "Resource monitoring not started"
        }

        $process = Get-Process -Id $PID
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
        $disk = Get-Counter '\PhysicalDisk(_Total)\% Disk Time' -ErrorAction SilentlyContinue

        $data = [PSCustomObject]@{
            Timestamp = Get-Date
            ElapsedTime = (Get-Date) - $script:ResourceMonitor.StartTime
            MemoryUsageMB = [math]::Round($process.WorkingSet / 1MB, 2)
            CpuUsagePercent = if ($cpu) { [math]::Round($cpu.CounterSamples[0].CookedValue, 2) } else { 0 }
            DiskUsagePercent = if ($disk) { [math]::Round($disk.CounterSamples[0].CookedValue, 2) } else { 0 }
            ThreadCount = $process.Threads.Count
            HandleCount = $process.HandleCount
        }

        # Store in monitoring arrays
        $script:ResourceMonitor.MemoryUsage += $data.MemoryUsageMB
        $script:ResourceMonitor.CpuUsage += $data.CpuUsagePercent
        $script:ResourceMonitor.DiskIO += $data.DiskUsagePercent

        return $data
    }
    catch {
        Write-Error "Failed to get resource monitoring data: $_"
        return $null
    }
}

function Stop-ResourceMonitoring {
    <#
    .SYNOPSIS
        Stops resource monitoring and returns summary

    .DESCRIPTION
        Stops monitoring and provides performance summary statistics

    .EXAMPLE
        Stop-ResourceMonitoring
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not $script:ResourceMonitor.StartTime) {
            throw "Resource monitoring not started"
        }

        $endTime = Get-Date
        $duration = $endTime - $script:ResourceMonitor.StartTime

        $summary = [PSCustomObject]@{
            TotalDuration = $duration
            AverageMemoryMB = [math]::Round(($script:ResourceMonitor.MemoryUsage | Measure-Object -Average).Average, 2)
            PeakMemoryMB = [math]::Round(($script:ResourceMonitor.MemoryUsage | Measure-Object -Maximum).Maximum, 2)
            AverageCpuPercent = [math]::Round(($script:ResourceMonitor.CpuUsage | Measure-Object -Average).Average, 2)
            PeakCpuPercent = [math]::Round(($script:ResourceMonitor.CpuUsage | Measure-Object -Maximum).Maximum, 2)
            AverageDiskPercent = [math]::Round(($script:ResourceMonitor.DiskIO | Measure-Object -Average).Average, 2)
            DataPoints = $script:ResourceMonitor.MemoryUsage.Count
        }

        # Reset monitoring
        $script:ResourceMonitor.StartTime = $null
        $script:ResourceMonitor.MemoryUsage = @()
        $script:ResourceMonitor.CpuUsage = @()
        $script:ResourceMonitor.DiskIO = @()

        Write-Host "Resource monitoring stopped. Duration: $($duration.TotalMinutes.ToString('F1')) minutes" -ForegroundColor Green
        return $summary
    }
    catch {
        Write-Error "Failed to stop resource monitoring: $_"
        return $null
    }
}