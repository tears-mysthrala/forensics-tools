# FileSignatureFunctions.ps1 - File signature analysis and validation

function Get-FileSignatures {
    <#
    .SYNOPSIS
        Analyzes file signatures and headers for forensic insights.
    .DESCRIPTION
        Examines file headers, magic bytes, and signatures to identify file types and potential tampering.
    .PARAMETER Path
        Directory or file path to analyze.
    .PARAMETER OutputPath
        Directory to save signature analysis results.
    .EXAMPLE
        Get-FileSignatures -Path C:\Windows\System32 -OutputPath C:\Analysis
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$OutputPath = "."
    )

    Write-Host "Analyzing file signatures..." -ForegroundColor Cyan

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $analysisDir = Join-Path $OutputPath "FileSignatures_$timestamp"

    if (-not (Test-Path $analysisDir)) {
        New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    }

    # Common file signatures (magic bytes)
    $fileSignatures = @{
        "FFD8FF" = "JPEG Image"
        "89504E47" = "PNG Image"
        "47494638" = "GIF Image"
        "424D" = "BMP Image"
        "4D5A" = "Windows Executable (PE)"
        "7F454C46" = "ELF Executable"
        "504B0304" = "ZIP Archive"
        "52617221" = "RAR Archive"
        "377ABCAF271C" = "7-Zip Archive"
        "255044462D" = "PDF Document"
        "D0CF11E0A1B11AE1" = "Microsoft Office Document"
        "000001BA" = "MPEG Video"
        "000001B3" = "MPEG Video"
        "464C5601" = "FLV Video"
        "1F8B08" = "GZIP Archive"
        "425A68" = "BZIP2 Archive"
    }

    $signatureAnalysis = @{
        Timestamp = Get-Date
        Path = $Path
        Signatures = @{}
    }

    Write-Host "Scanning files for signatures..." -ForegroundColor Yellow

    try {
        $files = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1000  # Limit for performance

        $results = @()
        foreach ($file in $files) {
            try {
                # Read first 16 bytes for signature analysis
                $bytes = [System.IO.File]::ReadAllBytes($file.FullName)[0..15]
                $hexSignature = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""

                # Check against known signatures
                $identifiedType = "Unknown"
                foreach ($sig in $fileSignatures.Keys) {
                    if ($hexSignature.StartsWith($sig)) {
                        $identifiedType = $fileSignatures[$sig]
                        break
                    }
                }

                # Check for extension mismatch
                $extension = $file.Extension.ToLower()
                $expectedExtension = switch ($identifiedType) {
                    "JPEG Image" { ".jpg"; ".jpeg" }
                    "PNG Image" { ".png" }
                    "GIF Image" { ".gif" }
                    "BMP Image" { ".bmp" }
                    "Windows Executable (PE)" { ".exe"; ".dll"; ".sys" }
                    "ELF Executable" { ".elf" }
                    "ZIP Archive" { ".zip" }
                    "RAR Archive" { ".rar" }
                    "7-Zip Archive" { ".7z" }
                    "PDF Document" { ".pdf" }
                    "Microsoft Office Document" { ".doc"; ".xls"; ".ppt" }
                    "MPEG Video" { ".mpg"; ".mpeg" }
                    "FLV Video" { ".flv" }
                    "GZIP Archive" { ".gz" }
                    "BZIP2 Archive" { ".bz2" }
                    default { $null }
                }

                $extensionMismatch = $false
                if ($expectedExtension -and $expectedExtension -notcontains $extension) {
                    $extensionMismatch = $true
                }

                $results += [PSCustomObject]@{
                    FileName = $file.Name
                    FullPath = $file.FullName
                    Size = $file.Length
                    Extension = $extension
                    IdentifiedType = $identifiedType
                    HexSignature = $hexSignature
                    ExtensionMismatch = $extensionMismatch
                    LastWriteTime = $file.LastWriteTime
                }

            } catch {
                Write-Warning "Failed to analyze $($file.FullName): $($_.Exception.Message)"
            }
        }

        # Export results
        $results | Export-Csv (Join-Path $analysisDir "file_signatures.csv") -NoTypeInformation

        # Analyze mismatches
        $mismatches = $results | Where-Object { $_.ExtensionMismatch }
        if ($mismatches) {
            $mismatches | Export-Csv (Join-Path $analysisDir "extension_mismatches.csv") -NoTypeInformation
            $signatureAnalysis.Signatures.ExtensionMismatches = $mismatches.Count
            Write-Host "⚠ Found $($mismatches.Count) files with extension mismatches" -ForegroundColor Red
        } else {
            $signatureAnalysis.Signatures.ExtensionMismatches = 0
            Write-Host "[OK] No extension mismatches found" -ForegroundColor Green
        }

        # Analyze by type
        $typeSummary = $results | Group-Object IdentifiedType | Sort-Object Count -Descending
        $typeSummary | Export-Csv (Join-Path $analysisDir "file_types_summary.csv") -NoTypeInformation

        $signatureAnalysis.Signatures.TotalFiles = $results.Count
        $signatureAnalysis.Signatures.FileTypes = $typeSummary

        Write-Host "[OK] Analyzed $($results.Count) files" -ForegroundColor Green

    } catch {
        Write-Warning "Failed to analyze file signatures: $($_.Exception.Message)"
        $signatureAnalysis.Signatures.Error = $_.Exception.Message
    }

    # Save analysis summary
    $summaryFile = Join-Path $analysisDir "file_signature_analysis.json"
    $signatureAnalysis | ConvertTo-Json -Depth 3 | Out-File $summaryFile

    Write-Host "File signature analysis complete!" -ForegroundColor Green
    Write-Host "Results saved to: $analysisDir" -ForegroundColor Cyan

    return $analysisDir
}