function Disable-FullPSReadLine {
    try {
        $minimalOptions = @{
            PredictionSource              = 'None'
            HistorySearchCursorMovesToEnd = $true
        }
        Set-PSReadLineOption @minimalOptions
        # Minimal key handlers
        Set-PSReadLineKeyHandler -Key Tab -Function Complete
    }
    catch {
        Write-Warning "Disabling full PSReadLine options failed: $_"
    }
}