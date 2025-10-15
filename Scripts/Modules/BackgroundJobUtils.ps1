function Start-BackgroundJob {
    param(
        [scriptblock]$ScriptBlock,
        [Parameter(ValueFromRemainingArguments = $true)] $ArgumentList
    )
    try {
        if (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue) {
            return Start-ThreadJob -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        }
    }
    catch {
        # fall back
    }
    return Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}