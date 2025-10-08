# Event Log Functions

Event log analysis and security monitoring functions.

## Functions

### Get-EventLogsSummary

Provides summary of event counts by type.

```powershell
Get-EventLogsSummary -Hours 24
```

**Parameters:**

- `Hours`: Hours of logs to analyze

**Returns:**

- Log name, total events
- Events by level (Error, Warning, Information)

### Search-EventLogs

Searches event logs for specific keywords.

```powershell
Search-EventLogs -Keyword "failed" -LogName "Security"
```

**Parameters:**

- `Keyword`: Search term
- `LogName`: Event log name
- `Hours`: Hours to search back
- `Level`: Event level filter

**Returns:**

- Event ID, time, source, message
- User and computer information