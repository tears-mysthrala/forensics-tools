# Registry Functions

Registry forensics and persistence analysis functions.

## Functions

### Get-RegistryKeys

Retrieves registry key values.

```powershell
Get-RegistryKeys -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Parameters:**

- `Path`: Registry path to enumerate
- `Recursive`: Include subkeys
- `IncludeValues`: Include key values

**Returns:**

- Key path, name, type, value
- Last modified time