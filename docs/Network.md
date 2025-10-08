# Network Functions

Network analysis and connection monitoring functions.

## Functions

### Get-NetworkConnections

Lists active network connections with process information.

```powershell
Get-NetworkConnections
Get-NetworkConnections -Protocol TCP
```

**Parameters:**

- `Protocol`: Filter by protocol (TCP, UDP)

**Returns:**

- Local/remote addresses and ports
- Process name and ID
- Connection state and protocol

### Get-NetworkShares

Lists network shares and their configuration.

```powershell
Get-NetworkShares
```

**Returns:**

- Share name, path, description
- Permissions and access control

### Get-USBDeviceHistory

Shows USB device connection history.

```powershell
Get-USBDeviceHistory
```

**Returns:**

- Device name, serial number, vendor ID
- First/last connection times
- Device class and type