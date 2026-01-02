# Windows Parental Controls (SRP)

Block unauthorized applications on Windows Home edition using Software Restriction Policies (SAFER).

## Why?

Windows Home doesn't include Group Policy Editor or AppLocker. Kids can bypass parental controls by:
- Installing apps to AppData, Downloads, or Desktop
- Running portable executables from USB drives
- Renaming blocked executables

This solution blocks **all** executables in user-writable locations for Standard User accounts, while leaving Administrator accounts unaffected.

## Quick Start

```powershell
# Run as Administrator
.\ParentalControl.ps1
```

This opens an interactive menu:
```
[1] Enable Protection      - Block unauthorized apps (wizard)
[2] Disable Protection     - Remove all restrictions (wizard)
[3] Manage Whitelist       - Allow games & apps
[4] View Status            - Detailed protection status
[5] View Blocked Attempts  - See what's been blocked
[6] Monitoring             - Detect unauthorized executables
[7] Exit
```

## Requirements

- Windows 10/11 (any edition, including Home)
- PowerShell 5.1+
- Administrator account (for setup)
- Child account must be a **Standard User** (not Administrator)

## How It Works

Uses the Windows SAFER subsystem (Software Restriction Policies) via registry:
- `PolicyScope = 1` ensures rules apply to **non-admins only**
- Blocks executables in: AppData, Downloads, Desktop, Documents, Temp, USB drives, etc.
- Logs allowed executables to `C:\ParentalControl\Logs\SAFER.log` (blocked events are logged to Windows Event Viewer by default)

## Files

| File | Purpose |
|------|---------|
| `ParentalControl.ps1` | Interactive menu launcher |
| `Enable-SRP-Complete.ps1` | Applies all blocking rules |
| `Rollback-SRP.ps1` | Removes all restrictions |
| `Add-GameWhitelist.ps1` | Whitelist games & apps |
| `ExeMonitor.ps1` | Detect unauthorized executables in whitelisted folders |

## Whitelisting Games & Apps

```powershell
# Interactive (via menu)
.\ParentalControl.ps1  # Then select option 3

# Command line
.\Add-GameWhitelist.ps1 -Preset Minecraft
.\Add-GameWhitelist.ps1 -Preset Spotify
.\Add-GameWhitelist.ps1 -Preset AllGames
.\Add-GameWhitelist.ps1 -CustomPath "D:\Games\MyGame"
```

### Available Presets

**Games:** Minecraft, Roblox, Steam, Epic, Discord, Overwolf, CurseForge

**Apps:** Spotify, Zoom, WhatsApp, Telegram, VSCode, GitHubDesktop, Slack, Signal

## What Gets Blocked

For Standard Users (child accounts):

| Location | Examples |
|----------|----------|
| `%APPDATA%` | Discord, Spotify, Telegram |
| `%LOCALAPPDATA%` | Chrome, VS Code, Roblox |
| `%USERPROFILE%\Downloads` | Downloaded installers |
| `%USERPROFILE%\Desktop` | Portable apps |
| `%TEMP%` | Temp executables |
| `C:\Users\Public` | Shared folder exploits |
| USB Drives (D: - K:) | Portable apps from USB |

## Recovery

If something goes wrong:

1. **Boot into Safe Mode** - SAFER rules are bypassed
2. Run `.\Rollback-SRP.ps1` to remove all restrictions
3. Or restore from the automatic backup in `%TEMP%\SAFER_backup_*.reg`

## Limitations

- Only blocks executables (.exe, .msi, .bat, etc.) - not web browsing
- Requires restart for full enforcement after enabling
- 133-character path limit for rules (handled automatically)
- Safe Mode bypasses all restrictions (by design, for recovery)

## License

MIT
