# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Windows Parental Controls - SRP & Monitoring Project

## Project Overview

This project implements **Software Restriction Policies (SRP)** on Windows Home edition (without Group Policy Editor) to prevent children from bypassing parental controls by:
- Installing applications to user-writable locations (AppData, Downloads, etc.)
- Renaming executables to evade name-based blocking
- Running portable applications from USB drives

The solution uses registry-based SAFER configuration combined with PowerShell monitoring scripts.

## Key Files

| File | Purpose |
|------|---------|
| `ParentalControl.ps1` | **Main launcher** - interactive menu with wizards |
| `Enable-SRP-Complete.ps1` | Core script - blocks ALL user-writable execution paths |
| `Rollback-SRP.ps1` | Completely removes SRP configuration |
| `Add-GameWhitelist.ps1` | Easy game/app whitelisting with presets (Minecraft, Roblox, Steam, etc.) |
| `ExeMonitor.ps1` | Baseline-based monitoring for unauthorized executables |
| `RealtimeMonitor.ps1` | FileSystemWatcher-based live monitoring (planned) |

## Technical Context

### How SRP/SAFER Works
- SAFER is a Windows subsystem (since XP) that controls executable permissions
- Registry path: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers`
- Security levels: `0` = Disallowed, `262144` = Unrestricted
- `PolicyScope = 1` means rules apply to non-admins only

### Critical Constraints
1. **Path rule limit**: 133 characters max (longer paths silently ignored)
2. **Windows 11 22H2+ bug**: Must set `HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp\RuleCount = 0`
3. **Depth coverage**: Rules need explicit wildcards at each depth level (`*`, `*\*`, `*\*\*`)
4. **Safe Mode**: Bypasses all SAFER rules (acts as recovery option)

### User-Writable Paths to Block
All of these must be blocked for complete coverage:
- `%APPDATA%` - AppData\Roaming
- `%LOCALAPPDATA%` - AppData\Local (where Chrome installs!)
- `%USERPROFILE%\AppData\LocalLow` - Often missed
- `%USERPROFILE%\Downloads`, `Desktop`, `Documents`, `Music`, `Pictures`, `Videos`
- `%TEMP%`, `%TMP%` - Temp folders
- `C:\Users\Public\*` - Writable by all users
- `%OneDrive%` - Synced folders
- Removable drives `D:` through `K:`

### Common Apps Needing Whitelist
Some legitimate apps install to AppData:
- Microsoft OneDrive: `%LOCALAPPDATA%\Microsoft\OneDrive\`
- Microsoft Teams: `%LOCALAPPDATA%\Microsoft\Teams\`
- Discord: `%LOCALAPPDATA%\Discord\`
- Spotify: `%APPDATA%\Spotify\`
- VS Code (user): `%LOCALAPPDATA%\Programs\Microsoft VS Code\`

## Development Guidelines

### When Modifying Enable-SRP-Complete.ps1
1. Always test with `-WhatIf` first
2. Remember the 133-character path limit
3. New blocked paths need multiple depth rules
4. Test from a Standard User account, not admin
5. Check `C:\ParentalControl\Logs\SAFER.log` for blocked attempts

### When Adding New Whitelist Entries

**For games and apps (preferred method):**
```powershell
# Use presets for common games/apps
.\Add-GameWhitelist.ps1 -Preset Minecraft
.\Add-GameWhitelist.ps1 -Preset Spotify

# Batch options
.\Add-GameWhitelist.ps1 -Preset AllGames   # All game presets
.\Add-GameWhitelist.ps1 -Preset AllApps    # All app presets
.\Add-GameWhitelist.ps1 -Preset All        # Everything

# Custom folder (auto-adds depth wildcards)
.\Add-GameWhitelist.ps1 -CustomPath "D:\Games\MyGame"

# View current whitelist
.\Add-GameWhitelist.ps1 -List
```

**Game presets:** Minecraft, Roblox, Steam, Epic, Discord, Overwolf, CurseForge

**App presets:** Spotify, Zoom, WhatsApp, Telegram, VSCode, GitHubDesktop, Slack, Signal

**For other apps (manual method):**
```powershell
Add-AllowRule -Path "%LOCALAPPDATA%\AppName\*" -Note "Description"
```

### Monitoring Whitelisted Folders

Since whitelisting a folder allows any executable in it to run, use ExeMonitor.ps1 to detect when new executables appear:

```powershell
# First, record current trusted executables as baseline
.\ExeMonitor.ps1 -UpdateBaseline

# Later, scan for new/unknown executables
.\ExeMonitor.ps1 -Scan

# Scan and quarantine suspicious files
.\ExeMonitor.ps1 -Scan -Quarantine

# View current baseline
.\ExeMonitor.ps1 -ShowBaseline
```

**Scheduled scanning:** Use the interactive menu (option 6 > Setup Scheduled Scan) to create a Windows scheduled task that runs as SYSTEM and cannot be disabled by Standard Users.

### Testing Checklist
- [ ] Verify child account is Standard User (not Admin)
- [ ] Run `gpupdate /force` after changes
- [ ] Restart computer for full enforcement
- [ ] Test blocked paths from child's account
- [ ] Verify admin account is unaffected
- [ ] Check SAFER.log for any issues

## Common Issues & Solutions

### "Rules aren't working"
1. Check Windows version - if 22H2+, ensure Srp\Gp fix is applied
2. Verify `PolicyScope = 1` is set
3. Run `gpupdate /force` and restart
4. Check if path exceeds 133 characters

### "Legitimate app blocked"
Add whitelist entry with full path including trailing `\*`

### "Child disabled the monitoring"
Ensure tasks run as `NT AUTHORITY\SYSTEM` - standard users cannot modify these

### "Need to temporarily allow something"
Option 1: Add specific whitelist entry
Option 2: Run rollback, install, then re-enable SRP
Option 3: Install as admin to Program Files instead

## PowerShell Commands Reference

```powershell
# View current BLOCK rules
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths" |
    ForEach-Object { Get-ItemProperty $_.PSPath }

# View current ALLOW rules (whitelist)
.\Add-GameWhitelist.ps1 -List

# Check if SRP is active
(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers").DefaultLevel

# View blocked attempts
Get-Content "C:\ParentalControl\Logs\SAFER.log" | Select-Object -Last 50

# Check monitoring tasks
Get-ScheduledTask | Where-Object {$_.TaskName -like "*ParentalControl*"}

# Whitelist a game or app
.\Add-GameWhitelist.ps1 -Preset Minecraft
.\Add-GameWhitelist.ps1 -Preset Spotify

# Whitelist all games or all apps
.\Add-GameWhitelist.ps1 -Preset AllGames
.\Add-GameWhitelist.ps1 -Preset AllApps

# Remove a whitelist
.\Add-GameWhitelist.ps1 -Preset Minecraft -Remove

# Monitoring commands
.\ExeMonitor.ps1 -UpdateBaseline        # Record current state as trusted
.\ExeMonitor.ps1 -Scan                   # Check for new executables
.\ExeMonitor.ps1 -Scan -Quarantine       # Scan and move suspicious files
.\ExeMonitor.ps1 -ShowBaseline           # View known executables

# View monitoring logs
Get-Content "C:\ParentalControl\Logs\ExeMonitor.log" | Select-Object -Last 30
```

## Project Structure

```
Repository (development):
├── ParentalControl.ps1          # Interactive menu launcher (start here!)
├── Enable-SRP-Complete.ps1      # Core SRP configuration
├── Rollback-SRP.ps1             # Remove all SRP settings
├── Add-GameWhitelist.ps1        # Game/app whitelisting helper
├── ExeMonitor.ps1               # Baseline-based executable monitoring
└── CLAUDE.md                    # This file

Deployed (C:\ParentalControl\):
├── Scripts\
│   ├── ParentalControl.ps1      # Run this for interactive menu
│   ├── Enable-SRP-Complete.ps1
│   ├── Rollback-SRP.ps1
│   ├── Add-GameWhitelist.ps1
│   ├── ExeMonitor.ps1           # Detects new executables in whitelisted folders
│   └── RealtimeMonitor.ps1      # (planned)
├── Logs\
│   ├── SAFER.log                # Blocked execution attempts
│   └── ExeMonitor.log           # Monitoring alerts
├── Data\
│   └── baseline.csv             # Known/trusted executables
└── Quarantine\                  # Quarantined suspicious files
```

## Quick Start

```powershell
# Run as Administrator
.\ParentalControl.ps1
```

This opens an interactive menu with options to:
1. Enable/disable protection with guided wizards
2. Whitelist games (multi-select presets or custom paths)
3. View protection status and blocked attempts
4. Monitor whitelisted folders for unauthorized executables

## Security Model

```
┌─────────────────────────────────────────────────────────────┐
│                    ADMIN ACCOUNT (Parent)                   │
│  • Can run anything from anywhere                           │
│  • Can modify SRP rules                                     │
│  • Can view monitoring logs                                 │
│  • Can whitelist new applications                           │
└─────────────────────────────────────────────────────────────┘
                              │
                    PolicyScope = 1
                    (Rules apply only to non-admins)
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│               STANDARD USER ACCOUNT (Child)                 │
│  • Can run apps from C:\Windows, C:\Program Files           │
│  • BLOCKED from running apps in user folders                │
│  • Cannot modify SRP rules                                  │
│  • Cannot disable monitoring tasks                          │
└─────────────────────────────────────────────────────────────┘
```

## Future Improvements to Consider

- [ ] Hash-based rules for specific blocked executables
- [ ] Certificate-based rules for publisher blocking
- [ ] Integration with Windows Defender Application Control
- [ ] Email/SMS alerts for blocked attempts
- [ ] Web-based dashboard for log viewing
- [ ] Automatic Chrome/Firefox update detection and blocking
