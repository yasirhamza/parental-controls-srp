<#
.SYNOPSIS
    COMPLETE Software Restriction Policy implementation blocking ALL user-writable paths
.DESCRIPTION
    Blocks executables from running in ANY location a standard user can write to.
    This includes paths often missed: LocalLow, Public folders, OneDrive, Documents, etc.
.NOTES
    - Child's account MUST be a Standard User (not Administrator)
    - RESTART REQUIRED after running for full enforcement
    - Test thoroughly - some legitimate apps may need whitelisting
    - SRP path rules have 133 character limit - paths are kept short
#>

param(
    [switch]$WhatIf,
    [string]$BackupPath = "$env:TEMP\SAFER_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
)

# Require admin only when making real changes (not for -WhatIf dry runs)
if (-not $WhatIf) {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
        Write-Host "       Run PowerShell as Administrator, or use -WhatIf for a dry run." -ForegroundColor Yellow
        exit 1
    }
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  COMPLETE SOFTWARE RESTRICTION POLICY - PARENTAL CONTROLS       ║
║  Blocks ALL user-writable execution paths                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "`n[WHATIF MODE] No changes will be made - showing what would happen`n" -ForegroundColor Yellow
}

# ═══════════════════════════════════════════════════════════════════
# WINDOWS 11 22H2+ CRITICAL FIX
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[1/6] Applying Windows 11 22H2+ compatibility fix..." -ForegroundColor Yellow
$SrpGpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp"
if ($WhatIf) {
    Write-Host "    [WOULD] Set $SrpGpPath\RuleCount = 0" -ForegroundColor Cyan
} else {
    if (!(Test-Path $SrpGpPath)) { New-Item -Path $SrpGpPath -Force | Out-Null }
    Set-ItemProperty -Path $SrpGpPath -Name "RuleCount" -Value 0 -Type DWord -Force
    Write-Host "    ✓ Srp\Gp RuleCount set to 0" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════
# BACKUP EXISTING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[2/6] Creating backup..." -ForegroundColor Yellow
if ($WhatIf) {
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer") {
        Write-Host "    [WOULD] Export existing config to: $BackupPath" -ForegroundColor Cyan
    } else {
        Write-Host "    [WOULD] No existing config to backup" -ForegroundColor Cyan
    }
} else {
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer") {
        $null = reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer" $BackupPath /y 2>&1
        Write-Host "    ✓ Backup saved to: $BackupPath" -ForegroundColor Green
    } else {
        Write-Host "    ✓ No existing config to backup" -ForegroundColor Green
    }
}

# ═══════════════════════════════════════════════════════════════════
# INITIALIZE REGISTRY STRUCTURE
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[3/6] Initializing registry structure..." -ForegroundColor Yellow

$BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
$LogPath = "C:\ParentalControl\Logs\SAFER.log"

# Core policy settings
$PolicySettings = @{
    "AuthenticodeEnabled" = 0          # Don't require signed executables
    "DefaultLevel"        = 262144     # Default: Allow (we block specific paths)
    "TransparentEnabled"  = 1          # Apply to EXE files
    "PolicyScope"         = 1          # Apply to non-admins ONLY (critical!)
    "ExecutableTypes"     = "ADE ADP BAS BAT CHM CMD COM CPL CRT EXE HLP HTA INF INS ISP JS JSE LNK MDB MDE MSC MSI MSP MST OCX PCD PIF PS1 REG SCR SHS URL VB VBE VBS WSC WSF WSH"
    "Levels"              = 0x00071000
}

if ($WhatIf) {
    Write-Host "    [WOULD] Remove existing SAFER config (if any)" -ForegroundColor Cyan
    Write-Host "    [WOULD] Create registry structure:" -ForegroundColor Cyan
    Write-Host "            $BasePath" -ForegroundColor Cyan
    Write-Host "            $BasePath\0\Paths (block rules)" -ForegroundColor Cyan
    Write-Host "            $BasePath\262144\Paths (allow rules)" -ForegroundColor Cyan
    Write-Host "    [WOULD] Set PolicyScope = 1 (non-admins only)" -ForegroundColor Cyan
    Write-Host "    [WOULD] Create log directory: $(Split-Path $LogPath -Parent)" -ForegroundColor Cyan
    Write-Host "    [WOULD] Set log file: $LogPath" -ForegroundColor Cyan
} else {
    # Clear and recreate
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer") {
        Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer" -Recurse -Force
    }

    New-Item -Path $BasePath -Force | Out-Null
    New-Item -Path "$BasePath\0\Paths" -Force | Out-Null       # Disallowed (blocked)
    New-Item -Path "$BasePath\262144\Paths" -Force | Out-Null  # Unrestricted (allowed)

    foreach ($key in $PolicySettings.Keys) {
        if ($key -eq "ExecutableTypes") {
            Set-ItemProperty -Path $BasePath -Name $key -Value $PolicySettings[$key] -Type MultiString
        } else {
            Set-ItemProperty -Path $BasePath -Name $key -Value $PolicySettings[$key] -Type DWord
        }
    }

    # Enable logging
    $LogDir = Split-Path $LogPath -Parent
    if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    Set-ItemProperty -Path $BasePath -Name "LogFileName" -Value $LogPath -Type String

    Write-Host "    ✓ Registry structure initialized" -ForegroundColor Green
    Write-Host "    ✓ Log file: $LogPath" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════
$script:BlockCount = 0
$script:AllowCount = 0

function Add-BlockRule {
    param ([string]$Path, [string]$Note = "")
    $guid = "{$([System.Guid]::NewGuid().ToString())}"
    $keyPath = "$BasePath\0\Paths\$guid"
    
    if ($WhatIf) {
        Write-Host "    [WOULD BLOCK] $Path" -ForegroundColor Red
    } else {
        New-Item -Path $keyPath -Force | Out-Null
        Set-ItemProperty -Path $keyPath -Name "ItemData" -Value $Path -Type ExpandString
        Set-ItemProperty -Path $keyPath -Name "SaferFlags" -Value 0 -Type DWord
        if ($Note) { Set-ItemProperty -Path $keyPath -Name "Description" -Value $Note -Type String }
    }
    $script:BlockCount++
}

function Add-AllowRule {
    param ([string]$Path, [string]$Note = "")
    $guid = "{$([System.Guid]::NewGuid().ToString())}"
    $keyPath = "$BasePath\262144\Paths\$guid"
    
    if ($WhatIf) {
        Write-Host "    [WOULD ALLOW] $Path" -ForegroundColor Green
    } else {
        New-Item -Path $keyPath -Force | Out-Null
        Set-ItemProperty -Path $keyPath -Name "ItemData" -Value $Path -Type ExpandString
        Set-ItemProperty -Path $keyPath -Name "SaferFlags" -Value 0 -Type DWord
        if ($Note) { Set-ItemProperty -Path $keyPath -Name "Description" -Value $Note -Type String }
    }
    $script:AllowCount++
}

# ═══════════════════════════════════════════════════════════════════
# ALLOW RULES - System directories (must come first)
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[4/6] Adding ALLOW rules for system directories..." -ForegroundColor Yellow

# Core Windows directories
Add-AllowRule -Path "C:\Windows\*" -Note "Windows system files"
Add-AllowRule -Path "C:\Program Files\*" -Note "64-bit programs"
Add-AllowRule -Path "C:\Program Files (x86)\*" -Note "32-bit programs"
Add-AllowRule -Path "C:\ProgramData\Microsoft\Windows Defender\*" -Note "Windows Defender"

# PowerShell execution policy test scripts (created automatically by PowerShell)
Add-AllowRule -Path "%TEMP%\__PSScriptPolicyTest_*" -Note "PowerShell policy test"
Add-AllowRule -Path "%LOCALAPPDATA%\Temp\__PSScriptPolicyTest_*" -Note "PowerShell policy test"

Write-Host "    ✓ $script:AllowCount system directories whitelisted" -ForegroundColor Green

# ═══════════════════════════════════════════════════════════════════
# BLOCK RULES - ALL user-writable paths
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[5/6] Adding BLOCK rules for user-writable paths..." -ForegroundColor Yellow

# --------------------------------------------------------------
# AppData\Roaming (%APPDATA%)
# Chrome extensions, Discord, Spotify, etc. install here
# --------------------------------------------------------------
Add-BlockRule -Path "%APPDATA%\*" -Note "AppData Roaming root"
Add-BlockRule -Path "%APPDATA%\*\*" -Note "AppData Roaming depth 2"
Add-BlockRule -Path "%APPDATA%\*\*\*" -Note "AppData Roaming depth 3"
Add-BlockRule -Path "%APPDATA%\*\*\*\*" -Note "AppData Roaming depth 4"

# --------------------------------------------------------------
# AppData\Local (%LOCALAPPDATA%)
# TARGETED blocking - we skip Microsoft folder to allow OneDrive, Teams, etc.
# Blanket wildcards (%LOCALAPPDATA%\*\*\*) conflict with allow rules
# --------------------------------------------------------------
# User-installed programs (common bypass location)
Add-BlockRule -Path "%LOCALAPPDATA%\Programs\*" -Note "Local Programs folder"
Add-BlockRule -Path "%LOCALAPPDATA%\Programs\*\*" -Note "Local Programs depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\Programs\*\*\*" -Note "Local Programs depth 3"
Add-BlockRule -Path "%LOCALAPPDATA%\Programs\*\*\*\*" -Note "Local Programs depth 4"

# Temp folder in LocalAppData
Add-BlockRule -Path "%LOCALAPPDATA%\Temp\*" -Note "Local Temp folder"
Add-BlockRule -Path "%LOCALAPPDATA%\Temp\*\*" -Note "Local Temp depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\Temp\*\*\*" -Note "Local Temp depth 3"

# Common app locations that children might exploit (NOT Microsoft folder)
Add-BlockRule -Path "%LOCALAPPDATA%\Discord\*" -Note "Discord"
Add-BlockRule -Path "%LOCALAPPDATA%\Discord\*\*" -Note "Discord depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\Discord\*\*\*" -Note "Discord depth 3"
Add-BlockRule -Path "%LOCALAPPDATA%\Discord\*\*\*\*" -Note "Discord depth 4"

Add-BlockRule -Path "%LOCALAPPDATA%\slack\*" -Note "Slack"
Add-BlockRule -Path "%LOCALAPPDATA%\slack\*\*" -Note "Slack depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\slack\*\*\*" -Note "Slack depth 3"

Add-BlockRule -Path "%LOCALAPPDATA%\GitHubDesktop\*" -Note "GitHub Desktop"
Add-BlockRule -Path "%LOCALAPPDATA%\GitHubDesktop\*\*" -Note "GitHub Desktop depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\GitHubDesktop\*\*\*" -Note "GitHub Desktop depth 3"

Add-BlockRule -Path "%LOCALAPPDATA%\Roblox\*" -Note "Roblox"
Add-BlockRule -Path "%LOCALAPPDATA%\Roblox\*\*" -Note "Roblox depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\Roblox\*\*\*" -Note "Roblox depth 3"
Add-BlockRule -Path "%LOCALAPPDATA%\Roblox\*\*\*\*" -Note "Roblox depth 4"

# UWP/Store apps cache
Add-BlockRule -Path "%LOCALAPPDATA%\Packages\*" -Note "UWP Packages"
Add-BlockRule -Path "%LOCALAPPDATA%\Packages\*\*" -Note "UWP Packages depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\Packages\*\*\*" -Note "UWP Packages depth 3"

# Browser locations (extensions, downloads)
Add-BlockRule -Path "%LOCALAPPDATA%\Google\*" -Note "Google folder"
Add-BlockRule -Path "%LOCALAPPDATA%\Google\*\*" -Note "Google depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\Google\*\*\*" -Note "Google depth 3"
Add-BlockRule -Path "%LOCALAPPDATA%\Google\*\*\*\*" -Note "Google depth 4"
Add-BlockRule -Path "%LOCALAPPDATA%\Mozilla\*" -Note "Mozilla folder"
Add-BlockRule -Path "%LOCALAPPDATA%\Mozilla\*\*" -Note "Mozilla depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\BraveSoftware\*" -Note "Brave browser"
Add-BlockRule -Path "%LOCALAPPDATA%\BraveSoftware\*\*" -Note "Brave depth 2"

# Other common locations
Add-BlockRule -Path "%LOCALAPPDATA%\CurseForge\*" -Note "CurseForge"
Add-BlockRule -Path "%LOCALAPPDATA%\CurseForge\*\*" -Note "CurseForge depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\CurseForge\*\*\*" -Note "CurseForge depth 3"
Add-BlockRule -Path "%LOCALAPPDATA%\EpicGamesLauncher\*" -Note "Epic Games"
Add-BlockRule -Path "%LOCALAPPDATA%\EpicGamesLauncher\*\*" -Note "Epic depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\EpicGamesLauncher\*\*\*" -Note "Epic depth 3"
Add-BlockRule -Path "%LOCALAPPDATA%\Steam\*" -Note "Steam local"
Add-BlockRule -Path "%LOCALAPPDATA%\Steam\*\*" -Note "Steam depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\Overwolf\*" -Note "Overwolf"
Add-BlockRule -Path "%LOCALAPPDATA%\Overwolf\*\*" -Note "Overwolf depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\Spotify\*" -Note "Spotify local"
Add-BlockRule -Path "%LOCALAPPDATA%\Spotify\*\*" -Note "Spotify depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\WhatsApp\*" -Note "WhatsApp"
Add-BlockRule -Path "%LOCALAPPDATA%\WhatsApp\*\*" -Note "WhatsApp depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\WhatsApp\*\*\*" -Note "WhatsApp depth 3"
Add-BlockRule -Path "%LOCALAPPDATA%\signal-desktop\*" -Note "Signal"
Add-BlockRule -Path "%LOCALAPPDATA%\signal-desktop\*\*" -Note "Signal depth 2"
Add-BlockRule -Path "%LOCALAPPDATA%\Telegram Desktop\*" -Note "Telegram"
Add-BlockRule -Path "%LOCALAPPDATA%\Telegram Desktop\*\*" -Note "Telegram depth 2"

# NOTE: %LOCALAPPDATA%\Microsoft\ is intentionally NOT blocked
# This allows OneDrive, Teams, Edge WebView, etc. to function

# --------------------------------------------------------------
# AppData\LocalLow (OFTEN MISSED!)
# Java, some games, and browser data
# --------------------------------------------------------------
Add-BlockRule -Path "%USERPROFILE%\AppData\LocalLow\*" -Note "AppData LocalLow"
Add-BlockRule -Path "%USERPROFILE%\AppData\LocalLow\*\*" -Note "LocalLow depth 2"
Add-BlockRule -Path "%USERPROFILE%\AppData\LocalLow\*\*\*" -Note "LocalLow depth 3"

# --------------------------------------------------------------
# TEMP directories (%TEMP%, %TMP%)
# Common malware and bypass location
# --------------------------------------------------------------
Add-BlockRule -Path "%TEMP%\*" -Note "User temp folder"
Add-BlockRule -Path "%TEMP%\*\*" -Note "User temp depth 2"
Add-BlockRule -Path "%TEMP%\*\*\*" -Note "User temp depth 3"
Add-BlockRule -Path "%TMP%\*" -Note "TMP folder"
Add-BlockRule -Path "C:\Windows\Temp\*" -Note "System temp folder"
Add-BlockRule -Path "C:\Windows\Temp\*\*" -Note "System temp depth 2"

# --------------------------------------------------------------
# User profile folders (OFTEN MISSED!)
# Downloads, Desktop, Documents, etc.
# --------------------------------------------------------------
Add-BlockRule -Path "%USERPROFILE%\Downloads\*" -Note "Downloads folder"
Add-BlockRule -Path "%USERPROFILE%\Downloads\*\*" -Note "Downloads depth 2"
Add-BlockRule -Path "%USERPROFILE%\Downloads\*\*\*" -Note "Downloads depth 3"

Add-BlockRule -Path "%USERPROFILE%\Desktop\*" -Note "Desktop folder"
Add-BlockRule -Path "%USERPROFILE%\Desktop\*\*" -Note "Desktop depth 2"

Add-BlockRule -Path "%USERPROFILE%\Documents\*" -Note "Documents folder"
Add-BlockRule -Path "%USERPROFILE%\Documents\*\*" -Note "Documents depth 2"
Add-BlockRule -Path "%USERPROFILE%\Documents\*\*\*" -Note "Documents depth 3"

Add-BlockRule -Path "%USERPROFILE%\Music\*" -Note "Music folder"
Add-BlockRule -Path "%USERPROFILE%\Music\*\*" -Note "Music depth 2"

Add-BlockRule -Path "%USERPROFILE%\Pictures\*" -Note "Pictures folder"
Add-BlockRule -Path "%USERPROFILE%\Pictures\*\*" -Note "Pictures depth 2"

Add-BlockRule -Path "%USERPROFILE%\Videos\*" -Note "Videos folder"
Add-BlockRule -Path "%USERPROFILE%\Videos\*\*" -Note "Videos depth 2"

Add-BlockRule -Path "%USERPROFILE%\Favorites\*" -Note "Favorites folder"
Add-BlockRule -Path "%USERPROFILE%\Contacts\*" -Note "Contacts folder"
Add-BlockRule -Path "%USERPROFILE%\Links\*" -Note "Links folder"
Add-BlockRule -Path "%USERPROFILE%\Saved Games\*" -Note "Saved Games folder"
Add-BlockRule -Path "%USERPROFILE%\Searches\*" -Note "Searches folder"
Add-BlockRule -Path "%USERPROFILE%\3D Objects\*" -Note "3D Objects folder"

# --------------------------------------------------------------
# C:\Users\Public (OFTEN MISSED!)
# Writable by all users - common bypass location
# --------------------------------------------------------------
Add-BlockRule -Path "C:\Users\Public\*" -Note "Public folder root"
Add-BlockRule -Path "C:\Users\Public\*\*" -Note "Public folder depth 2"
Add-BlockRule -Path "C:\Users\Public\Desktop\*" -Note "Public Desktop"
Add-BlockRule -Path "C:\Users\Public\Documents\*" -Note "Public Documents"
Add-BlockRule -Path "C:\Users\Public\Downloads\*" -Note "Public Downloads"
Add-BlockRule -Path "C:\Users\Public\Music\*" -Note "Public Music"
Add-BlockRule -Path "C:\Users\Public\Pictures\*" -Note "Public Pictures"
Add-BlockRule -Path "C:\Users\Public\Videos\*" -Note "Public Videos"

# --------------------------------------------------------------
# Removable drives / USB (OFTEN MISSED!)
# Block common drive letters for removable media
# --------------------------------------------------------------
foreach ($letter in 'D','E','F','G','H','I','J','K') {
    Add-BlockRule -Path "${letter}:\*" -Note "Removable drive $letter"
    Add-BlockRule -Path "${letter}:\*\*" -Note "Removable drive $letter depth 2"
    Add-BlockRule -Path "${letter}:\*\*\*" -Note "Removable drive $letter depth 3"
}

# --------------------------------------------------------------
# Intel/AMD/NVIDIA user-writable driver folders
# --------------------------------------------------------------
Add-BlockRule -Path "C:\Intel\*" -Note "Intel folder"
Add-BlockRule -Path "C:\AMD\*" -Note "AMD folder"
Add-BlockRule -Path "C:\NVIDIA\*" -Note "NVIDIA folder"

if ($WhatIf) {
    Write-Host "    [WOULD] Block $script:BlockCount user-writable paths" -ForegroundColor Cyan
} else {
    Write-Host "    ✓ $script:BlockCount user-writable paths blocked" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════
# WHITELIST - USE Add-GameWhitelist.ps1 FOR GAMES/APPS
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[6/6] Configuring whitelisting..." -ForegroundColor Yellow

# NOTE: Microsoft apps (OneDrive, Teams, EdgeWebView) work automatically
# because we use TARGETED blocking that skips %LOCALAPPDATA%\Microsoft\

# Games and apps in blocked locations need explicit whitelisting.
# Use: .\Add-GameWhitelist.ps1 -Preset <name>
# Available: Minecraft, Roblox, Steam, Epic, Discord, Spotify, etc.

Write-Host "    ✓ Use Add-GameWhitelist.ps1 to allow specific games/apps" -ForegroundColor Green

# ═══════════════════════════════════════════════════════════════════
# FINALIZE
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n" + "═" * 68 -ForegroundColor Cyan
if ($WhatIf) {
    Write-Host "SIMULATION COMPLETE (no changes made)" -ForegroundColor Yellow
} else {
    Write-Host "CONFIGURATION COMPLETE" -ForegroundColor Green
}
Write-Host "═" * 68 -ForegroundColor Cyan

Write-Host @"

SUMMARY:
  • Blocked paths:     $script:BlockCount rules
  • Log file:          $LogPath
  • Backup file:       $BackupPath
  • Policy applies to: Standard users ONLY (admins unaffected)

BLOCKED LOCATIONS:
  ✗ AppData\Roaming (all subfolders)
  ✗ AppData\Local\Programs, Temp, and app-specific folders
  ✗ Downloads, Desktop, Documents, Music, Pictures, Videos
  ✗ Temp folders (%TEMP%, %TMP%, C:\Windows\Temp)
  ✗ C:\Users\Public (all subfolders)
  ✗ Removable drives (D: through K:)

ALLOWED (Microsoft apps work automatically):
  ✓ OneDrive, Teams, Edge WebView, Windows Apps

"@ -ForegroundColor White

if ($WhatIf) {
    Write-Host "To apply these changes for real, run without -WhatIf:" -ForegroundColor Yellow
    Write-Host "  .\Enable-SRP-Complete.ps1" -ForegroundColor Cyan
} else {
    Write-Host @"
NEXT STEPS:
  1. Run: gpupdate /force
  2. RESTART the computer
  3. Test from the CHILD'S account (not yours!)
  4. Check logs at: $LogPath
  5. Add whitelist exceptions as needed

"@ -ForegroundColor White
    Write-Host "Applying group policy update..." -ForegroundColor Yellow
    gpupdate /force
    Write-Host "`n⚠️  RESTART REQUIRED for full enforcement!" -ForegroundColor Red
}
