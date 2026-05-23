#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Adds whitelist exceptions for games and applications
.DESCRIPTION
    Run this AFTER Enable-SRP-Complete.ps1 to allow specific games and apps
    that install to user-writable locations (AppData, etc.)
.PARAMETER Preset
    Use a preset - Games: Minecraft, Roblox, Steam, Epic, Discord, Overwolf, CurseForge
                   Apps: Spotify, Zoom, WhatsApp, Telegram, VSCode, GitHubDesktop, Slack, Signal
                   Special: AllGames, AllApps, All
.PARAMETER CustomPath
    Add a custom path to whitelist
.PARAMETER List
    Show all current whitelist entries
.EXAMPLE
    .\Add-GameWhitelist.ps1 -Preset Minecraft
.EXAMPLE
    .\Add-GameWhitelist.ps1 -Preset Spotify
.EXAMPLE
    .\Add-GameWhitelist.ps1 -Preset AllGames
.EXAMPLE
    .\Add-GameWhitelist.ps1 -CustomPath "D:\Games\MyGame"
#>

param(
    [ValidateSet(
        # Games
        "Minecraft", "Roblox", "Steam", "Epic", "Discord", "Overwolf", "CurseForge",
        # Apps
        "Spotify", "Zoom", "WhatsApp", "Telegram", "VSCode", "GitHubDesktop", "Slack", "Signal", "OneDrive", "PowerShell",
        # Batch options
        "AllGames", "AllApps", "All"
    )]
    [string]$Preset,
    
    [string]$CustomPath,
    
    [switch]$List,
    
    [switch]$Remove
)

$BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"

# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

function Add-AllowRule {
    param (
        [string]$Path, 
        [string]$Note = ""
    )
    
    # Check if already exists
    $existing = Get-ChildItem $BasePath -ErrorAction SilentlyContinue | 
        Where-Object { (Get-ItemProperty $_.PSPath).ItemData -eq $Path }
    
    if ($existing) {
        Write-Host "    ⏭ Already exists: $Path" -ForegroundColor Yellow
        return
    }
    
    $guid = "{$([System.Guid]::NewGuid().ToString())}"
    $keyPath = "$BasePath\$guid"
    
    New-Item -Path $keyPath -Force | Out-Null
    Set-ItemProperty -Path $keyPath -Name "ItemData" -Value $Path -Type ExpandString
    Set-ItemProperty -Path $keyPath -Name "SaferFlags" -Value 0 -Type DWord
    if ($Note) { 
        Set-ItemProperty -Path $keyPath -Name "Description" -Value $Note -Type String 
    }
    
    Write-Host "    ✓ Added: $Path" -ForegroundColor Green
}

function Remove-AllowRule {
    param ([string]$Path)
    
    $existing = Get-ChildItem $BasePath -ErrorAction SilentlyContinue | 
        Where-Object { (Get-ItemProperty $_.PSPath).ItemData -eq $Path }
    
    if ($existing) {
        Remove-Item $existing.PSPath -Force
        Write-Host "    ✓ Removed: $Path" -ForegroundColor Green
    } else {
        Write-Host "    ⚠ Not found: $Path" -ForegroundColor Yellow
    }
}

# ═══════════════════════════════════════════════════════════════════
# GAME PRESETS
# ═══════════════════════════════════════════════════════════════════
# SAFER tie-break: when an ALLOW and a BLOCK rule have equal specificity
# (same number of literal chars before the wildcard), the BLOCK wins.
# Enable-SRP-Complete.ps1 adds per-app BLOCK rules like
# "%LOCALAPPDATA%\Discord\*", so ALLOW rules must push the wildcard
# further right with a real subfolder name (Versions, app-*, etc.) to
# out-specify the block. Don't reintroduce paths like
# "%LOCALAPPDATA%\<app>\*" here — they tie and stay blocked.

$GamePresets = @{
    Minecraft = @{
        Name = "Minecraft"
        Category = "Game"
        Paths = @(
            @{Path = "%APPDATA%\.minecraft\*"; Note = "Minecraft Java"},
            @{Path = "%APPDATA%\.minecraft\*\*"; Note = "Minecraft depth 2"},
            @{Path = "%APPDATA%\.minecraft\*\*\*"; Note = "Minecraft depth 3"},
            @{Path = "%APPDATA%\.minecraft\*\*\*\*"; Note = "Minecraft depth 4 (mods)"},
            @{Path = "%LOCALAPPDATA%\Packages\Microsoft.Minecraft*"; Note = "Minecraft Bedrock"}
        )
        Notes = "Java + Bedrock + mods (Forge, Fabric)"
    }

    Roblox = @{
        Name = "Roblox"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Roblox\Versions\*"; Note = "Roblox versions root"},
            @{Path = "%LOCALAPPDATA%\Roblox\Versions\*\*"; Note = "Roblox version files"},
            @{Path = "%LOCALAPPDATA%\Roblox\Versions\*\*\*"; Note = "Roblox version subfolders"},
            @{Path = "%LOCALAPPDATA%\Roblox\Downloads\*"; Note = "Roblox installer cache"}
        )
        Notes = "Roblox Player and Studio (Versions\\version-XXX\\RobloxPlayerBeta.exe)"
    }

    Steam = @{
        Name = "Steam"
        Category = "Game"
        Paths = @(
            @{Path = "%APPDATA%\Steam\*"; Note = "Steam roaming"},
            @{Path = "%USERPROFILE%\AppData\LocalLow\Steam\*"; Note = "Steam LocalLow"}
        )
        Notes = "Steam client (main install in Program Files; %LOCALAPPDATA%\\Steam is data only)"
    }

    Epic = @{
        Name = "Epic Games"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\EpicGamesLauncher\Saved\*"; Note = "Epic Saved data"},
            @{Path = "%LOCALAPPDATA%\EpicGamesLauncher\Saved\*\*"; Note = "Epic Saved depth 2"},
            @{Path = "%LOCALAPPDATA%\EpicGamesLauncher\Saved\*\*\*"; Note = "Epic Saved depth 3"},
            @{Path = "%LOCALAPPDATA%\FortniteGame\*"; Note = "Fortnite data"},
            @{Path = "%LOCALAPPDATA%\UnrealEngine\*"; Note = "Unreal Engine"}
        )
        Notes = "Epic launcher (main exe in Program Files; only Saved\\ may run helpers)"
    }

    Discord = @{
        Name = "Discord"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Discord\Update.exe"; Note = "Discord Squirrel updater"},
            @{Path = "%LOCALAPPDATA%\Discord\app-*\*"; Note = "Discord versioned app"},
            @{Path = "%LOCALAPPDATA%\Discord\app-*\*\*"; Note = "Discord app depth 2"},
            @{Path = "%APPDATA%\discord\*"; Note = "Discord roaming"}
        )
        Notes = "Voice/text chat (Squirrel installer: app-X.Y.Z\\Discord.exe + Update.exe)"
    }

    Overwolf = @{
        Name = "Overwolf"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Overwolf\OverwolfLauncher.exe"; Note = "Overwolf launcher"},
            @{Path = "%LOCALAPPDATA%\Overwolf\OverwolfPackages\*"; Note = "Overwolf packages"},
            @{Path = "%LOCALAPPDATA%\Overwolf\OverwolfPackages\*\*"; Note = "Overwolf packages depth 2"},
            @{Path = "%LOCALAPPDATA%\Overwolf\Extensions\*"; Note = "Overwolf extensions"},
            @{Path = "%LOCALAPPDATA%\Overwolf\Extensions\*\*"; Note = "Overwolf extensions depth 2"}
        )
        Notes = "Gaming overlay and mods"
    }

    CurseForge = @{
        Name = "CurseForge"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\CurseForge\Bin\*"; Note = "CurseForge binaries"},
            @{Path = "%LOCALAPPDATA%\CurseForge\Bin\*\*"; Note = "CurseForge bin depth 2"},
            @{Path = "%LOCALAPPDATA%\CurseForge\Install\*"; Note = "CurseForge installer"},
            @{Path = "%USERPROFILE%\curseforge\*"; Note = "CurseForge games"},
            @{Path = "%USERPROFILE%\curseforge\*\*"; Note = "CurseForge depth 2"},
            @{Path = "%USERPROFILE%\curseforge\*\*\*"; Note = "CurseForge depth 3"}
        )
        Notes = "Mod manager (Minecraft, WoW)"
    }
}

# ═══════════════════════════════════════════════════════════════════
# APP PRESETS
# ═══════════════════════════════════════════════════════════════════

$AppPresets = @{
    Spotify = @{
        Name = "Spotify"
        Category = "App"
        Paths = @(
            @{Path = "%APPDATA%\Spotify\*"; Note = "Spotify app"},
            @{Path = "%APPDATA%\Spotify\*\*"; Note = "Spotify depth 2"},
            @{Path = "%APPDATA%\Spotify\*\*\*"; Note = "Spotify depth 3"},
            @{Path = "%LOCALAPPDATA%\Spotify\Update\*"; Note = "Spotify updater"},
            @{Path = "%LOCALAPPDATA%\Spotify\Data\*"; Note = "Spotify cache"}
        )
        Notes = "Music streaming (main exe in %APPDATA%\\Spotify)"
    }

    Zoom = @{
        Name = "Zoom"
        Category = "App"
        Paths = @(
            @{Path = "%APPDATA%\Zoom\*"; Note = "Zoom app"},
            @{Path = "%APPDATA%\Zoom\*\*"; Note = "Zoom depth 2"},
            @{Path = "%APPDATA%\Zoom\*\*\*"; Note = "Zoom depth 3"},
            @{Path = "%APPDATA%\Zoom\bin\*"; Note = "Zoom binaries"}
        )
        Notes = "Video conferencing"
    }

    WhatsApp = @{
        Name = "WhatsApp"
        Category = "App"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\WhatsApp\Update.exe"; Note = "WhatsApp Squirrel updater"},
            @{Path = "%LOCALAPPDATA%\WhatsApp\app-*\*"; Note = "WhatsApp versioned app"},
            @{Path = "%LOCALAPPDATA%\WhatsApp\app-*\*\*"; Note = "WhatsApp app depth 2"},
            @{Path = "%APPDATA%\WhatsApp\*"; Note = "WhatsApp roaming"}
        )
        Notes = "Messaging (Squirrel installer); UWP build runs from Packages and is unaffected"
    }

    Telegram = @{
        Name = "Telegram"
        Category = "App"
        Paths = @(
            @{Path = "%APPDATA%\Telegram Desktop\*"; Note = "Telegram app"},
            @{Path = "%APPDATA%\Telegram Desktop\*\*"; Note = "Telegram depth 2"},
            @{Path = "%APPDATA%\Telegram Desktop\*\*\*"; Note = "Telegram depth 3"}
        )
        Notes = "Messaging app"
    }

    VSCode = @{
        Name = "VS Code"
        Category = "App"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Programs\Microsoft VS Code\*"; Note = "VS Code app"},
            @{Path = "%LOCALAPPDATA%\Programs\Microsoft VS Code\*\*"; Note = "VS Code depth 2"},
            @{Path = "%LOCALAPPDATA%\Programs\Microsoft VS Code\*\*\*"; Note = "VS Code depth 3"},
            @{Path = "%APPDATA%\Code\*"; Note = "VS Code settings"},
            @{Path = "%APPDATA%\Code\*\*"; Note = "VS Code settings depth 2"}
        )
        Notes = "Code editor"
    }

    GitHubDesktop = @{
        Name = "GitHub Desktop"
        Category = "App"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\GitHubDesktop\Update.exe"; Note = "GitHub Desktop Squirrel updater"},
            @{Path = "%LOCALAPPDATA%\GitHubDesktop\app-*\*"; Note = "GitHub Desktop versioned app"},
            @{Path = "%LOCALAPPDATA%\GitHubDesktop\app-*\*\*"; Note = "GitHub Desktop app depth 2"},
            @{Path = "%APPDATA%\GitHub Desktop\*"; Note = "GitHub Desktop roaming"}
        )
        Notes = "Git client (Squirrel installer: app-X.Y.Z\\GitHubDesktop.exe + Update.exe)"
    }

    Slack = @{
        Name = "Slack"
        Category = "App"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\slack\Update.exe"; Note = "Slack Squirrel updater"},
            @{Path = "%LOCALAPPDATA%\slack\app-*\*"; Note = "Slack versioned app"},
            @{Path = "%LOCALAPPDATA%\slack\app-*\*\*"; Note = "Slack app depth 2"},
            @{Path = "%APPDATA%\Slack\*"; Note = "Slack roaming"}
        )
        Notes = "Team communication (Squirrel installer: app-X.Y.Z\\slack.exe + Update.exe)"
    }

    Signal = @{
        Name = "Signal"
        Category = "App"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Programs\signal-desktop\*"; Note = "Signal app"},
            @{Path = "%LOCALAPPDATA%\Programs\signal-desktop\*\*"; Note = "Signal depth 2"},
            @{Path = "%LOCALAPPDATA%\Programs\signal-desktop\*\*\*"; Note = "Signal depth 3"},
            @{Path = "%APPDATA%\Signal\*"; Note = "Signal data"}
        )
        Notes = "Secure messaging"
    }

    OneDrive = @{
        Name = "OneDrive"
        Category = "App"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Microsoft\OneDrive\*"; Note = "OneDrive app"},
            @{Path = "%LOCALAPPDATA%\Microsoft\OneDrive\*\*"; Note = "OneDrive depth 2"},
            @{Path = "%LOCALAPPDATA%\Microsoft\OneDrive\*\*\*"; Note = "OneDrive depth 3"},
            @{Path = "%LOCALAPPDATA%\Microsoft\OneDrive\*\*\*\*"; Note = "OneDrive depth 4"}
        )
        Notes = "Cloud sync client"
    }

    PowerShell = @{
        Name = "PowerShell Policy Test"
        Category = "System"
        Paths = @(
            @{Path = "%TEMP%\__PSScriptPolicyTest_*"; Note = "PowerShell policy test"},
            @{Path = "%LOCALAPPDATA%\Temp\__PSScriptPolicyTest_*"; Note = "PowerShell policy test"}
        )
        Notes = "Required for PowerShell execution policy checks"
    }
}

# Combine all presets for lookup
$AllPresets = $GamePresets + $AppPresets

# ═══════════════════════════════════════════════════════════════════
# MAIN LOGIC
# ═══════════════════════════════════════════════════════════════════

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  WHITELIST MANAGER - Games & Apps                               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Check if SRP is configured
if (!(Test-Path $BasePath)) {
    Write-Host "`n⚠ SRP not configured! Run Enable-SRP-Complete.ps1 first." -ForegroundColor Red
    exit 1
}

# List current rules
if ($List) {
    Write-Host "`nCurrent ALLOW rules:" -ForegroundColor Yellow
    Get-ChildItem $BasePath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath
        $desc = if ($props.Description) { " ($($props.Description))" } else { "" }
        Write-Host "  • $($props.ItemData)$desc" -ForegroundColor White
    }
    exit 0
}

# Apply preset
if ($Preset) {
    $presetsToApply = @()

    switch ($Preset) {
        "All" {
            Write-Host "`nApplying ALL presets (Games + Apps)..." -ForegroundColor Yellow
            $presetsToApply = $AllPresets.Keys
        }
        "AllGames" {
            Write-Host "`nApplying all GAME presets..." -ForegroundColor Yellow
            $presetsToApply = $GamePresets.Keys
        }
        "AllApps" {
            Write-Host "`nApplying all APP presets..." -ForegroundColor Yellow
            $presetsToApply = $AppPresets.Keys
        }
        default {
            $presetsToApply = @($Preset)
        }
    }

    foreach ($presetKey in $presetsToApply) {
        $preset_data = $AllPresets[$presetKey]
        if ($null -eq $preset_data) { continue }

        Write-Host "`n[$($preset_data.Name)]" -ForegroundColor Cyan
        if ($presetsToApply.Count -eq 1) {
            Write-Host "  $($preset_data.Notes)" -ForegroundColor DarkGray
        }

        foreach ($pathInfo in $preset_data.Paths) {
            if ($Remove) {
                Remove-AllowRule -Path $pathInfo.Path
            } else {
                Add-AllowRule -Path $pathInfo.Path -Note $pathInfo.Note
            }
        }
    }
}

# Custom path
if ($CustomPath) {
    Write-Host "`n[Custom Path]" -ForegroundColor Cyan

    # Strip trailing backslashes; otherwise "path\" + "\*" produces "path\\*",
    # which SAFER stores literally and never matches anything.
    $CustomPath = $CustomPath.TrimEnd('\')

    # Normalize path and add wildcards if needed
    $pathsToAdd = @()

    if ($CustomPath -notmatch '\*$') {
        # Add with depth wildcards
        $pathsToAdd += "$CustomPath\*"
        $pathsToAdd += "$CustomPath\*\*"
        $pathsToAdd += "$CustomPath\*\*\*"
    } else {
        $pathsToAdd += $CustomPath
    }
    
    foreach ($p in $pathsToAdd) {
        if ($Remove) {
            Remove-AllowRule -Path $p
        } else {
            Add-AllowRule -Path $p -Note "Custom game path"
        }
    }
}

# Show usage if no params
if (!$Preset -and !$CustomPath -and !$List) {
    Write-Host @"

USAGE:
  .\Add-GameWhitelist.ps1 -Preset <name>     Add a preset
  .\Add-GameWhitelist.ps1 -Preset AllGames   Add all game presets
  .\Add-GameWhitelist.ps1 -Preset AllApps    Add all app presets
  .\Add-GameWhitelist.ps1 -Preset All        Add everything
  .\Add-GameWhitelist.ps1 -CustomPath <path> Add custom folder
  .\Add-GameWhitelist.ps1 -List              Show current whitelist
  .\Add-GameWhitelist.ps1 -Preset X -Remove  Remove a preset

GAMES:
"@ -ForegroundColor White

    foreach ($key in $GamePresets.Keys | Sort-Object) {
        $preset_data = $GamePresets[$key]
        Write-Host "  • $key" -ForegroundColor Green -NoNewline
        Write-Host " - $($preset_data.Notes)" -ForegroundColor DarkGray
    }

    Write-Host "`nAPPS:" -ForegroundColor White

    foreach ($key in $AppPresets.Keys | Sort-Object) {
        $preset_data = $AppPresets[$key]
        Write-Host "  • $key" -ForegroundColor Cyan -NoNewline
        Write-Host " - $($preset_data.Notes)" -ForegroundColor DarkGray
    }

    Write-Host @"

EXAMPLES:
  .\Add-GameWhitelist.ps1 -Preset Minecraft
  .\Add-GameWhitelist.ps1 -Preset Spotify
  .\Add-GameWhitelist.ps1 -Preset AllGames
  .\Add-GameWhitelist.ps1 -CustomPath "D:\Games\MyGame"

"@ -ForegroundColor White
    exit 0
}

# Refresh policy
Write-Host "`nApplying changes..." -ForegroundColor Yellow
gpupdate /force 2>$null | Out-Null
Write-Host "✓ Done! Changes are active immediately." -ForegroundColor Green
