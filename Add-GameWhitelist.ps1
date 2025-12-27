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
        "Spotify", "Zoom", "WhatsApp", "Telegram", "VSCode", "GitHubDesktop", "Slack", "Signal",
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
            @{Path = "%LOCALAPPDATA%\Roblox\*"; Note = "Roblox Player"},
            @{Path = "%LOCALAPPDATA%\Roblox\*\*"; Note = "Roblox depth 2"},
            @{Path = "%LOCALAPPDATA%\Roblox\*\*\*"; Note = "Roblox depth 3"},
            @{Path = "%LOCALAPPDATA%\Roblox\*\*\*\*"; Note = "Roblox depth 4"}
        )
        Notes = "Roblox Player and Studio"
    }

    Steam = @{
        Name = "Steam"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Steam\*"; Note = "Steam local data"},
            @{Path = "%LOCALAPPDATA%\Steam\*\*"; Note = "Steam depth 2"},
            @{Path = "%LOCALAPPDATA%\Steam\*\*\*"; Note = "Steam depth 3"},
            @{Path = "%APPDATA%\Steam\*"; Note = "Steam roaming"},
            @{Path = "%USERPROFILE%\AppData\LocalLow\Steam\*"; Note = "Steam LocalLow"}
        )
        Notes = "Steam client data (main install in Program Files)"
    }

    Epic = @{
        Name = "Epic Games"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\EpicGamesLauncher\*"; Note = "Epic launcher"},
            @{Path = "%LOCALAPPDATA%\EpicGamesLauncher\*\*"; Note = "Epic depth 2"},
            @{Path = "%LOCALAPPDATA%\EpicGamesLauncher\*\*\*"; Note = "Epic depth 3"},
            @{Path = "%LOCALAPPDATA%\FortniteGame\*"; Note = "Fortnite data"},
            @{Path = "%LOCALAPPDATA%\UnrealEngine\*"; Note = "Unreal Engine"}
        )
        Notes = "Epic launcher + Fortnite data"
    }

    Discord = @{
        Name = "Discord"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Discord\*"; Note = "Discord app"},
            @{Path = "%LOCALAPPDATA%\Discord\*\*"; Note = "Discord depth 2"},
            @{Path = "%LOCALAPPDATA%\Discord\*\*\*"; Note = "Discord depth 3"},
            @{Path = "%LOCALAPPDATA%\Discord\*\*\*\*"; Note = "Discord depth 4"},
            @{Path = "%APPDATA%\discord\*"; Note = "Discord roaming"}
        )
        Notes = "Voice/text chat for gaming"
    }

    Overwolf = @{
        Name = "Overwolf"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Overwolf\*"; Note = "Overwolf"},
            @{Path = "%LOCALAPPDATA%\Overwolf\*\*"; Note = "Overwolf depth 2"},
            @{Path = "%LOCALAPPDATA%\Overwolf\*\*\*"; Note = "Overwolf depth 3"}
        )
        Notes = "Gaming overlay and mods"
    }

    CurseForge = @{
        Name = "CurseForge"
        Category = "Game"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\CurseForge\*"; Note = "CurseForge"},
            @{Path = "%LOCALAPPDATA%\CurseForge\*\*"; Note = "CurseForge depth 2"},
            @{Path = "%LOCALAPPDATA%\CurseForge\*\*\*"; Note = "CurseForge depth 3"},
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
            @{Path = "%LOCALAPPDATA%\Spotify\*"; Note = "Spotify local"},
            @{Path = "%LOCALAPPDATA%\Spotify\*\*"; Note = "Spotify local depth 2"}
        )
        Notes = "Music streaming"
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
            @{Path = "%LOCALAPPDATA%\WhatsApp\*"; Note = "WhatsApp app"},
            @{Path = "%LOCALAPPDATA%\WhatsApp\*\*"; Note = "WhatsApp depth 2"},
            @{Path = "%LOCALAPPDATA%\WhatsApp\*\*\*"; Note = "WhatsApp depth 3"},
            @{Path = "%APPDATA%\WhatsApp\*"; Note = "WhatsApp roaming"}
        )
        Notes = "Messaging app"
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
            @{Path = "%LOCALAPPDATA%\GitHubDesktop\*"; Note = "GitHub Desktop"},
            @{Path = "%LOCALAPPDATA%\GitHubDesktop\*\*"; Note = "GitHub Desktop depth 2"},
            @{Path = "%LOCALAPPDATA%\GitHubDesktop\*\*\*"; Note = "GitHub Desktop depth 3"},
            @{Path = "%APPDATA%\GitHub Desktop\*"; Note = "GitHub Desktop roaming"}
        )
        Notes = "Git client"
    }

    Slack = @{
        Name = "Slack"
        Category = "App"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\slack\*"; Note = "Slack app"},
            @{Path = "%LOCALAPPDATA%\slack\*\*"; Note = "Slack depth 2"},
            @{Path = "%LOCALAPPDATA%\slack\*\*\*"; Note = "Slack depth 3"},
            @{Path = "%APPDATA%\Slack\*"; Note = "Slack roaming"}
        )
        Notes = "Team communication"
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
