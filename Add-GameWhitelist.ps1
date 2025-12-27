#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Adds whitelist exceptions for games and game platforms
.DESCRIPTION
    Run this AFTER Enable-SRP-Complete.ps1 to allow specific games
.PARAMETER Preset
    Use a preset: Steam, Epic, Minecraft, Roblox, Discord, All
.PARAMETER CustomPath
    Add a custom path to whitelist
.PARAMETER List
    Show all current whitelist entries
.EXAMPLE
    .\Add-GameWhitelist.ps1 -Preset Minecraft
.EXAMPLE
    .\Add-GameWhitelist.ps1 -Preset All
.EXAMPLE
    .\Add-GameWhitelist.ps1 -CustomPath "D:\Games\MyGame"
#>

param(
    [ValidateSet("Steam", "Epic", "Minecraft", "Roblox", "Discord", "Overwolf", "CurseForge", "All")]
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
    Steam = @{
        Name = "Steam"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Steam\*"; Note = "Steam local data"},
            @{Path = "%LOCALAPPDATA%\Steam\*\*"; Note = "Steam depth 2"},
            @{Path = "%LOCALAPPDATA%\Steam\*\*\*"; Note = "Steam depth 3"},
            @{Path = "%APPDATA%\Steam\*"; Note = "Steam roaming"},
            @{Path = "%USERPROFILE%\AppData\LocalLow\Steam\*"; Note = "Steam LocalLow"}
        )
        Notes = "Main Steam install in Program Files is already allowed"
    }
    
    Epic = @{
        Name = "Epic Games"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\EpicGamesLauncher\*"; Note = "Epic launcher"},
            @{Path = "%LOCALAPPDATA%\EpicGamesLauncher\*\*"; Note = "Epic depth 2"},
            @{Path = "%LOCALAPPDATA%\EpicGamesLauncher\*\*\*"; Note = "Epic depth 3"},
            @{Path = "%LOCALAPPDATA%\FortniteGame\*"; Note = "Fortnite data"},
            @{Path = "%LOCALAPPDATA%\UnrealEngine\*"; Note = "Unreal Engine"}
        )
        Notes = "Main Epic install in Program Files is already allowed"
    }
    
    Minecraft = @{
        Name = "Minecraft"
        Paths = @(
            @{Path = "%APPDATA%\.minecraft\*"; Note = "Minecraft Java"},
            @{Path = "%APPDATA%\.minecraft\*\*"; Note = "Minecraft depth 2"},
            @{Path = "%APPDATA%\.minecraft\*\*\*"; Note = "Minecraft depth 3"},
            @{Path = "%APPDATA%\.minecraft\*\*\*\*"; Note = "Minecraft depth 4 (mods)"},
            @{Path = "%LOCALAPPDATA%\Packages\Microsoft.Minecraft*"; Note = "Minecraft Bedrock"}
        )
        Notes = "Includes support for mods (Forge, Fabric, etc.)"
    }
    
    Roblox = @{
        Name = "Roblox"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Roblox\*"; Note = "Roblox Player"},
            @{Path = "%LOCALAPPDATA%\Roblox\*\*"; Note = "Roblox depth 2"},
            @{Path = "%LOCALAPPDATA%\Roblox\*\*\*"; Note = "Roblox depth 3"},
            @{Path = "%LOCALAPPDATA%\Roblox\*\*\*\*"; Note = "Roblox depth 4"}
        )
        Notes = "Roblox Player and Roblox Studio"
    }
    
    Discord = @{
        Name = "Discord"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Discord\*"; Note = "Discord app"},
            @{Path = "%LOCALAPPDATA%\Discord\*\*"; Note = "Discord depth 2"},
            @{Path = "%LOCALAPPDATA%\Discord\*\*\*"; Note = "Discord depth 3"},
            @{Path = "%APPDATA%\discord\*"; Note = "Discord roaming"}
        )
        Notes = "Voice chat for gaming"
    }
    
    Overwolf = @{
        Name = "Overwolf"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\Overwolf\*"; Note = "Overwolf"},
            @{Path = "%LOCALAPPDATA%\Overwolf\*\*"; Note = "Overwolf depth 2"},
            @{Path = "%LOCALAPPDATA%\Overwolf\*\*\*"; Note = "Overwolf depth 3"}
        )
        Notes = "Gaming overlay and mods platform"
    }
    
    CurseForge = @{
        Name = "CurseForge"
        Paths = @(
            @{Path = "%LOCALAPPDATA%\CurseForge\*"; Note = "CurseForge"},
            @{Path = "%LOCALAPPDATA%\CurseForge\*\*"; Note = "CurseForge depth 2"},
            @{Path = "%LOCALAPPDATA%\CurseForge\*\*\*"; Note = "CurseForge depth 3"},
            @{Path = "%USERPROFILE%\curseforge\*"; Note = "CurseForge games"},
            @{Path = "%USERPROFILE%\curseforge\*\*"; Note = "CurseForge depth 2"},
            @{Path = "%USERPROFILE%\curseforge\*\*\*"; Note = "CurseForge depth 3"}
        )
        Notes = "Mod manager for Minecraft, WoW, etc."
    }
}

# ═══════════════════════════════════════════════════════════════════
# MAIN LOGIC
# ═══════════════════════════════════════════════════════════════════

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  GAME WHITELIST MANAGER                                         ║
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
    if ($Preset -eq "All") {
        Write-Host "`nApplying ALL game presets..." -ForegroundColor Yellow
        foreach ($key in $GamePresets.Keys) {
            $preset_data = $GamePresets[$key]
            Write-Host "`n[$($preset_data.Name)]" -ForegroundColor Cyan
            foreach ($pathInfo in $preset_data.Paths) {
                if ($Remove) {
                    Remove-AllowRule -Path $pathInfo.Path
                } else {
                    Add-AllowRule -Path $pathInfo.Path -Note $pathInfo.Note
                }
            }
        }
    } else {
        $preset_data = $GamePresets[$Preset]
        Write-Host "`n[$($preset_data.Name)]" -ForegroundColor Cyan
        Write-Host "  $($preset_data.Notes)" -ForegroundColor DarkGray
        
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
  .\Add-GameWhitelist.ps1 -Preset <name>     Add a game preset
  .\Add-GameWhitelist.ps1 -Preset All        Add all game presets
  .\Add-GameWhitelist.ps1 -CustomPath <path> Add custom game folder
  .\Add-GameWhitelist.ps1 -List              Show current whitelist
  .\Add-GameWhitelist.ps1 -Preset X -Remove  Remove a preset

AVAILABLE PRESETS:
"@ -ForegroundColor White

    foreach ($key in $GamePresets.Keys | Sort-Object) {
        $preset_data = $GamePresets[$key]
        Write-Host "  • $key" -ForegroundColor Green -NoNewline
        Write-Host " - $($preset_data.Notes)" -ForegroundColor DarkGray
    }
    
    Write-Host @"

EXAMPLES:
  .\Add-GameWhitelist.ps1 -Preset Minecraft
  .\Add-GameWhitelist.ps1 -Preset Roblox -Preset Discord
  .\Add-GameWhitelist.ps1 -CustomPath "D:\Games\MyGame"
  .\Add-GameWhitelist.ps1 -CustomPath "%USERPROFILE%\Games"

"@ -ForegroundColor White
    exit 0
}

# Refresh policy
Write-Host "`nApplying changes..." -ForegroundColor Yellow
gpupdate /force 2>$null | Out-Null
Write-Host "✓ Done! Changes are active immediately." -ForegroundColor Green
