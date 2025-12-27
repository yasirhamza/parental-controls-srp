#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Interactive menu launcher for Windows Parental Controls
.DESCRIPTION
    Unified interface to manage Software Restriction Policies (SRP)
    for blocking unauthorized applications on child accounts.
.NOTES
    Run as Administrator for full functionality.
#>

$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
$script:LogPath = "C:\ParentalControl\Logs\SAFER.log"

# ═══════════════════════════════════════════════════════════════════
# GAME PRESETS (duplicated from Add-GameWhitelist.ps1 for display)
# ═══════════════════════════════════════════════════════════════════
$script:GamePresets = [ordered]@{
    "1" = @{ Name = "Steam"; Desc = "Steam client and games" }
    "2" = @{ Name = "Epic"; Desc = "Epic Games Launcher and Fortnite" }
    "3" = @{ Name = "Minecraft"; Desc = "Java + Bedrock editions with mod support" }
    "4" = @{ Name = "Roblox"; Desc = "Roblox Player and Studio" }
    "5" = @{ Name = "Discord"; Desc = "Voice chat for gaming" }
    "6" = @{ Name = "Overwolf"; Desc = "Gaming overlay and mods platform" }
    "7" = @{ Name = "CurseForge"; Desc = "Mod manager for Minecraft, WoW, etc." }
}

# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

function Write-Header {
    param ([string]$Title)
    Clear-Host
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  $($Title.PadRight(62))║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Write-MenuOption {
    param (
        [string]$Key,
        [string]$Label,
        [string]$Description = ""
    )
    Write-Host "  [" -NoNewline
    Write-Host $Key -ForegroundColor Yellow -NoNewline
    Write-Host "] " -NoNewline
    Write-Host $Label -ForegroundColor White -NoNewline
    if ($Description) {
        Write-Host " - $Description" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
}

function Read-Choice {
    param (
        [string]$Prompt = "Enter choice",
        [string[]]$ValidChoices
    )
    Write-Host ""
    Write-Host "  $Prompt" -NoNewline -ForegroundColor White
    Write-Host ": " -NoNewline
    $choice = Read-Host
    return $choice.Trim()
}

function Read-YesNo {
    param (
        [string]$Prompt,
        [bool]$Default = $true
    )
    $defaultText = if ($Default) { "[Y/n]" } else { "[y/N]" }
    Write-Host ""
    Write-Host "  $Prompt $defaultText " -NoNewline -ForegroundColor White
    $response = Read-Host

    if ([string]::IsNullOrWhiteSpace($response)) {
        return $Default
    }
    return $response -match '^[Yy]'
}

function Press-AnyKey {
    Write-Host ""
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Test-SRPEnabled {
    if (!(Test-Path $script:BasePath)) {
        return $false
    }
    $defaultLevel = Get-ItemProperty -Path $script:BasePath -Name "DefaultLevel" -ErrorAction SilentlyContinue
    return ($null -ne $defaultLevel)
}

function Get-BlockRuleCount {
    $blockPath = "$script:BasePath\0\Paths"
    if (Test-Path $blockPath) {
        return (Get-ChildItem $blockPath -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    return 0
}

function Get-AllowRuleCount {
    $allowPath = "$script:BasePath\262144\Paths"
    if (Test-Path $allowPath) {
        return (Get-ChildItem $allowPath -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    return 0
}

function Get-WhitelistedGames {
    $allowPath = "$script:BasePath\262144\Paths"
    $games = @()

    if (Test-Path $allowPath) {
        $rules = Get-ChildItem $allowPath -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ItemProperty $_.PSPath
        }

        # Detect games by path patterns
        $gamePatterns = @{
            "Minecraft" = "\.minecraft|Microsoft\.Minecraft"
            "Roblox" = "Roblox"
            "Steam" = "Steam"
            "Epic" = "EpicGames|Fortnite|UnrealEngine"
            "Discord" = "Discord"
            "Overwolf" = "Overwolf"
            "CurseForge" = "CurseForge|curseforge"
        }

        foreach ($game in $gamePatterns.Keys) {
            if ($rules | Where-Object { $_.ItemData -match $gamePatterns[$game] }) {
                $games += $game
            }
        }
    }
    return $games | Select-Object -Unique
}

# ═══════════════════════════════════════════════════════════════════
# STATUS VIEW
# ═══════════════════════════════════════════════════════════════════

function Show-Status {
    Write-Header "PROTECTION STATUS"

    $enabled = Test-SRPEnabled
    $blockCount = Get-BlockRuleCount
    $allowCount = Get-AllowRuleCount
    $games = Get-WhitelistedGames

    Write-Host ""
    Write-Host "  Protection:    " -NoNewline
    if ($enabled) {
        Write-Host "ENABLED" -ForegroundColor Green
    } else {
        Write-Host "DISABLED" -ForegroundColor Red
    }

    if ($enabled) {
        $policyScope = Get-ItemProperty -Path $script:BasePath -Name "PolicyScope" -ErrorAction SilentlyContinue
        Write-Host "  Policy Scope:  " -NoNewline
        if ($policyScope.PolicyScope -eq 1) {
            Write-Host "Standard Users Only (Admins exempt)" -ForegroundColor Green
        } else {
            Write-Host "All Users" -ForegroundColor Yellow
        }

        Write-Host "  Block Rules:   $blockCount paths blocked" -ForegroundColor White
        Write-Host "  Allow Rules:   $allowCount paths whitelisted" -ForegroundColor White

        Write-Host "  Log File:      " -NoNewline
        if (Test-Path $script:LogPath) {
            Write-Host $script:LogPath -ForegroundColor Cyan
        } else {
            Write-Host "(not created yet)" -ForegroundColor DarkGray
        }

        # Check for recent blocks
        if (Test-Path $script:LogPath) {
            $today = Get-Date -Format "yyyy-MM-dd"
            $todayBlocks = (Get-Content $script:LogPath -ErrorAction SilentlyContinue |
                Where-Object { $_ -match $today } | Measure-Object).Count
            Write-Host "  Today's Blocks: $todayBlocks attempts" -ForegroundColor $(if ($todayBlocks -gt 0) { "Yellow" } else { "Green" })
        }

        Write-Host ""
        Write-Host "  Whitelisted Games:" -ForegroundColor White
        if ($games.Count -gt 0) {
            foreach ($game in $games) {
                Write-Host "    • $game" -ForegroundColor Cyan
            }
        } else {
            Write-Host "    (none)" -ForegroundColor DarkGray
        }
    }

    Press-AnyKey
}

# ═══════════════════════════════════════════════════════════════════
# BLOCKED ATTEMPTS VIEW
# ═══════════════════════════════════════════════════════════════════

function Show-BlockedAttempts {
    Write-Header "BLOCKED ATTEMPTS"

    if (!(Test-Path $script:LogPath)) {
        Write-Host ""
        Write-Host "  No log file found at: $script:LogPath" -ForegroundColor Yellow
        Write-Host "  Logs are created when SRP blocks an execution attempt." -ForegroundColor DarkGray
        Press-AnyKey
        return
    }

    Write-Host ""
    Write-Host "  Recent blocked attempts (last 20):" -ForegroundColor White
    Write-Host "  " + ("-" * 60) -ForegroundColor DarkGray

    $logs = Get-Content $script:LogPath -Tail 20 -ErrorAction SilentlyContinue

    if ($logs) {
        foreach ($line in $logs) {
            Write-Host "  $line" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  No blocked attempts recorded yet." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "  " + ("-" * 60) -ForegroundColor DarkGray
    Write-Host "  Log file: $script:LogPath" -ForegroundColor DarkGray

    Press-AnyKey
}

# ═══════════════════════════════════════════════════════════════════
# ENABLE PROTECTION WIZARD
# ═══════════════════════════════════════════════════════════════════

function Invoke-EnableWizard {
    Write-Header "ENABLE PROTECTION - WIZARD"

    # Step 1: Check if already enabled
    if (Test-SRPEnabled) {
        Write-Host ""
        Write-Host "  Protection is already ENABLED." -ForegroundColor Yellow
        Write-Host ""
        if (!(Read-YesNo -Prompt "Do you want to re-apply the configuration?")) {
            return
        }
    }

    # Step 2: Pre-flight checks
    Write-Host ""
    Write-Host "  PRE-FLIGHT CHECKLIST" -ForegroundColor White
    Write-Host "  " + ("-" * 40) -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  Before enabling protection, confirm:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Your account (parent) is an Administrator" -ForegroundColor Cyan
    Write-Host "  2. Child's account is a Standard User (not Admin)" -ForegroundColor Cyan
    Write-Host "  3. You're ready to restart the computer after" -ForegroundColor Cyan
    Write-Host ""

    if (!(Read-YesNo -Prompt "Have you confirmed the above?")) {
        Write-Host ""
        Write-Host "  Please set up accounts correctly first." -ForegroundColor Yellow
        Write-Host "  Go to Settings > Accounts > Family & other users" -ForegroundColor DarkGray
        Press-AnyKey
        return
    }

    # Step 3: Show what will be blocked
    Write-Host ""
    Write-Host "  WHAT WILL BE BLOCKED:" -ForegroundColor White
    Write-Host "  " + ("-" * 40) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  For Standard Users (child), executables will be blocked in:" -ForegroundColor White
    Write-Host ""
    Write-Host "    • AppData (Roaming, Local, LocalLow)" -ForegroundColor Red
    Write-Host "    • Downloads, Desktop, Documents" -ForegroundColor Red
    Write-Host "    • Music, Pictures, Videos" -ForegroundColor Red
    Write-Host "    • Temp folders" -ForegroundColor Red
    Write-Host "    • C:\Users\Public" -ForegroundColor Red
    Write-Host "    • OneDrive folders" -ForegroundColor Red
    Write-Host "    • USB drives (D: through K:)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Administrators (you) are NOT affected." -ForegroundColor Green
    Write-Host ""

    if (!(Read-YesNo -Prompt "Proceed with enabling protection?")) {
        Write-Host ""
        Write-Host "  Cancelled." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Step 4: Run the enable script
    Write-Host ""
    Write-Host "  Applying protection..." -ForegroundColor Yellow
    Write-Host "  " + ("-" * 40) -ForegroundColor DarkGray
    Write-Host ""

    $enableScript = Join-Path $script:ScriptDir "Enable-SRP-Complete.ps1"
    if (Test-Path $enableScript) {
        & $enableScript
    } else {
        Write-Host "  ERROR: Enable-SRP-Complete.ps1 not found!" -ForegroundColor Red
        Write-Host "  Expected at: $enableScript" -ForegroundColor Red
        Press-AnyKey
        return
    }

    # Step 5: Prompt for restart
    Write-Host ""
    Write-Host "  " + ("=" * 50) -ForegroundColor Green
    Write-Host "  PROTECTION ENABLED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "  " + ("=" * 50) -ForegroundColor Green
    Write-Host ""

    if (Read-YesNo -Prompt "Restart computer now for full enforcement?") {
        Write-Host ""
        Write-Host "  Restarting in 10 seconds... (Press Ctrl+C to cancel)" -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    } else {
        Write-Host ""
        Write-Host "  Remember to restart later for full enforcement!" -ForegroundColor Yellow
        Press-AnyKey
    }
}

# ═══════════════════════════════════════════════════════════════════
# DISABLE PROTECTION WIZARD
# ═══════════════════════════════════════════════════════════════════

function Invoke-DisableWizard {
    Write-Header "DISABLE PROTECTION - WIZARD"

    # Step 1: Check if already disabled
    if (!(Test-SRPEnabled)) {
        Write-Host ""
        Write-Host "  Protection is already DISABLED." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Step 2: Confirm intent
    Write-Host ""
    Write-Host "  WARNING: This will remove all application restrictions." -ForegroundColor Red
    Write-Host "  The child account will be able to run any application." -ForegroundColor Red
    Write-Host ""

    if (!(Read-YesNo -Prompt "Are you sure you want to disable protection?" -Default $false)) {
        Write-Host ""
        Write-Host "  Cancelled." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Step 3: Options
    Write-Host ""
    $keepLogs = Read-YesNo -Prompt "Keep log files for review?"

    # Step 4: Run rollback
    Write-Host ""
    Write-Host "  Removing protection..." -ForegroundColor Yellow
    Write-Host "  " + ("-" * 40) -ForegroundColor DarkGray
    Write-Host ""

    $rollbackScript = Join-Path $script:ScriptDir "Rollback-SRP.ps1"
    if (Test-Path $rollbackScript) {
        $params = @{}
        if ($keepLogs) { $params["KeepLogs"] = $true }
        & $rollbackScript @params
    } else {
        Write-Host "  ERROR: Rollback-SRP.ps1 not found!" -ForegroundColor Red
        Write-Host "  Expected at: $rollbackScript" -ForegroundColor Red
        Press-AnyKey
        return
    }

    # Step 5: Confirm
    Write-Host ""
    Write-Host "  " + ("=" * 50) -ForegroundColor Green
    Write-Host "  PROTECTION DISABLED" -ForegroundColor Green
    Write-Host "  " + ("=" * 50) -ForegroundColor Green
    Write-Host ""
    Write-Host "  Restart recommended for complete removal." -ForegroundColor Yellow

    Press-AnyKey
}

# ═══════════════════════════════════════════════════════════════════
# GAME WHITELIST MENU
# ═══════════════════════════════════════════════════════════════════

function Show-GameMenu {
    while ($true) {
        Write-Header "MANAGE GAME WHITELIST"

        if (!(Test-SRPEnabled)) {
            Write-Host ""
            Write-Host "  Protection is not enabled." -ForegroundColor Yellow
            Write-Host "  Enable protection first before managing whitelist." -ForegroundColor DarkGray
            Press-AnyKey
            return
        }

        Write-Host ""
        Write-MenuOption -Key "1" -Label "Add game presets" -Description "Minecraft, Roblox, Steam, etc."
        Write-MenuOption -Key "2" -Label "Add custom game folder" -Description "Whitelist any path"
        Write-MenuOption -Key "3" -Label "Remove game presets" -Description "Undo whitelisting"
        Write-MenuOption -Key "4" -Label "View current whitelist" -Description "See all allowed paths"
        Write-MenuOption -Key "5" -Label "Back to main menu"

        $choice = Read-Choice -Prompt "Enter choice [1-5]"

        switch ($choice) {
            "1" { Invoke-GamePresetWizard -Remove:$false }
            "2" { Invoke-CustomGameWizard }
            "3" { Invoke-GamePresetWizard -Remove:$true }
            "4" { Show-CurrentWhitelist }
            "5" { return }
            default {
                Write-Host "  Invalid choice." -ForegroundColor Red
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

function Invoke-GamePresetWizard {
    param ([switch]$Remove)

    $action = if ($Remove) { "REMOVE" } else { "ADD" }
    Write-Header "$action GAME PRESETS"

    Write-Host ""
    Write-Host "  Available game presets:" -ForegroundColor White
    Write-Host ""

    foreach ($key in $script:GamePresets.Keys) {
        $preset = $script:GamePresets[$key]
        Write-Host "  [$key] " -NoNewline -ForegroundColor Yellow
        Write-Host $preset.Name.PadRight(15) -NoNewline -ForegroundColor Cyan
        Write-Host $preset.Desc -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  [A] All presets" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Enter numbers separated by commas (e.g., 1,3,5)" -ForegroundColor DarkGray
    Write-Host "  Or enter 'A' for all presets" -ForegroundColor DarkGray

    $selection = Read-Choice -Prompt "Select games to $($action.ToLower())"

    if ([string]::IsNullOrWhiteSpace($selection)) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Parse selection
    $selectedPresets = @()
    if ($selection -match '^[Aa]') {
        $selectedPresets = $script:GamePresets.Keys | ForEach-Object { $script:GamePresets[$_].Name }
    } else {
        $numbers = $selection -split '[,\s]+' | Where-Object { $_ -match '^\d+$' }
        foreach ($num in $numbers) {
            if ($script:GamePresets.ContainsKey($num)) {
                $selectedPresets += $script:GamePresets[$num].Name
            }
        }
    }

    if ($selectedPresets.Count -eq 0) {
        Write-Host "  No valid selections." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Confirm
    Write-Host ""
    Write-Host "  Selected: $($selectedPresets -join ', ')" -ForegroundColor Cyan
    Write-Host ""

    if (!(Read-YesNo -Prompt "Proceed with $($action.ToLower())ing these games?")) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Apply
    Write-Host ""
    $whitelistScript = Join-Path $script:ScriptDir "Add-GameWhitelist.ps1"

    if (!(Test-Path $whitelistScript)) {
        Write-Host "  ERROR: Add-GameWhitelist.ps1 not found!" -ForegroundColor Red
        Press-AnyKey
        return
    }

    foreach ($preset in $selectedPresets) {
        Write-Host "  Processing: $preset..." -ForegroundColor Yellow
        if ($Remove) {
            & $whitelistScript -Preset $preset -Remove
        } else {
            & $whitelistScript -Preset $preset
        }
    }

    Write-Host ""
    Write-Host "  Done!" -ForegroundColor Green
    Press-AnyKey
}

function Invoke-CustomGameWizard {
    Write-Header "ADD CUSTOM GAME FOLDER"

    Write-Host ""
    Write-Host "  Enter the path to the game folder." -ForegroundColor White
    Write-Host ""
    Write-Host "  Examples:" -ForegroundColor DarkGray
    Write-Host "    D:\Games\MyGame" -ForegroundColor DarkGray
    Write-Host "    %USERPROFILE%\Games\CustomGame" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  Path: " -NoNewline -ForegroundColor White
    $customPath = Read-Host

    if ([string]::IsNullOrWhiteSpace($customPath)) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Expand and validate if absolute path
    $expandedPath = [Environment]::ExpandEnvironmentVariables($customPath)
    if ($expandedPath -match '^[A-Za-z]:' -and !(Test-Path $expandedPath)) {
        Write-Host ""
        Write-Host "  Warning: Path does not exist: $expandedPath" -ForegroundColor Yellow
        if (!(Read-YesNo -Prompt "Add anyway?")) {
            Write-Host "  Cancelled." -ForegroundColor Yellow
            Press-AnyKey
            return
        }
    }

    # Show what will be added
    Write-Host ""
    Write-Host "  The following rules will be added:" -ForegroundColor White
    Write-Host "    $customPath\*" -ForegroundColor Cyan
    Write-Host "    $customPath\*\*" -ForegroundColor Cyan
    Write-Host "    $customPath\*\*\*" -ForegroundColor Cyan
    Write-Host ""

    if (!(Read-YesNo -Prompt "Proceed?")) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Apply
    $whitelistScript = Join-Path $script:ScriptDir "Add-GameWhitelist.ps1"
    if (Test-Path $whitelistScript) {
        & $whitelistScript -CustomPath $customPath
        Write-Host ""
        Write-Host "  Done!" -ForegroundColor Green
    } else {
        Write-Host "  ERROR: Add-GameWhitelist.ps1 not found!" -ForegroundColor Red
    }

    Press-AnyKey
}

function Show-CurrentWhitelist {
    Write-Header "CURRENT WHITELIST"

    $allowPath = "$script:BasePath\262144\Paths"

    if (!(Test-Path $allowPath)) {
        Write-Host ""
        Write-Host "  No whitelist entries found." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    Write-Host ""
    Write-Host "  Allowed paths (executables can run here):" -ForegroundColor White
    Write-Host "  " + ("-" * 50) -ForegroundColor DarkGray
    Write-Host ""

    Get-ChildItem $allowPath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath
        $desc = if ($props.Description) { " ($($props.Description))" } else { "" }
        Write-Host "  • $($props.ItemData)" -ForegroundColor Cyan -NoNewline
        Write-Host $desc -ForegroundColor DarkGray
    }

    Press-AnyKey
}

# ═══════════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════════

function Show-MainMenu {
    while ($true) {
        Write-Header "WINDOWS PARENTAL CONTROLS"

        # Show current status inline
        $enabled = Test-SRPEnabled
        Write-Host ""
        Write-Host "  Status: " -NoNewline
        if ($enabled) {
            Write-Host "PROTECTED" -ForegroundColor Green -NoNewline
            Write-Host " ($(Get-BlockRuleCount) block rules, $(Get-AllowRuleCount) allow rules)" -ForegroundColor DarkGray
        } else {
            Write-Host "NOT PROTECTED" -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "  " + ("-" * 50) -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuOption -Key "1" -Label "Enable Protection" -Description "Block unauthorized apps (wizard)"
        Write-MenuOption -Key "2" -Label "Disable Protection" -Description "Remove all restrictions (wizard)"
        Write-MenuOption -Key "3" -Label "Manage Game Whitelist" -Description "Allow specific games"
        Write-MenuOption -Key "4" -Label "View Status" -Description "Detailed protection status"
        Write-MenuOption -Key "5" -Label "View Blocked Attempts" -Description "See what's been blocked"
        Write-MenuOption -Key "6" -Label "Exit"

        $choice = Read-Choice -Prompt "Enter choice [1-6]"

        switch ($choice) {
            "1" { Invoke-EnableWizard }
            "2" { Invoke-DisableWizard }
            "3" { Show-GameMenu }
            "4" { Show-Status }
            "5" { Show-BlockedAttempts }
            "6" {
                Write-Host ""
                Write-Host "  Goodbye!" -ForegroundColor Cyan
                return
            }
            default {
                Write-Host "  Invalid choice. Please enter 1-6." -ForegroundColor Red
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

Show-MainMenu
