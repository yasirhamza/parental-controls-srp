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
# PRESETS (synced with Add-GameWhitelist.ps1)
# ═══════════════════════════════════════════════════════════════════
$script:GamePresets = [ordered]@{
    "1" = @{ Name = "Minecraft"; Desc = "Java + Bedrock + mods" }
    "2" = @{ Name = "Roblox"; Desc = "Player and Studio" }
    "3" = @{ Name = "Steam"; Desc = "Steam client data" }
    "4" = @{ Name = "Epic"; Desc = "Epic + Fortnite data" }
    "5" = @{ Name = "Discord"; Desc = "Voice/text chat" }
    "6" = @{ Name = "Overwolf"; Desc = "Gaming overlay" }
    "7" = @{ Name = "CurseForge"; Desc = "Mod manager" }
}

$script:AppPresets = [ordered]@{
    "8"  = @{ Name = "Spotify"; Desc = "Music streaming" }
    "9"  = @{ Name = "Zoom"; Desc = "Video calls" }
    "10" = @{ Name = "WhatsApp"; Desc = "Messaging" }
    "11" = @{ Name = "Telegram"; Desc = "Messaging" }
    "12" = @{ Name = "VSCode"; Desc = "Code editor" }
    "13" = @{ Name = "GitHubDesktop"; Desc = "Git client" }
    "14" = @{ Name = "Slack"; Desc = "Team chat" }
    "15" = @{ Name = "Signal"; Desc = "Secure messaging" }
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
        Write-Header "MANAGE WHITELIST"

        if (!(Test-SRPEnabled)) {
            Write-Host ""
            Write-Host "  Protection is not enabled." -ForegroundColor Yellow
            Write-Host "  Enable protection first before managing whitelist." -ForegroundColor DarkGray
            Press-AnyKey
            return
        }

        Write-Host ""
        Write-MenuOption -Key "1" -Label "Add presets" -Description "Games & Apps (Minecraft, Spotify, etc.)"
        Write-MenuOption -Key "2" -Label "Add custom folder" -Description "Whitelist any path"
        Write-MenuOption -Key "3" -Label "Remove presets" -Description "Undo whitelisting"
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
    Write-Header "$action PRESETS"

    # Combine presets for lookup
    $allPresets = @{}
    foreach ($key in $script:GamePresets.Keys) { $allPresets[$key] = $script:GamePresets[$key] }
    foreach ($key in $script:AppPresets.Keys) { $allPresets[$key] = $script:AppPresets[$key] }

    Write-Host ""
    Write-Host "  GAMES:" -ForegroundColor White
    foreach ($key in $script:GamePresets.Keys) {
        $preset = $script:GamePresets[$key]
        Write-Host "  [$($key.PadLeft(2))] " -NoNewline -ForegroundColor Yellow
        Write-Host $preset.Name.PadRight(15) -NoNewline -ForegroundColor Green
        Write-Host $preset.Desc -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  APPS:" -ForegroundColor White
    foreach ($key in $script:AppPresets.Keys) {
        $preset = $script:AppPresets[$key]
        Write-Host "  [$($key.PadLeft(2))] " -NoNewline -ForegroundColor Yellow
        Write-Host $preset.Name.PadRight(15) -NoNewline -ForegroundColor Cyan
        Write-Host $preset.Desc -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  [G] All Games    [P] All Apps    [A] Everything" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Enter numbers separated by commas (e.g., 1,3,8,10)" -ForegroundColor DarkGray

    $selection = Read-Choice -Prompt "Select items to $($action.ToLower())"

    if ([string]::IsNullOrWhiteSpace($selection)) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Parse selection
    $selectedPresets = @()
    $batchPreset = $null

    if ($selection -match '^[Aa]$') {
        $batchPreset = "All"
        $selectedPresets = $allPresets.Keys | ForEach-Object { $allPresets[$_].Name }
    } elseif ($selection -match '^[Gg]$') {
        $batchPreset = "AllGames"
        $selectedPresets = $script:GamePresets.Keys | ForEach-Object { $script:GamePresets[$_].Name }
    } elseif ($selection -match '^[Pp]$') {
        $batchPreset = "AllApps"
        $selectedPresets = $script:AppPresets.Keys | ForEach-Object { $script:AppPresets[$_].Name }
    } else {
        $numbers = $selection -split '[,\s]+' | Where-Object { $_ -match '^\d+$' }
        foreach ($num in $numbers) {
            if ($allPresets.ContainsKey($num)) {
                $selectedPresets += $allPresets[$num].Name
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
    if ($selectedPresets.Count -le 5) {
        Write-Host "  Selected: $($selectedPresets -join ', ')" -ForegroundColor Cyan
    } else {
        Write-Host "  Selected: $($selectedPresets.Count) items" -ForegroundColor Cyan
    }
    Write-Host ""

    if (!(Read-YesNo -Prompt "Proceed with $($action.ToLower())ing these?")) {
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

    # Use batch preset if available for efficiency
    if ($batchPreset) {
        Write-Host "  Applying $batchPreset..." -ForegroundColor Yellow
        if ($Remove) {
            & $whitelistScript -Preset $batchPreset -Remove
        } else {
            & $whitelistScript -Preset $batchPreset
        }
    } else {
        foreach ($preset in $selectedPresets) {
            Write-Host "  Processing: $preset..." -ForegroundColor Yellow
            if ($Remove) {
                & $whitelistScript -Preset $preset -Remove
            } else {
                & $whitelistScript -Preset $preset
            }
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
# MONITORING MENU
# ═══════════════════════════════════════════════════════════════════

function Show-MonitoringMenu {
    while ($true) {
        Write-Header "EXECUTABLE MONITORING"

        if (!(Test-SRPEnabled)) {
            Write-Host ""
            Write-Host "  Protection is not enabled." -ForegroundColor Yellow
            Write-Host "  Enable protection first before using monitoring." -ForegroundColor DarkGray
            Press-AnyKey
            return
        }

        # Check baseline status
        $baselineFile = "C:\ParentalControl\Data\baseline.csv"
        $hasBaseline = Test-Path $baselineFile
        $baselineCount = 0
        if ($hasBaseline) {
            $baselineCount = (Import-Csv $baselineFile -ErrorAction SilentlyContinue | Measure-Object).Count
        }

        Write-Host ""
        Write-Host "  Baseline: " -NoNewline
        if ($hasBaseline) {
            Write-Host "$baselineCount known executables" -ForegroundColor Green
        } else {
            Write-Host "NOT SET (run Update Baseline first!)" -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "  " + ("-" * 50) -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuOption -Key "1" -Label "Scan Now" -Description "Check for new/unknown executables"
        Write-MenuOption -Key "2" -Label "Scan & Quarantine" -Description "Scan and move suspicious files"
        Write-MenuOption -Key "3" -Label "Update Baseline" -Description "Record current state as trusted"
        Write-MenuOption -Key "4" -Label "View Baseline" -Description "Show known executables"
        Write-MenuOption -Key "5" -Label "View Monitor Log" -Description "See recent alerts"
        Write-MenuOption -Key "6" -Label "Setup Scheduled Scan" -Description "Run automatically"
        Write-MenuOption -Key "7" -Label "Back to main menu"

        $choice = Read-Choice -Prompt "Enter choice [1-7]"

        $monitorScript = Join-Path $script:ScriptDir "ExeMonitor.ps1"

        switch ($choice) {
            "1" {
                if (!(Test-Path $monitorScript)) {
                    Write-Host "  ERROR: ExeMonitor.ps1 not found!" -ForegroundColor Red
                    Press-AnyKey
                    continue
                }
                if (!$hasBaseline) {
                    Write-Host ""
                    Write-Host "  No baseline set! Run 'Update Baseline' first." -ForegroundColor Yellow
                    Write-Host "  This records your current trusted executables." -ForegroundColor DarkGray
                    Press-AnyKey
                    continue
                }
                & $monitorScript -Scan
                Press-AnyKey
            }
            "2" {
                if (!(Test-Path $monitorScript)) {
                    Write-Host "  ERROR: ExeMonitor.ps1 not found!" -ForegroundColor Red
                    Press-AnyKey
                    continue
                }
                if (!$hasBaseline) {
                    Write-Host ""
                    Write-Host "  No baseline set! Run 'Update Baseline' first." -ForegroundColor Yellow
                    Press-AnyKey
                    continue
                }
                Write-Host ""
                Write-Host "  This will MOVE any new executables to quarantine." -ForegroundColor Yellow
                if (Read-YesNo -Prompt "Proceed with scan and quarantine?") {
                    & $monitorScript -Scan -Quarantine
                }
                Press-AnyKey
            }
            "3" {
                if (!(Test-Path $monitorScript)) {
                    Write-Host "  ERROR: ExeMonitor.ps1 not found!" -ForegroundColor Red
                    Press-AnyKey
                    continue
                }
                Write-Host ""
                Write-Host "  This will record all current executables in whitelisted" -ForegroundColor Yellow
                Write-Host "  folders as 'trusted'. Run this after installing games/apps." -ForegroundColor Yellow
                Write-Host ""
                if (Read-YesNo -Prompt "Update baseline now?") {
                    & $monitorScript -UpdateBaseline
                }
                Press-AnyKey
            }
            "4" {
                if (!(Test-Path $monitorScript)) {
                    Write-Host "  ERROR: ExeMonitor.ps1 not found!" -ForegroundColor Red
                    Press-AnyKey
                    continue
                }
                & $monitorScript -ShowBaseline
                Press-AnyKey
            }
            "5" {
                Show-MonitorLog
            }
            "6" {
                Invoke-SetupScheduledScan
            }
            "7" { return }
            default {
                Write-Host "  Invalid choice." -ForegroundColor Red
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

function Show-MonitorLog {
    Write-Header "MONITOR LOG"

    $logPath = "C:\ParentalControl\Logs\ExeMonitor.log"

    if (!(Test-Path $logPath)) {
        Write-Host ""
        Write-Host "  No monitor log found." -ForegroundColor Yellow
        Write-Host "  Logs are created when scans detect new executables." -ForegroundColor DarkGray
        Press-AnyKey
        return
    }

    Write-Host ""
    Write-Host "  Recent monitoring alerts (last 30 entries):" -ForegroundColor White
    Write-Host "  " + ("-" * 55) -ForegroundColor DarkGray
    Write-Host ""

    Get-Content $logPath -Tail 30 -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_ -match "\[ALERT\]") {
            Write-Host "  $_" -ForegroundColor Red
        } elseif ($_ -match "\[WARN\]") {
            Write-Host "  $_" -ForegroundColor Yellow
        } elseif ($_ -match "\[OK\]") {
            Write-Host "  $_" -ForegroundColor Green
        } else {
            Write-Host "  $_" -ForegroundColor White
        }
    }

    Write-Host ""
    Write-Host "  " + ("-" * 55) -ForegroundColor DarkGray
    Write-Host "  Log file: $logPath" -ForegroundColor DarkGray

    Press-AnyKey
}

function Invoke-SetupScheduledScan {
    Write-Header "SETUP SCHEDULED SCAN"

    Write-Host ""
    Write-Host "  This will create a Windows scheduled task to automatically" -ForegroundColor White
    Write-Host "  scan whitelisted folders for new executables." -ForegroundColor White
    Write-Host ""

    # Check if task already exists
    $taskName = "ParentalControl_ExeMonitor"
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

    if ($existingTask) {
        Write-Host "  Scheduled task already exists:" -ForegroundColor Yellow
        Write-Host "    Name: $taskName" -ForegroundColor Cyan
        Write-Host "    State: $($existingTask.State)" -ForegroundColor Cyan
        Write-Host ""

        if (Read-YesNo -Prompt "Remove existing task and recreate?" -Default $false) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Host "  Removed existing task." -ForegroundColor Green
        } else {
            Press-AnyKey
            return
        }
    }

    Write-Host ""
    Write-Host "  How often should the scan run?" -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] Every hour" -ForegroundColor Yellow
    Write-Host "  [2] Every 4 hours" -ForegroundColor Yellow
    Write-Host "  [3] Every 12 hours" -ForegroundColor Yellow
    Write-Host "  [4] Daily" -ForegroundColor Yellow
    Write-Host "  [5] Cancel" -ForegroundColor Yellow

    $freqChoice = Read-Choice -Prompt "Select frequency [1-5]"

    $interval = switch ($freqChoice) {
        "1" { New-TimeSpan -Hours 1 }
        "2" { New-TimeSpan -Hours 4 }
        "3" { New-TimeSpan -Hours 12 }
        "4" { New-TimeSpan -Days 1 }
        "5" { $null }
        default { $null }
    }

    if ($null -eq $interval) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        Press-AnyKey
        return
    }

    # Create the scheduled task
    $monitorScript = Join-Path $script:ScriptDir "ExeMonitor.ps1"

    if (!(Test-Path $monitorScript)) {
        Write-Host "  ERROR: ExeMonitor.ps1 not found!" -ForegroundColor Red
        Press-AnyKey
        return
    }

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monitorScript`" -Scan -Silent"

        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval $interval

        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -DontStopOnIdleEnd

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Description "Scans whitelisted folders for new executables" | Out-Null

        Write-Host ""
        Write-Host "  Scheduled task created successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "    Task: $taskName" -ForegroundColor Cyan
        Write-Host "    Runs as: SYSTEM (cannot be disabled by child)" -ForegroundColor Cyan
        Write-Host "    Frequency: Every $($interval.TotalHours) hour(s)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Alerts will be logged to:" -ForegroundColor White
        Write-Host "    C:\ParentalControl\Logs\ExeMonitor.log" -ForegroundColor Cyan

    } catch {
        Write-Host ""
        Write-Host "  ERROR: Failed to create scheduled task" -ForegroundColor Red
        Write-Host "  $_" -ForegroundColor Red
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
        Write-MenuOption -Key "3" -Label "Manage Whitelist" -Description "Allow games & apps"
        Write-MenuOption -Key "4" -Label "View Status" -Description "Detailed protection status"
        Write-MenuOption -Key "5" -Label "View Blocked Attempts" -Description "See what's been blocked"
        Write-MenuOption -Key "6" -Label "Monitoring" -Description "Detect unauthorized executables"
        Write-MenuOption -Key "7" -Label "Exit"

        $choice = Read-Choice -Prompt "Enter choice [1-7]"

        switch ($choice) {
            "1" { Invoke-EnableWizard }
            "2" { Invoke-DisableWizard }
            "3" { Show-GameMenu }
            "4" { Show-Status }
            "5" { Show-BlockedAttempts }
            "6" { Show-MonitoringMenu }
            "7" {
                Write-Host ""
                Write-Host "  Goodbye!" -ForegroundColor Cyan
                return
            }
            default {
                Write-Host "  Invalid choice. Please enter 1-7." -ForegroundColor Red
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

Show-MainMenu
