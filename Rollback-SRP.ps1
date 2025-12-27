#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Completely removes Software Restriction Policies and restores normal operation
.DESCRIPTION
    This script:
    1. Removes all SAFER/SRP registry keys
    2. Optionally restores from a backup
    3. Cleans up related settings
    4. Removes monitoring tasks (optional)
.PARAMETER RestoreFromBackup
    Path to a .reg backup file to restore instead of just deleting
.PARAMETER RemoveMonitoring
    Also remove the scheduled monitoring tasks
.PARAMETER KeepLogs
    Don't delete log files
.EXAMPLE
    .\Rollback-SRP.ps1
    # Removes all SRP configuration
.EXAMPLE
    .\Rollback-SRP.ps1 -RestoreFromBackup "C:\backup\SAFER_backup.reg"
    # Restores from a specific backup file
.EXAMPLE
    .\Rollback-SRP.ps1 -RemoveMonitoring -KeepLogs
    # Full removal but keeps log files for review
#>

param(
    [string]$RestoreFromBackup = "",
    [switch]$RemoveMonitoring,
    [switch]$KeepLogs,
    [switch]$WhatIf
)

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  SOFTWARE RESTRICTION POLICY - ROLLBACK SCRIPT                  ║
║  Removes all parental control SRP settings                      ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "`n[WHATIF MODE] No changes will be made`n" -ForegroundColor Yellow
}

# ═══════════════════════════════════════════════════════════════════
# STEP 1: Create safety backup before removal
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[1/5] Creating safety backup before removal..." -ForegroundColor Yellow

$SafetyBackup = "$env:TEMP\SAFER_pre_rollback_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"

if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer") {
    if (!$WhatIf) {
        reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer" $SafetyBackup /y 2>$null
    }
    Write-Host "    ✓ Safety backup created: $SafetyBackup" -ForegroundColor Green
} else {
    Write-Host "    ✓ No existing SRP configuration found" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════
# STEP 2: Remove or restore SAFER registry keys
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[2/5] Removing SRP registry configuration..." -ForegroundColor Yellow

$RegistryPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer",
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Safer"
)

if ($RestoreFromBackup -and (Test-Path $RestoreFromBackup)) {
    Write-Host "    Restoring from backup: $RestoreFromBackup" -ForegroundColor Cyan
    
    if (!$WhatIf) {
        # First remove existing
        foreach ($path in $RegistryPaths) {
            if (Test-Path $path) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        # Then restore
        reg import $RestoreFromBackup 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    ✓ Backup restored successfully" -ForegroundColor Green
        } else {
            Write-Host "    ⚠ Backup restore may have had issues" -ForegroundColor Yellow
        }
    }
} else {
    # Just remove everything
    foreach ($path in $RegistryPaths) {
        if (Test-Path $path) {
            if (!$WhatIf) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host "    ✓ Removed: $path" -ForegroundColor Green
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# STEP 3: Clean up Windows 11 22H2+ fix
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[3/5] Cleaning up Srp\Gp settings..." -ForegroundColor Yellow

$SrpGpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp"
if (Test-Path $SrpGpPath) {
    if (!$WhatIf) {
        Remove-ItemProperty -Path $SrpGpPath -Name "RuleCount" -ErrorAction SilentlyContinue
        # Remove key if empty
        $props = Get-ItemProperty -Path $SrpGpPath -ErrorAction SilentlyContinue
        if ($null -eq $props -or ($props.PSObject.Properties.Name | Where-Object { $_ -notmatch '^PS' }).Count -eq 0) {
            Remove-Item -Path $SrpGpPath -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "    ✓ Srp\Gp settings cleaned" -ForegroundColor Green
} else {
    Write-Host "    ✓ No Srp\Gp settings found" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════
# STEP 4: Remove scheduled monitoring tasks (optional)
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[4/5] Checking monitoring tasks..." -ForegroundColor Yellow

$TasksToRemove = @(
    "ParentalControl_ExeScanner",
    "ParentalControl_RealtimeMonitor"
)

if ($RemoveMonitoring) {
    foreach ($taskName in $TasksToRemove) {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            if (!$WhatIf) {
                Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }
            Write-Host "    ✓ Removed task: $taskName" -ForegroundColor Green
        }
    }
    
    # Clean up monitoring folders
    $FoldersToRemove = @(
        "C:\ParentalControl\Scripts",
        "C:\ParentalControl\Data",
        "C:\ParentalControl\Quarantine"
    )
    
    if (!$KeepLogs) {
        $FoldersToRemove += "C:\ParentalControl\Logs"
    }
    
    foreach ($folder in $FoldersToRemove) {
        if (Test-Path $folder) {
            if (!$WhatIf) {
                Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host "    ✓ Removed folder: $folder" -ForegroundColor Green
        }
    }
    
    # Remove parent folder if empty
    if ((Test-Path "C:\ParentalControl") -and !$WhatIf) {
        $remaining = Get-ChildItem "C:\ParentalControl" -ErrorAction SilentlyContinue
        if ($remaining.Count -eq 0) {
            Remove-Item "C:\ParentalControl" -Force -ErrorAction SilentlyContinue
        }
    }
} else {
    # Just report on tasks
    foreach ($taskName in $TasksToRemove) {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            Write-Host "    ⚠ Task exists: $taskName (use -RemoveMonitoring to remove)" -ForegroundColor Yellow
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# STEP 5: Apply changes and verify
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[5/5] Applying changes..." -ForegroundColor Yellow

if (!$WhatIf) {
    # Force group policy update
    gpupdate /force 2>$null
}

# Verify removal
$remainingConfig = $false
foreach ($path in $RegistryPaths) {
    if (Test-Path $path) {
        $remainingConfig = $true
        Write-Host "    ⚠ Warning: $path still exists" -ForegroundColor Yellow
    }
}

if (!$remainingConfig) {
    Write-Host "    ✓ All SRP configuration removed" -ForegroundColor Green
}

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n" + "═" * 68 -ForegroundColor Cyan
Write-Host "ROLLBACK COMPLETE" -ForegroundColor Green
Write-Host "═" * 68 -ForegroundColor Cyan

Write-Host @"

ACTIONS TAKEN:
  • SRP registry keys removed
  • Srp\Gp settings cleaned
  $(if ($RemoveMonitoring) { "• Monitoring tasks removed" } else { "• Monitoring tasks preserved (use -RemoveMonitoring to remove)" })
  $(if ($KeepLogs) { "• Log files preserved" } else { "" })

SAFETY BACKUP:
  $SafetyBackup

TO RE-ENABLE RESTRICTIONS:
  Run: .\Enable-SRP-Complete.ps1

NEXT STEPS:
  1. RESTART the computer for changes to take full effect
  2. Test that applications now run normally from user folders

"@ -ForegroundColor White

if (!$WhatIf) {
    Write-Host "⚠️  RESTART RECOMMENDED for complete rollback!" -ForegroundColor Yellow
}

# ═══════════════════════════════════════════════════════════════════
# OPTIONAL: Quick verification function
# ═══════════════════════════════════════════════════════════════════

function Test-SRPRemoval {
    Write-Host "`nVerifying SRP removal..." -ForegroundColor Cyan
    
    $issues = @()
    
    # Check registry
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers") {
        $issues += "HKLM Safer key still exists"
    }
    
    # Check Srp\Gp
    $srpGp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp" -Name "RuleCount" -ErrorAction SilentlyContinue
    if ($srpGp) {
        $issues += "Srp\Gp RuleCount still set"
    }
    
    if ($issues.Count -eq 0) {
        Write-Host "✓ All clear - SRP completely removed" -ForegroundColor Green
    } else {
        Write-Host "⚠ Issues found:" -ForegroundColor Yellow
        $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
}

# Run verification
if (!$WhatIf) {
    Test-SRPRemoval
}
