#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitors whitelisted folders for new/unknown executables
.DESCRIPTION
    Scans whitelisted paths and detects executables that weren't in the baseline.
    Can quarantine suspicious files and alert parents.
.PARAMETER Scan
    Run a scan now and report findings
.PARAMETER UpdateBaseline
    Update the baseline with current executables (run after installing legitimate apps).
    By default, performs incremental update (only files modified since last update).
.PARAMETER Full
    When used with -UpdateBaseline, forces a full rescan of all whitelisted paths.
    Use this to rebuild the baseline from scratch.
.PARAMETER Quarantine
    Move detected executables to quarantine folder
.PARAMETER ShowBaseline
    Display current baseline
.PARAMETER ConvertAndEnrichSaferLog
    Convert SAFER.log from UTF-16 LE to UTF-8 and enrich each entry with
    timestamp and file hashes (SHA-256, SHA-1) for SIEM ingestion.
.PARAMETER ExportCDB
    Export baseline.csv to Wazuh CDB list format (srp_baseline.cdb) for
    syncing with Wazuh Manager. Outputs to C:\ParentalControl\Data\.
.EXAMPLE
    .\ExeMonitor.ps1 -Scan
.EXAMPLE
    .\ExeMonitor.ps1 -UpdateBaseline
.EXAMPLE
    .\ExeMonitor.ps1 -UpdateBaseline -Full
.EXAMPLE
    .\ExeMonitor.ps1 -ConvertAndEnrichSaferLog
.EXAMPLE
    .\ExeMonitor.ps1 -ExportCDB
#>

param(
    [switch]$Scan,
    [switch]$UpdateBaseline,
    [switch]$Full,
    [switch]$Quarantine,
    [switch]$ShowBaseline,
    [switch]$ConvertAndEnrichSaferLog,
    [switch]$ExportCDB,
    [switch]$Silent
)

$script:DataDir = "C:\ParentalControl\Data"
$script:LogDir = "C:\ParentalControl\Logs"
$script:QuarantineDir = "C:\ParentalControl\Quarantine"
$script:BaselineFile = "$script:DataDir\baseline.csv"
$script:BaselineCDB = "$script:DataDir\srp_baseline.cdb"
$script:AlertLog = "$script:LogDir\ExeMonitor.log"
$script:SaferLog = "$script:LogDir\SAFER.log"
$script:SaferLogUtf8 = "$script:LogDir\SAFER-utf8.log"
$script:BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"

# Executable extensions to monitor
$script:ExeExtensions = @('.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js', '.wsf', '.ps1')

# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

function Convert-AndEnrichSaferLog {
    <#
    .SYNOPSIS
        Converts SAFER.log from UTF-16 LE to UTF-8 and enriches with hashes
    .DESCRIPTION
        Only appends NEW lines to the UTF-8 file to preserve file position
        for log collectors like Wazuh agent that track file offsets.
        Adds timestamp and file hashes (SHA-256, SHA-1) to each line.
    #>
    if (!(Test-Path $script:SaferLog)) {
        if (!$Silent) {
            Write-Host "  SAFER.log not found at: $script:SaferLog" -ForegroundColor Yellow
        }
        return $false
    }

    try {
        # Read source as UTF-16 LE (Unicode)
        $sourceLines = @(Get-Content -Path $script:SaferLog -Encoding Unicode -ErrorAction Stop)

        # Get existing line count in UTF-8 file (if exists)
        $existingLineCount = 0
        if (Test-Path $script:SaferLogUtf8) {
            $existingLines = @(Get-Content -Path $script:SaferLogUtf8 -ErrorAction SilentlyContinue)
            $existingLineCount = $existingLines.Count
        }

        # Only process new lines (skip already converted)
        if ($sourceLines.Count -gt $existingLineCount) {
            $newLines = $sourceLines | Select-Object -Skip $existingLineCount
            $newCount = @($newLines).Count

            if ($newCount -gt 0) {
                $processedLines = @()

                foreach ($line in $newLines) {
                    if ($line -match 'identified (.+?) as ') {
                        $targetPath = $Matches[1]
                        $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"

                        # Compute hashes if file exists
                        $sha256 = ""
                        $sha1 = ""
                        if (Test-Path $targetPath -ErrorAction SilentlyContinue) {
                            $sha256 = (Get-FileHash $targetPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            $sha1 = (Get-FileHash $targetPath -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
                        }

                        # Append enrichment data: |timestamp|SHA256:hash|SHA1:hash
                        $enrichedLine = "$line|$timestamp|SHA256:$sha256|SHA1:$sha1"
                        $processedLines += $enrichedLine
                    } else {
                        $processedLines += $line
                    }
                }

                # Append processed lines (preserves file position for log collectors)
                $processedLines | Out-File -FilePath $script:SaferLogUtf8 -Encoding UTF8 -Append

                if (!$Silent) {
                    Write-Host "  Appended $newCount new lines (enriched with hashes)" -ForegroundColor Green
                    Write-Host "  Total lines: $($existingLineCount + $newCount)" -ForegroundColor Cyan
                    Write-Host "  Output: $script:SaferLogUtf8" -ForegroundColor Cyan
                }
            }
        } else {
            if (!$Silent) {
                Write-Host "  No new lines to convert (UTF-8 has $existingLineCount lines)" -ForegroundColor DarkGray
            }
        }
        return $true
    }
    catch {
        if (!$Silent) {
            Write-Host "  Error converting log: $_" -ForegroundColor Red
        }
        return $false
    }
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Ensure log directory exists
    if (!(Test-Path $script:LogDir)) {
        New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    }

    Add-Content -Path $script:AlertLog -Value $logEntry -ErrorAction SilentlyContinue

    if (!$Silent) {
        switch ($Level) {
            "ALERT" { Write-Host "  ! $Message" -ForegroundColor Red }
            "WARN"  { Write-Host "  ? $Message" -ForegroundColor Yellow }
            "OK"    { Write-Host "  + $Message" -ForegroundColor Green }
            default { Write-Host "  $Message" -ForegroundColor White }
        }
    }
}

function Get-WhitelistedPaths {
    <#
    .SYNOPSIS
        Gets all whitelisted paths from the registry
    #>
    $paths = @()

    if (!(Test-Path $script:BasePath)) {
        return $paths
    }

    Get-ChildItem $script:BasePath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath
        $path = $props.ItemData

        # Expand environment variables
        $expandedPath = [Environment]::ExpandEnvironmentVariables($path)

        # Remove wildcards to get the base folder
        $basePath = $expandedPath -replace '\\\*.*$', ''

        if ($basePath -and (Test-Path $basePath -ErrorAction SilentlyContinue)) {
            $paths += $basePath
        }
    }

    return $paths | Select-Object -Unique
}

function Get-ExecutablesInPath {
    param (
        [string]$Path,
        [datetime]$ModifiedSince = [datetime]::MinValue
    )

    $executables = @()

    if (!(Test-Path $Path)) {
        return $executables
    }

    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $script:ExeExtensions -contains $_.Extension.ToLower() -and
            $_.LastWriteTime -gt $ModifiedSince
        } |
        ForEach-Object {
            $sha256 = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $sha1 = (Get-FileHash $_.FullName -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
            $executables += [PSCustomObject]@{
                Path = $_.FullName
                Name = $_.Name
                SHA256 = $sha256
                SHA1 = $sha1
                Size = $_.Length
                Created = $_.CreationTime
                Modified = $_.LastWriteTime
            }
        }

    return $executables
}

function Initialize-Directories {
    @($script:DataDir, $script:LogDir, $script:QuarantineDir) | ForEach-Object {
        if (!(Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# BASELINE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

function Update-Baseline {
    param ([switch]$FullMode)

    Initialize-Directories

    $whitelistedPaths = Get-WhitelistedPaths

    if ($whitelistedPaths.Count -eq 0) {
        Write-Host "  No whitelisted paths found." -ForegroundColor Yellow
        return
    }

    # Determine if we can do incremental update (default) or full rescan
    $modifiedSince = $null
    $existingBaseline = @{}
    $doIncremental = $false

    if (-not $FullMode) {
        if (Test-Path $script:BaselineFile) {
            try {
                $baselineInfo = Get-Item $script:BaselineFile -Force -ErrorAction Stop
                $modifiedSince = $baselineInfo.LastWriteTime

                # Load existing baseline into hashtable keyed by path
                Get-Baseline | ForEach-Object {
                    if ($_.Path) {
                        $existingBaseline[$_.Path] = $_
                    }
                }

                if ($existingBaseline.Count -gt 0) {
                    $doIncremental = $true
                    Write-Host "`n  Incremental update (files modified since $($modifiedSince.ToString('yyyy-MM-dd HH:mm:ss')))..." -ForegroundColor Yellow
                    Write-Host "  Existing baseline: $($existingBaseline.Count) executables" -ForegroundColor DarkGray
                } else {
                    Write-Host "`n  Existing baseline is empty - performing full scan..." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "`n  Cannot read baseline file - performing full scan..." -ForegroundColor Yellow
            }
        } else {
            Write-Host "`n  No existing baseline - performing full scan..." -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n  Full baseline rescan..." -ForegroundColor Yellow
    }

    Write-Host "  Scanning $($whitelistedPaths.Count) whitelisted locations..." -ForegroundColor White

    $newExecutables = @()
    $updatedCount = 0
    $addedCount = 0

    foreach ($path in $whitelistedPaths) {
        Write-Host "    Scanning: $path" -ForegroundColor DarkGray
        if ($doIncremental -and $modifiedSince) {
            $exes = Get-ExecutablesInPath -Path $path -ModifiedSince $modifiedSince
        } else {
            $exes = Get-ExecutablesInPath -Path $path
        }
        $newExecutables += $exes
    }

    if ($doIncremental) {
        # Merge: update existing entries or add new ones
        foreach ($exe in $newExecutables) {
            if (-not $exe.Path) { continue }  # Skip entries with null path
            if ($existingBaseline.ContainsKey($exe.Path)) {
                $existingBaseline[$exe.Path] = $exe
                $updatedCount++
            } else {
                $existingBaseline[$exe.Path] = $exe
                $addedCount++
            }
        }

        # Write merged baseline
        $mergedBaseline = $existingBaseline.Values | Sort-Object Path
        $mergedBaseline | Export-Csv -Path $script:BaselineFile -NoTypeInformation -Force

        Write-Host "`n  Incremental update complete:" -ForegroundColor Green
        Write-Host "    Updated: $updatedCount" -ForegroundColor Cyan
        Write-Host "    Added:   $addedCount" -ForegroundColor Cyan
        Write-Host "    Total:   $($mergedBaseline.Count)" -ForegroundColor Green
        Write-Log "Incremental baseline update: $updatedCount updated, $addedCount added, $($mergedBaseline.Count) total" -Level "OK"
    } else {
        # Full replacement
        if ($newExecutables.Count -gt 0) {
            $newExecutables | Export-Csv -Path $script:BaselineFile -NoTypeInformation -Force
            Write-Host "`n  Baseline updated: $($newExecutables.Count) executables recorded" -ForegroundColor Green
            Write-Log "Baseline updated with $($newExecutables.Count) executables" -Level "OK"
        } else {
            Write-Host "`n  No executables found in whitelisted paths" -ForegroundColor Yellow
        }
    }
}

function Get-Baseline {
    if (!(Test-Path $script:BaselineFile)) {
        return @()
    }

    return Import-Csv $script:BaselineFile
}

function Show-Baseline {
    $baseline = Get-Baseline

    if ($baseline.Count -eq 0) {
        Write-Host "`n  No baseline exists. Run with -UpdateBaseline first." -ForegroundColor Yellow
        return
    }

    Write-Host "`n  Baseline: $($baseline.Count) known executables" -ForegroundColor Cyan
    Write-Host "  " + ("-" * 50) -ForegroundColor DarkGray

    $baseline | Group-Object { Split-Path (Split-Path $_.Path -Parent) -Leaf } | ForEach-Object {
        Write-Host "`n  [$($_.Name)] - $($_.Count) files" -ForegroundColor White
        $_.Group | Select-Object -First 5 | ForEach-Object {
            Write-Host "    $($_.Name)" -ForegroundColor DarkGray
        }
        if ($_.Count -gt 5) {
            Write-Host "    ... and $($_.Count - 5) more" -ForegroundColor DarkGray
        }
    }
}

function Export-BaselineToCDB {
    <#
    .SYNOPSIS
        Exports baseline.csv to Wazuh CDB list format for SIEM baseline sync
    .DESCRIPTION
        Converts baseline paths to CDB format: "C:\path\to\file.exe":
        Also outputs structured log entries for Wazuh agent collection.
    #>
    $baseline = Get-Baseline

    if ($baseline.Count -eq 0) {
        if (!$Silent) {
            Write-Host "`n  No baseline exists. Run with -UpdateBaseline first." -ForegroundColor Yellow
        }
        return $false
    }

    Initialize-Directories

    try {
        # Generate CDB format file
        $cdbContent = @()
        foreach ($item in $baseline) {
            # CDB format: "path": (quoted path with trailing colon)
            $cdbEntry = "`"$($item.Path)`":"
            $cdbContent += $cdbEntry
        }

        # Write CDB file (UTF-8 without BOM for Wazuh compatibility)
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllLines($script:BaselineCDB, $cdbContent, $utf8NoBom)

        if (!$Silent) {
            Write-Host "`n  Exported $($baseline.Count) entries to CDB format" -ForegroundColor Green
            Write-Host "  Output: $script:BaselineCDB" -ForegroundColor Cyan
        }

        # Also log a sync event for Wazuh agent to pick up
        $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        $syncLog = "$script:LogDir\baseline-sync.log"
        $syncEntry = "BASELINE_SYNC|$timestamp|entries:$($baseline.Count)|file:$script:BaselineCDB"
        Add-Content -Path $syncLog -Value $syncEntry -Encoding UTF8

        Write-Log "Exported $($baseline.Count) baseline entries to CDB format" -Level "OK"
        return $true
    }
    catch {
        if (!$Silent) {
            Write-Host "  Error exporting CDB: $_" -ForegroundColor Red
        }
        return $false
    }
}

# ═══════════════════════════════════════════════════════════════════
# SCANNING
# ═══════════════════════════════════════════════════════════════════

function Invoke-Scan {
    param ([switch]$QuarantineNew)

    Initialize-Directories

    $baseline = Get-Baseline
    $baselineHashes = @{}
    $baselinePaths = @{}

    foreach ($item in $baseline) {
        # Support both old "Hash" field and new "SHA256" field for backwards compatibility
        $hash = if ($item.SHA256) { $item.SHA256 } else { $item.Hash }
        if ($hash) { $baselineHashes[$hash] = $item }
        if ($item.Path) { $baselinePaths[$item.Path] = $item }
    }

    $whitelistedPaths = Get-WhitelistedPaths

    if ($whitelistedPaths.Count -eq 0) {
        if (!$Silent) {
            Write-Host "`n  No whitelisted paths to scan." -ForegroundColor Yellow
        }
        return @()
    }

    if (!$Silent) {
        Write-Host "`n  Scanning $($whitelistedPaths.Count) whitelisted locations..." -ForegroundColor Yellow
    }

    $newExecutables = @()
    $knownCount = 0

    foreach ($path in $whitelistedPaths) {
        $exes = Get-ExecutablesInPath -Path $path

        foreach ($exe in $exes) {
            $isKnown = $false

            # Check by SHA256 hash first (most reliable)
            if ($exe.SHA256 -and $baselineHashes.ContainsKey($exe.SHA256)) {
                $isKnown = $true
            }
            # Fall back to path check
            elseif ($baselinePaths.ContainsKey($exe.Path)) {
                # Path exists but hash changed - suspicious!
                $baselineItem = $baselinePaths[$exe.Path]
                $oldHash = if ($baselineItem.SHA256) { $baselineItem.SHA256 } else { $baselineItem.Hash }
                if ($oldHash -ne $exe.SHA256) {
                    $exe | Add-Member -NotePropertyName "Reason" -NotePropertyValue "MODIFIED (hash changed)" -Force
                    $newExecutables += $exe
                    continue
                }
                $isKnown = $true
            }

            if ($isKnown) {
                $knownCount++
            } else {
                $exe | Add-Member -NotePropertyName "Reason" -NotePropertyValue "NEW (not in baseline)" -Force
                $newExecutables += $exe
            }
        }
    }

    # Report results
    if (!$Silent) {
        Write-Host "`n  Results:" -ForegroundColor White
        Write-Host "    Known executables: $knownCount" -ForegroundColor Green
        Write-Host "    New/Modified:      $($newExecutables.Count)" -ForegroundColor $(if ($newExecutables.Count -gt 0) { "Red" } else { "Green" })
    }

    # Handle new executables
    if ($newExecutables.Count -gt 0) {
        Write-Log "SCAN ALERT: Found $($newExecutables.Count) new/modified executables" -Level "ALERT"

        foreach ($exe in $newExecutables) {
            Write-Log "  $($exe.Reason): $($exe.Path) [SHA256:$($exe.SHA256)] [SHA1:$($exe.SHA1)]" -Level "ALERT"

            if (!$Silent) {
                Write-Host "`n  ALERT: $($exe.Reason)" -ForegroundColor Red
                Write-Host "    File: $($exe.Name)" -ForegroundColor White
                Write-Host "    Path: $($exe.Path)" -ForegroundColor DarkGray
                Write-Host "    SHA256: $($exe.SHA256)" -ForegroundColor DarkGray
                Write-Host "    SHA1: $($exe.SHA1)" -ForegroundColor DarkGray
                Write-Host "    Size: $([math]::Round($exe.Size / 1KB, 2)) KB" -ForegroundColor DarkGray
                Write-Host "    Created: $($exe.Created)" -ForegroundColor DarkGray
            }

            # Quarantine if requested
            if ($QuarantineNew) {
                $quarantinePath = Join-Path $script:QuarantineDir "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($exe.Name)"
                try {
                    Move-Item -Path $exe.Path -Destination $quarantinePath -Force
                    Write-Log "Quarantined: $($exe.Path) -> $quarantinePath" -Level "WARN"
                    if (!$Silent) {
                        Write-Host "    QUARANTINED -> $quarantinePath" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Log "Failed to quarantine: $($exe.Path) - $_" -Level "ALERT"
                    if (!$Silent) {
                        Write-Host "    Failed to quarantine: $_" -ForegroundColor Red
                    }
                }
            }
        }
    } else {
        Write-Log "Scan complete: No new executables detected" -Level "OK"
    }

    return $newExecutables
}

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

if (!$Silent) {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  EXECUTABLE MONITOR                                              ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

# Handle log conversion (doesn't require SRP)
if ($ConvertAndEnrichSaferLog) {
    if (!$Silent) {
        Write-Host "`n  Converting and enriching SAFER.log..." -ForegroundColor Yellow
    }
    $result = Convert-AndEnrichSaferLog
    exit $(if ($result) { 0 } else { 1 })
}

# Check if SRP is configured
$allowPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"
if (!(Test-Path $allowPath)) {
    Write-Host "`n  SRP not configured. Run Enable-SRP-Complete.ps1 first." -ForegroundColor Red
    exit 1
}

if ($ShowBaseline) {
    Show-Baseline
    exit 0
}

if ($ExportCDB) {
    if (!$Silent) {
        Write-Host "`n  Exporting baseline to CDB format..." -ForegroundColor Yellow
    }
    $result = Export-BaselineToCDB
    exit $(if ($result) { 0 } else { 1 })
}

if ($UpdateBaseline) {
    Update-Baseline -FullMode:$Full
    exit 0
}

if ($Scan) {
    $results = Invoke-Scan -QuarantineNew:$Quarantine

    # Convert SAFER.log to UTF-8 after each scan
    Convert-AndEnrichSaferLog | Out-Null

    if (!$Silent) {
        Write-Host ""
        if ($results.Count -eq 0) {
            Write-Host "  All clear - no suspicious executables found." -ForegroundColor Green
        } else {
            Write-Host "  Review the alerts above. Consider:" -ForegroundColor Yellow
            Write-Host "    - If legitimate: run -UpdateBaseline to add to known list" -ForegroundColor DarkGray
            Write-Host "    - If suspicious: run -Scan -Quarantine to move files" -ForegroundColor DarkGray
        }
    }

    exit $results.Count
}

# Show usage
Write-Host @"

USAGE:
  .\ExeMonitor.ps1 -Scan                       Scan for new executables
  .\ExeMonitor.ps1 -Scan -Quarantine           Scan and quarantine new files
  .\ExeMonitor.ps1 -UpdateBaseline             Incremental update (default, fast)
  .\ExeMonitor.ps1 -UpdateBaseline -Full       Full rescan of all whitelisted paths
  .\ExeMonitor.ps1 -ShowBaseline               Show known executables
  .\ExeMonitor.ps1 -ConvertAndEnrichSaferLog   Convert to UTF-8 + add hashes/timestamps
  .\ExeMonitor.ps1 -ExportCDB                  Export baseline to Wazuh CDB format

WORKFLOW:
  1. After whitelisting games/apps, run -UpdateBaseline
  2. Periodically run -Scan to check for new executables
  3. If alerts appear:
     - Legitimate app? Run -UpdateBaseline (fast incremental)
     - Suspicious? Run -Scan -Quarantine
  4. To rebuild baseline from scratch: -UpdateBaseline -Full

SIEM INTEGRATION:
  -ConvertAndEnrichSaferLog produces enriched logs for Wazuh
  -ExportCDB exports baseline to C:\ParentalControl\Data\srp_baseline.cdb

  Sync baseline to Wazuh Manager via agent file collection or scheduled task.

"@ -ForegroundColor White
