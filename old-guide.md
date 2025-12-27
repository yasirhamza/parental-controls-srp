# Windows Home parental controls without Group Policy

**Software Restriction Policies (SRP) work on all Windows editions—including Home—through direct registry configuration**, eliminating the need for the missing Group Policy Editor. Combined with automated monitoring scripts, parents can effectively prevent children from installing unauthorized applications to their user profile while detecting evasion attempts in real-time. This guide provides complete PowerShell scripts, registry configurations, and Task Scheduler setups that run under SYSTEM privileges to prevent tampering by the child.

## Part 1: Blocking executables via registry-based SRP

The Windows SAFER subsystem (the engine behind Software Restriction Policies) has existed since Windows XP and operates entirely through registry entries. The Group Policy Editor merely provides a GUI for these same registry keys—meaning Windows Home users can configure identical protection through PowerShell or .reg files.

### Critical fix required for Windows 11 22H2+

Microsoft introduced a breaking change in Windows 11 22H2 that disables SAFER by default due to residual AppLocker registry entries. **This must be fixed first** or all subsequent rules will be silently ignored:

```powershell
# Run as Administrator - Required for Windows 11 22H2 and later
$SrpGpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp"
if (!(Test-Path $SrpGpPath)) {
    New-Item -Path $SrpGpPath -Force | Out-Null
}
Set-ItemProperty -Path $SrpGpPath -Name "RuleCount" -Value 0 -Type DWord -Force
```

### Complete implementation script

The following PowerShell script configures SRP to block executables from user profile directories while whitelisting legitimate applications. Save this as `Enable-SRP-ParentalControls.ps1` and run as Administrator:

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Implements Software Restriction Policies to block unauthorized executables
    from user profile directories for parental controls on Windows Home
.NOTES
    Child's account MUST be a Standard User (not Administrator)
    Restart required after running for full enforcement
#>

# ===== WINDOWS 11 22H2+ FIX =====
$SrpGpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp"
if (!(Test-Path $SrpGpPath)) { New-Item -Path $SrpGpPath -Force | Out-Null }
Set-ItemProperty -Path $SrpGpPath -Name "RuleCount" -Value 0 -Type DWord -Force

# ===== BASE CONFIGURATION =====
$BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"

# Clear existing configuration and create backup
if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer") {
    reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer" "$env:TEMP\SAFER_backup.reg" /y
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer" -Recurse -Force
}

# Create registry structure
New-Item -Path $BasePath -Force | Out-Null
New-Item -Path "$BasePath\0\Paths" -Force | Out-Null      # Disallowed rules
New-Item -Path "$BasePath\262144\Paths" -Force | Out-Null # Unrestricted rules

# Configure policy settings
Set-ItemProperty -Path $BasePath -Name "AuthenticodeEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path $BasePath -Name "DefaultLevel" -Value 262144 -Type DWord  # Default: Allow
Set-ItemProperty -Path $BasePath -Name "TransparentEnabled" -Value 1 -Type DWord # Enforce on EXE only
Set-ItemProperty -Path $BasePath -Name "PolicyScope" -Value 1 -Type DWord        # Non-admins only
Set-ItemProperty -Path $BasePath -Name "Levels" -Value 0x00071000 -Type DWord

# Enable logging
Set-ItemProperty -Path $BasePath -Name "LogFileName" -Value "C:\Users\Public\Documents\SAFER.log"

# ===== HELPER FUNCTIONS =====
function Add-BlockedPath {
    param ([string]$Path, [string]$Description = "")
    $guid = "{" + [System.Guid]::NewGuid().ToString() + "}"
    $keyPath = "$BasePath\0\Paths\$guid"
    New-Item -Path $keyPath -Force | Out-Null
    Set-ItemProperty -Path $keyPath -Name "ItemData" -Value $Path -Type ExpandString
    Set-ItemProperty -Path $keyPath -Name "SaferFlags" -Value 0 -Type DWord
    Write-Host "BLOCKED: $Path" -ForegroundColor Red
}

function Add-AllowedPath {
    param ([string]$Path, [string]$Description = "")
    $guid = "{" + [System.Guid]::NewGuid().ToString() + "}"
    $keyPath = "$BasePath\262144\Paths\$guid"
    New-Item -Path $keyPath -Force | Out-Null
    Set-ItemProperty -Path $keyPath -Name "ItemData" -Value $Path -Type ExpandString
    Set-ItemProperty -Path $keyPath -Name "SaferFlags" -Value 0 -Type DWord
    Write-Host "ALLOWED: $Path" -ForegroundColor Green
}

# ===== SYSTEM DIRECTORIES (ALLOW) =====
Write-Host "`n=== Allowing System Directories ===" -ForegroundColor Cyan
Add-AllowedPath -Path "C:\Windows\"
Add-AllowedPath -Path "C:\Program Files\"
Add-AllowedPath -Path "C:\Program Files (x86)\"
Add-AllowedPath -Path "C:\ProgramData\Microsoft\Windows Defender\"

# ===== USER DIRECTORIES (BLOCK) =====
Write-Host "`n=== Blocking User Profile Directories ===" -ForegroundColor Cyan

# Block AppData (Roaming) - where many user-installed apps live
Add-BlockedPath -Path "%APPDATA%"
Add-BlockedPath -Path "%APPDATA%\*"
Add-BlockedPath -Path "%APPDATA%\*\*"
Add-BlockedPath -Path "%APPDATA%\*\*\*"

# Block LocalAppData - where Chrome installs when run as standard user
Add-BlockedPath -Path "%LOCALAPPDATA%"
Add-BlockedPath -Path "%LOCALAPPDATA%\*"
Add-BlockedPath -Path "%LOCALAPPDATA%\*\*"
Add-BlockedPath -Path "%LOCALAPPDATA%\*\*\*"

# Block Downloads folder
Add-BlockedPath -Path "%USERPROFILE%\Downloads"
Add-BlockedPath -Path "%USERPROFILE%\Downloads\*"
Add-BlockedPath -Path "%USERPROFILE%\Downloads\*\*"

# Block Temp directories (common malware/bypass location)
Add-BlockedPath -Path "%TEMP%"
Add-BlockedPath -Path "%TEMP%\*"
Add-BlockedPath -Path "%TMP%"

# Block Desktop executables
Add-BlockedPath -Path "%USERPROFILE%\Desktop"
Add-BlockedPath -Path "%USERPROFILE%\Desktop\*"

# ===== WHITELIST LEGITIMATE APPLICATIONS =====
Write-Host "`n=== Whitelisting Approved Applications ===" -ForegroundColor Cyan

# Microsoft applications that install to AppData
Add-AllowedPath -Path "%LOCALAPPDATA%\Microsoft\OneDrive\"
Add-AllowedPath -Path "%LOCALAPPDATA%\Microsoft\Teams\"
Add-AllowedPath -Path "%LOCALAPPDATA%\Microsoft\EdgeWebView\"
Add-AllowedPath -Path "%LOCALAPPDATA%\Packages\MSTeams_*\"

# Add other approved apps as needed (uncomment as required)
# Add-AllowedPath -Path "%LOCALAPPDATA%\Discord\"
# Add-AllowedPath -Path "%APPDATA%\Zoom\"
Add-AllowedPath -Path "%APPDATA%\Spotify\"

Write-Host "`n=== Configuration Complete ===" -ForegroundColor Green
Write-Host "Log file: C:\Users\Public\Documents\SAFER.log"
Write-Host "Backup saved: $env:TEMP\SAFER_backup.reg"
Write-Host "`nRESTART REQUIRED for full enforcement" -ForegroundColor Yellow
gpupdate /force
```

### Understanding SAFER security levels

| Level Value | Name         | Effect                                                                     |
| ----------- | ------------ | -------------------------------------------------------------------------- |
| **0**       | Disallowed   | Executable blocked from running                                            |
| **262144**  | Unrestricted | Executable runs normally                                                   |
| **131072**  | Basic User   | Runs with restricted rights (effectively same as Disallowed on Windows 7+) |

The **PolicyScope value of 1** is critical—it means restrictions apply only to non-administrators, allowing parents (with admin accounts) to run any software while blocking the child's Standard User account.

### Adding new whitelist exceptions

When legitimate software needs to run from AppData, use this function to add exceptions:

```powershell
function Add-SRPException {
    param ([Parameter(Mandatory)][string]$Path)
    $BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"
    $guid = "{" + [System.Guid]::NewGuid().ToString() + "}"
    New-Item -Path "$BasePath\$guid" -Force | Out-Null
    Set-ItemProperty -Path "$BasePath\$guid" -Name "ItemData" -Value $Path -Type ExpandString
    Set-ItemProperty -Path "$BasePath\$guid" -Name "SaferFlags" -Value 0 -Type DWord
    Write-Host "Exception added: $Path" -ForegroundColor Green
}

# Examples:
# Add-SRPException -Path "%LOCALAPPDATA%\Discord\"
# Add-SRPException -Path "%APPDATA%\Spotify\"
```

### Common applications requiring whitelisting

| Application            | Whitelist Path                               |
| ---------------------- | -------------------------------------------- |
| Microsoft OneDrive     | `%LOCALAPPDATA%\Microsoft\OneDrive\`         |
| Microsoft Teams        | `%LOCALAPPDATA%\Microsoft\Teams\`            |
| Discord                | `%LOCALAPPDATA%\Discord\`                    |
| Slack                  | `%LOCALAPPDATA%\slack\`                      |
| Spotify                | `%APPDATA%\Spotify\`                         |
| Zoom                   | `%APPDATA%\Zoom\` and `%LOCALAPPDATA%\Zoom\` |
| VS Code (user install) | `%LOCALAPPDATA%\Programs\Microsoft VS Code\` |

### Verifying and troubleshooting SRP

Check the SAFER log file to see blocked execution attempts:

```powershell
# View all blocked attempts
Get-Content "C:\Users\Public\Documents\SAFER.log" | Where-Object { $_ -match "Disallowed" }

# Check Windows Event Log for SRP events (Event IDs 865-868, 882)
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Microsoft-Windows-SoftwareRestrictionPolicies'} -MaxEvents 20
```

To temporarily disable SRP for troubleshooting:

```powershell
# Disable (rename key)
Rename-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer" "_Safer" -Force
gpupdate /force

# Re-enable
Rename-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\_Safer" "Safer" -Force
gpupdate /force
```

---

## Part 2: Automated monitoring for unauthorized executables

Even with SRP in place, monitoring provides an additional layer of detection—catching renamed files, new download attempts, and any bypass attempts before they succeed.

### Comprehensive scanning script

Save this as `C:\ParentalControl\Scripts\ExeMonitor.ps1`:

```powershell
<#
.SYNOPSIS
    Scans user folders for executable files and alerts on new discoveries
.NOTES
    Run via Task Scheduler as SYSTEM to prevent child from disabling
#>

param(
    [string]$LogPath = "C:\ParentalControl\Logs\ExeMonitor.log",
    [string]$BaselinePath = "C:\ParentalControl\Data\baseline.csv",
    [string]$QuarantinePath = "C:\ParentalControl\Quarantine",
    [switch]$QuarantineFiles,
    [switch]$SendEmail,
    [string]$EmailTo = "parent@email.com"
)

# Ensure directories exist
foreach ($dir in @((Split-Path $LogPath -Parent), (Split-Path $BaselinePath -Parent), $QuarantinePath)) {
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Tee-Object -FilePath $LogPath -Append
}

# Get all user profile folders (monitor all non-admin users)
$userProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { 
    $_.Name -notin @("Public", "Default", "Default User", "All Users") 
}

# Executable extensions to monitor
$dangerousExtensions = @("*.exe", "*.msi", "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.js", "*.com", "*.scr")

# Load previous baseline
$baseline = @{}
if (Test-Path $BaselinePath) {
    Import-Csv $BaselinePath | ForEach-Object { $baseline[$_.FullPath] = $_.Hash }
}

# Scan each user's profile
$currentFiles = @()
$newFiles = @()

foreach ($profile in $userProfiles) {
    $foldersToScan = @(
        "$($profile.FullName)\AppData\Roaming",
        "$($profile.FullName)\AppData\Local",
        "$($profile.FullName)\Downloads",
        "$($profile.FullName)\Desktop"
    )

    foreach ($folder in $foldersToScan) {
        if (Test-Path $folder) {
            Get-ChildItem -Path $folder -Include $dangerousExtensions -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                $fileInfo = [PSCustomObject]@{
                    FullPath = $_.FullName
                    Name = $_.Name
                    User = $profile.Name
                    CreationTime = $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                    Size = $_.Length
                    Hash = $hash
                    DetectedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                $currentFiles += $fileInfo

                # Check if this is a new file
                if (-not $baseline.ContainsKey($_.FullName)) {
                    $newFiles += $fileInfo
                    Write-Log "NEW EXECUTABLE: $($_.FullName) (User: $($profile.Name))" -Level "ALERT"
                }
            }
        }
    }
}

# Update baseline
$currentFiles | Export-Csv $BaselinePath -NoTypeInformation -Force

# Process new files
if ($newFiles.Count -gt 0) {
    Write-Log "Detected $($newFiles.Count) new executable(s)" -Level "ALERT"

    $alertBody = "PARENTAL CONTROL ALERT`n`nNew executable files detected:`n`n"
    foreach ($file in $newFiles) {
        $alertBody += "User: $($file.User)`n"
        $alertBody += "File: $($file.Name)`n"
        $alertBody += "Path: $($file.FullPath)`n"
        $alertBody += "Size: $([math]::Round($file.Size/1KB, 2)) KB`n"
        $alertBody += "Created: $($file.CreationTime)`n`n"

        # Quarantine if enabled
        if ($QuarantineFiles) {
            $quarantineName = "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($file.User)_$($file.Name).quarantined"
            try {
                Move-Item -Path $file.FullPath -Destination (Join-Path $QuarantinePath $quarantineName) -Force
                Write-Log "Quarantined: $($file.FullPath)" -Level "INFO"
            } catch {
                Write-Log "Failed to quarantine: $($file.FullPath) - $_" -Level "ERROR"
            }
        }
    }

    # Send email alert
    if ($SendEmail -and $EmailTo) {
        # Configure your SMTP settings here
        $smtpParams = @{
            From = "parental-control@yourdomain.com"
            To = $EmailTo
            Subject = "ALERT: New Executable Detected - $(Get-Date -Format 'MMM dd HH:mm')"
            Body = $alertBody
            SmtpServer = "smtp.gmail.com"
            Port = 587
            # Credential = $credential  # Set up separately
            UseSsl = $true
        }
        try {
            Send-MailMessage @smtpParams
            Write-Log "Email alert sent to $EmailTo"
        } catch {
            Write-Log "Email failed: $_" -Level "ERROR"
        }
    }

    # Windows toast notification (if BurntToast is installed)
    try {
        Import-Module BurntToast -ErrorAction Stop
        New-BurntToastNotification -Text "Parental Control Alert", "$($newFiles.Count) new executable(s) detected!" -Sound Alarm2
    } catch { }
}

Write-Log "Scan complete. Files: $($currentFiles.Count), New: $($newFiles.Count)"
```

### Real-time monitoring with FileSystemWatcher

For immediate detection, this script monitors folders continuously. Save as `C:\ParentalControl\Scripts\RealtimeMonitor.ps1`:

```powershell
<#
.SYNOPSIS
    Real-time monitoring using FileSystemWatcher for immediate detection
.NOTES
    Runs continuously - deploy via Task Scheduler at startup
#>

$QuarantinePath = "C:\ParentalControl\Quarantine"
$LogPath = "C:\ParentalControl\Logs\RealTimeMonitor.log"

# Get all user AppData folders
$foldersToWatch = @()
Get-ChildItem "C:\Users" -Directory | Where-Object { 
    $_.Name -notin @("Public", "Default", "Default User", "All Users") 
} | ForEach-Object {
    $foldersToWatch += "$($_.FullName)\AppData\Local"
    $foldersToWatch += "$($_.FullName)\AppData\Roaming"
    $foldersToWatch += "$($_.FullName)\Downloads"
}

$executableExtensions = @('.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.com', '.scr')

$action = {
    $filePath = $event.SourceEventArgs.FullPath
    $fileName = $event.SourceEventArgs.Name
    $extension = [System.IO.Path]::GetExtension($filePath).ToLower()

    if ($executableExtensions -contains $extension) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "ALERT: New executable - $filePath"
        "$timestamp - $logMessage" | Out-File "C:\ParentalControl\Logs\RealTimeMonitor.log" -Append

        # Toast notification
        try {
            Import-Module BurntToast -ErrorAction SilentlyContinue
            New-BurntToastNotification -Text "Security Alert!", "New executable: $fileName" -Sound Alarm1
        } catch { }

        # Quarantine immediately
        Start-Sleep -Milliseconds 500  # Wait for file to finish writing
        $quarantinePath = "C:\ParentalControl\Quarantine"
        if (Test-Path $filePath) {
            $quarantineName = "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$fileName.quarantined"
            Move-Item -Path $filePath -Destination (Join-Path $quarantinePath $quarantineName) -Force -ErrorAction SilentlyContinue
        }
    }
}

# Create watchers
$watchers = @()
foreach ($folder in $foldersToWatch) {
    if (Test-Path $folder) {
        $watcher = New-Object System.IO.FileSystemWatcher -Property @{
            Path = $folder
            Filter = "*.*"
            IncludeSubdirectories = $true
            EnableRaisingEvents = $true
        }
        Register-ObjectEvent -InputObject $watcher -EventName Created -Action $action
        $watchers += $watcher
    }
}

"$(Get-Date) - Real-time monitoring started for $($watchers.Count) folders" | Out-File $LogPath -Append

# Keep running indefinitely
while ($true) { Start-Sleep -Seconds 60 }
```

### Setting up Task Scheduler via PowerShell

This script creates two scheduled tasks running as SYSTEM (preventing the child from disabling them):

```powershell
#Requires -RunAsAdministrator
# SetupMonitoringTasks.ps1 - Creates protected scheduled tasks

$ScriptFolder = "C:\ParentalControl\Scripts"

# Secure the folder - only Admins and SYSTEM can access
$acl = Get-Acl $ScriptFolder
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
Set-Acl $ScriptFolder $acl

# Task 1: Hourly scanning task
$scanAction = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptFolder\ExeMonitor.ps1`" -QuarantineFiles"

$scanTriggers = @(
    (New-ScheduledTaskTrigger -AtLogon),
    (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue))
)

$scanSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "ParentalControl_ExeScanner" `
    -Action $scanAction -Trigger $scanTriggers -Settings $scanSettings -Principal $principal `
    -Description "Scans for unauthorized executables hourly" -Force

# Task 2: Real-time monitoring (runs continuously)
$realtimeAction = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptFolder\RealtimeMonitor.ps1`""

$realtimeTrigger = New-ScheduledTaskTrigger -AtStartup
$realtimeSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "ParentalControl_RealtimeMonitor" `
    -Action $realtimeAction -Trigger $realtimeTrigger -Settings $realtimeSettings -Principal $principal `
    -Description "Real-time executable monitoring" -Force

Write-Host "Scheduled tasks created successfully" -ForegroundColor Green
Write-Host "Tasks run as SYSTEM - cannot be disabled by standard users" -ForegroundColor Yellow
```

### Preventing the child from disabling monitoring

Several security measures ensure the monitoring persists:

1. **SYSTEM account execution**: Tasks running under `NT AUTHORITY\SYSTEM` cannot be stopped, modified, or viewed by standard users

2. **NTFS permissions**: The script folder is locked down so only Administrators and SYSTEM can access it

3. **Hidden execution**: Scripts run with `-WindowStyle Hidden` so no PowerShell window appears

4. **Self-healing tasks**: Configure tasks to restart automatically on failure with `RestartCount` and `RestartInterval`

5. **Tamper detection** (add to ExeMonitor.ps1):

```powershell
# Check if tasks are still enabled
$tasks = Get-ScheduledTask | Where-Object {$_.TaskName -like "*ParentalControl*"}
foreach ($task in $tasks) {
    if ($task.State -eq "Disabled") {
        Enable-ScheduledTask -TaskName $task.TaskName
        Write-Log "TAMPER DETECTED: Re-enabled task $($task.TaskName)" -Level "ALERT"
    }
}
```

---

## Important limitations and considerations

**SRP limitations to understand:**

- Path rules have a **maximum of 133 characters**—longer paths are silently ignored
- Safe Mode bypasses SAFER rules entirely (acts as a recovery option if needed)
- Rules apply per-machine, so affects all standard user accounts equally
- Some Windows Store apps may behave unexpectedly; test thoroughly

**Monitoring limitations:**

- FileSystemWatcher can miss events during high disk activity
- Renamed executables with non-standard extensions may slip through initially
- Network drives and removable media require separate monitoring

**Recommended combined approach:**

- Use SRP as the primary enforcement mechanism (prevents execution)
- Use scheduled scanning as the detection layer (catches what gets through)
- Use real-time monitoring for immediate alerts (catches in progress)
- Regularly review logs at `C:\Users\Public\Documents\SAFER.log` and `C:\ParentalControl\Logs\`

## Conclusion

This dual-layer approach provides robust protection against unauthorized software installation on Windows Home. The registry-based SRP implementation blocks executables from running in user-writable locations without requiring Group Policy Editor, while the automated monitoring system provides visibility into any bypass attempts. Running all monitoring tasks under the SYSTEM account ensures the child cannot disable protection, and the quarantine functionality automatically neutralizes detected threats. For complete protection, deploy both the SRP configuration and monitoring scripts, verify functionality by testing from the child's account, then regularly review the SAFER.log file to fine-tune whitelisting for legitimate applications.