# Wazuh SIEM Integration for Windows SRP

This directory contains Wazuh configuration files for monitoring Windows Software Restriction Policy (SRP) events.

## Components

| File | Purpose |
|------|---------|
| `decoders/windows_srp_decoders.xml` | Parses SAFER log format into structured fields (standard + enriched) |
| `rules/windows_srp_rules.xml` | Detection rules for SRP events (IDs 100600-100699) |
| `lists/srp_baseline` | CDB list of known-good executables for baseline detection |
| `agent-config/srp-localfile.xml` | Agent configuration snippet for log collection |
| `scripts/sync-baseline.sh` | Manager-side script to sync baseline from Windows agents |
| `dashboards/srp-security-dashboard.ndjson` | OpenSearch dashboard with event timeline and drill-down |

## Installation

### 1. Install Decoders and Rules

Copy to your Wazuh manager:

```bash
# Copy decoder
cp decoders/windows_srp_decoders.xml /var/ossec/etc/decoders/

# Copy rules
cp rules/windows_srp_rules.xml /var/ossec/etc/rules/

# Copy baseline list (create directory first)
mkdir -p /var/ossec/etc/lists/srp
cp lists/srp_baseline /var/ossec/etc/lists/srp/
```

### 2. Add CDB List to ossec.conf

Edit `/var/ossec/etc/ossec.conf` and add within the `<ruleset>` section:

```xml
<list>etc/lists/srp/srp_baseline</list>
```

### 3. Configure Agent Log Collection

Add the agent config to `/var/ossec/etc/shared/default/agent.conf`:

```xml
<agent_config os="Windows">
  <localfile>
    <location>C:\ParentalControl\Logs\SAFER-UTF8.log</location>
    <log_format>syslog</log_format>
    <frequency>5</frequency>
  </localfile>
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

### 4. Restart Wazuh Manager

```bash
systemctl restart wazuh-manager
# Or for Docker:
docker restart wazuh.manager
```

### 5. Import Dashboard (Optional)

Import the SRP Security Dashboard into OpenSearch Dashboards:

**Via UI:**
1. Navigate to Management → Saved Objects
2. Click Import
3. Select `dashboards/srp-security-dashboard.ndjson`
4. Click Import

**Via API:**
```bash
curl -sk -u admin:$PASSWORD \
  -X POST "https://localhost:5601/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" \
  -F file=@dashboards/srp-security-dashboard.ndjson
```

The dashboard includes:
- **SRP Event Timeline** - Events over time by rule ID
- **Blocked Events** - Windows SRP blocked executions
- **Allowed Events** - SAFER log allowed executions
- **All SRP Events** - Combined view
- **New Executables** - Executables not in baseline

## Rule IDs

| ID | Level | Description |
|----|-------|-------------|
| **File-based (SAFER log)** | | |
| 100650 | 0 | Base SRP log file event |
| 100651 | 3 | SRP ALLOWED (Unrestricted) |
| 100652 | 10 | SRP BLOCKED (Disallowed) - NOTE: Won't trigger; SAFER.log only logs allowed executables |
| 100653 | 12 | Blocked in user profile - NOTE: Won't trigger; SAFER.log only logs allowed executables |
| 100654 | 11 | Blocked PowerShell script - NOTE: Won't trigger; SAFER.log only logs allowed executables |
| **Baseline Detection** | | |
| 100660 | 7 | NEW EXECUTABLE not in baseline |
| 100661 | 10 | New executable in user profile |
| 100662 | 11 | New executable from Downloads |
| 100663 | 11 | New executable from Temp |
| **Event Log (EventChannel)** | | |
| 100600 | 0 | Base SRP event from Windows Event Log |
| 100610 | 10 | Event 865 - Executable blocked |
| 100611 | 10 | Event 866 - Blocked by path rule |
| 100612 | 10 | Event 867 - Blocked by certificate rule |
| 100613 | 10 | Event 868 - Blocked by hash rule |

## Windows Prerequisites

1. Run `ExeMonitor.ps1 -ConvertAndEnrichSaferLog` to convert SAFER.log from UTF-16 to UTF-8 with hash enrichment
2. Schedule the conversion task to run periodically (e.g., every 5 minutes)
3. Install and configure the Wazuh agent on the Windows machine

### Log Enrichment

The `-ConvertAndEnrichSaferLog` flag converts and adds timestamp and file hashes to each log entry:

**Standard format:**
```
svchost.exe (PID = 1596) identified C:\Windows\test.exe as Unrestricted using default rule, Guid = {...}
```

**Enriched format:**
```
svchost.exe (PID = 1596) identified C:\Windows\test.exe as Unrestricted using default rule, Guid = {...}|2026-01-02T10:30:00Z|SHA256:ABC123...|SHA1:DEF456...
```

The decoder extracts these additional fields:
- `srp.timestamp` - When the log was processed
- `srp.sha256` - SHA-256 hash of the executable (if file exists)
- `srp.sha1` - SHA-1 hash of the executable (if file exists)

## Managing the Baseline

The baseline list uses Wazuh CDB format. Windows paths require double quotes due to the colon in drive letters:

```
# Correct format (note double quotes)
"C:\Windows\System32\notepad.exe":
"C:\Program Files\MyApp\app.exe":

# Incorrect (will fail to parse)
C:\Windows\System32\notepad.exe:
```

### Syncing Baseline from Windows Agent

ExeMonitor.ps1 can export the local baseline to CDB format for syncing with the Wazuh Manager:

**On Windows (generate CDB):**
```powershell
.\ExeMonitor.ps1 -ExportCDB
# Output: C:\ParentalControl\Data\srp_baseline.cdb
```

**Sync methods:**

1. **Manual copy** - Copy `srp_baseline.cdb` to manager via file share or SCP
2. **Wazuh logcollector command** - Output CDB content as log events (see agent-config/srp-localfile.xml)
3. **Scheduled task + API** - Windows task exports CDB, script uploads via Wazuh API

**Manager-side sync script:**
```bash
# Copy the script to manager
cp scripts/sync-baseline.sh /var/ossec/active-response/bin/

# Manual sync from agent files
./sync-baseline.sh <agent_id>
```

### Adding to Baseline

```bash
# Add a new executable
echo '"C:\Path\To\new.exe":' >> /var/ossec/etc/lists/srp/srp_baseline

# Restart manager to recompile CDB
systemctl restart wazuh-manager
```

### Regenerating Baseline from Alerts

Extract allowed executables from recent alerts:

```bash
grep "100651" /var/ossec/logs/alerts/alerts.json | \
  python3 -c "import sys,json; [print(f'\"{json.loads(l)[\"data\"][\"srp\"][\"target_path\"]}\":') for l in sys.stdin]" | \
  sort -u > srp_baseline_new.txt
```

## Testing

Test the decoder and rules using wazuh-logtest:

**Standard format:**
```bash
echo 'svchost.exe (PID = 1596) identified C:\Windows\test.exe as Unrestricted using default rule, Guid = {11015445-d282-4f86-96a2-9e485f593302}' | \
  /var/ossec/bin/wazuh-logtest
```

**Enriched format:**
```bash
echo 'svchost.exe (PID = 1596) identified C:\Windows\test.exe as Unrestricted using default rule, Guid = {11015445-d282-4f86-96a2-9e485f593302}|2026-01-02T10:30:00Z|SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855|SHA1:DA39A3EE5E6B4B0D3255BFEF95601890AFD80709' | \
  /var/ossec/bin/wazuh-logtest
```

## Troubleshooting

### Agent not sending logs
1. Check agent status: `/var/ossec/bin/agent_control -i <id>`
2. Verify file exists: `C:\ParentalControl\Logs\SAFER-UTF8.log`
3. Check file encoding (must be UTF-8, not UTF-16)
4. Run `ExeMonitor.ps1 -ConvertSaferLog` on Windows

### CDB list not loading
1. Ensure declared in ossec.conf `<ruleset>` section
2. Check file format (paths need double quotes)
3. Restart manager after changes

### No events in Wazuh
- SAFER log only contains **allowed** events
- **Blocked** events come via Windows EventChannel
- Check both log sources are configured
