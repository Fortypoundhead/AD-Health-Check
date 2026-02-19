# Active Directory Health Audit Script

A pragmatic PowerShell Active Directory health audit script that generates a Green / Yellow / Red health score along with JSON and HTML reports.

This script is designed for senior sysadmins and infrastructure engineers who want quick, repeatable visibility into overall AD health without manually running multiple tools.

## What this script checks

The audit combines several high-value AD signals into a single score:

### Core AD Health

- Replication summary (repadmin /replsummary)
- Domain Controller diagnostics (dcdiag /e /q)
- DNS SRV record validation
- Time skew across DCs (w32tm /monitor)
- SYSVOL / DFSR migration state
- Optional DFSR backlog check

### Security & Authentication

- Secure channel verification (nltest /sc_verify)
- Kerberos / replication predictor events

### Operational Signals

- Directory Services, DNS, DFSR event logs
- Basic DC resource signals (CPU, memory, LSASS working set)
- Aggregated health scoring system

## Output

Each run generates:

- HTML report (human-readable dashboard)
- JSON report (automation / historical tracking)

Example output:

```
Overall: Green (95%)
JSON: C:\ADHealth\ADHealth_contoso_com_20260219_141500.json
HTML: C:\ADHealth\ADHealth_contoso_com_20260219_141500.html
```

## Health Scoring
| Status | Meaning |
|--------|---------|
| Green | Environment healthy |
| Yellow | Warnings or early indicators |
|Red | Action required |

Scoring is weighted so replication, diagnostics, and DNS issues impact results more heavily.

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- Domain joined system
- Recommended: run from a Domain Controller or management server
- RSAT Active Directory tools installed

Tools used:

- repadmin
- dcdiag
- nltest
- w32tm
- dfsrmig / dfsrdiag (optional)

## Usage

Basic:

```
.\Invoke-ADHealthAudit.ps1
```


Custom output folder:

```
.\Invoke-ADHealthAudit.ps1 -OutputDir C:\Reports\ADHealth
```

Enable DFSR backlog checks:

```
.\Invoke-ADHealthAudit.ps1 -EnableDfsrBacklog
```

Scan more event history:

```
.\Invoke-ADHealthAudit.ps1 -DaysEvents 3
```

## Recommended Scheduled Task (Weekly)

Example:

```
$action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Invoke-ADHealthAudit.ps1 -OutputDir \\fileserver\ops\ADHealth"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 7:15am

Register-ScheduledTask `
  -TaskName "AD Health Audit Weekly" `
  -Action $action `
  -Trigger $trigger `
  -RunLevel Highest
```

## Why this exists

Active Directory rarely fails suddenly.

It usually degrades first:

- slow authentication
- DNS drift
- replication lag
- subtle event log warnings

This script surfaces those early signals before users notice.

## Designed Philosophy

- Practical over academic
- Low noise, high signal
- Minimal dependencies
- One-file deploy
- Easy automation

## Notes

- Some checks only return full results when run on a Domain Controller.
- DNS and DFSR logs may not exist on member servers.
- The script intentionally favors warning over false confidence.

## Roadmap Ideas

Possible future improvements:

- Email or Teams alerts
- Historical trend scoring
- Multi-domain forest awareness
- HTML charts / trend graphs
- AD site topology visual summary

## Author

Built for real-world AD environments and operational visibility.

## License

GNU Public License v3