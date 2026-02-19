<#
.SYNOPSIS
  Active Directory Health Audit (Green/Yellow/Red) with HTML + JSON report.

.DESCRIPTION
  Runs a set of pragmatic AD health checks and scores them:
   - Replication summary (repadmin)
   - DC diagnostics summary (dcdiag)
   - DNS SRV record sanity (_ldap._tcp.dc._msdcs)
   - Time skew drift (w32tm /monitor)
   - SYSVOL/DFSR state + optional backlog probe
   - Secure channel spot checks (nltest /sc_verify) from THIS machine
   - Key Directory Services / DNS Server / DFS Replication event IDs
   - Basic DC resource signals (CPU, memory, LSASS working set)

  Output:
   - JSON report for automation
   - HTML report for humans

.NOTES
  Best run as a domain admin (or with delegated rights).
  Run on a domain-joined server with RSAT (ActiveDirectory module) available.

.PARAMETER OutputDir
  Directory to write reports.

.PARAMETER Domain
  DNS name of the domain. Default uses current domain.

.PARAMETER DaysEvents
  How many days back to scan event logs.

.PARAMETER SampleSecureChannelCount
  How many random computers to sample for secure channel verification (requires remote execution if enabled).
  Default 0 (local-only). If you enable it, see notes in code.

.PARAMETER EnableDfsrBacklog
  Attempt DFSR backlog checks between DCs (can be slow/noisy in some environments).

.EXAMPLE
  .\Invoke-ADHealthAudit.ps1 -OutputDir \\fileserver\ops\ADHealth -DaysEvents 3

#>

[CmdletBinding()]
param(
  [Parameter()][string]$OutputDir = "C:\ADHealth",
  [Parameter()][string]$Domain,
  [Parameter()][int]$DaysEvents = 2,
  [Parameter()][int]$SampleSecureChannelCount = 0,
  [Parameter()][switch]$EnableDfsrBacklog
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Result {
  param(
    [string]$Name,
    [ValidateSet("Green","Yellow","Red","Info")] [string]$Status,
    [int]$Weight = 10,
    [string]$Summary = "",
    [string]$Details = ""
  )
  [pscustomobject]@{
    name    = $Name
    status  = $Status
    weight  = $Weight
    summary = $Summary
    details = $Details
  }
}

function Invoke-External {
  param(
    [Parameter(Mandatory)][string]$File,
    [string[]]$ArgumentList = @()
  )

  $ErrorActionPreference = "Continue"

  # Call the executable with a real argument array (no string-joining bugs)
  $output = & $File @ArgumentList 2>&1
  $exitCode = $LASTEXITCODE

  # Normalize output to a single string for your report
  $outText = ($output | Out-String).Trim()

  [pscustomobject]@{
    ExitCode = $exitCode
    StdOut   = $outText
    StdErr   = ""   # merged into StdOut via 2>&1
  }
}


function Get-DomainName {
  if ($Domain -and $Domain.Trim()) { return $Domain.Trim() }
  try {
    Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
    return (Get-ADDomain).DNSRoot
  } catch {
    # Fallback
    return ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
  }
}

function Ensure-OutputDir {
  if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
  }
}

function Score-Results {
  param([object[]]$Results)

  $totalWeight = ($Results | Where-Object { $_.status -ne "Info" } | Measure-Object -Property weight -Sum).Sum
  if (-not $totalWeight) { $totalWeight = 1 }

  $penalty = 0
  foreach ($r in $Results) {
    if ($r.status -eq "Red")    { $penalty += [math]::Round($r.weight * 1.0, 2) }
    if ($r.status -eq "Yellow") { $penalty += [math]::Round($r.weight * 0.5, 2) }
  }

  $raw = [math]::Max(0, [math]::Round((($totalWeight - $penalty) / $totalWeight) * 100, 0))
  $overall =
    if ($raw -ge 90 -and -not ($Results.status -contains "Red")) { "Green" }
    elseif ($raw -ge 70 -and -not ($Results.status -contains "Red")) { "Yellow" }
    else { "Red" }

  [pscustomobject]@{
    overallStatus = $overall
    scorePercent  = $raw
    totalWeight   = $totalWeight
    penalty       = $penalty
  }
}

function ConvertTo-HtmlReport {
  param(
    [string]$Title,
    [pscustomobject]$Meta,
    [pscustomobject]$Score,
    [object[]]$Results
  )

  $css = @"
  body { font-family: Segoe UI, Arial, sans-serif; margin: 18px; }
  h1 { margin-bottom: 4px; }
  .meta { color: #444; margin-bottom: 16px; }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-weight: 600; }
  .Green { background: #d7f5dd; color: #0f5a20; }
  .Yellow { background: #fff5cc; color: #7a5a00; }
  .Red { background: #ffd6d6; color: #8a0b0b; }
  .Info { background: #e7eef9; color: #1c3f7a; }
  table { border-collapse: collapse; width: 100%; margin-top: 14px; }
  th, td { border: 1px solid #ddd; padding: 10px; vertical-align: top; }
  th { background: #f6f6f6; text-align: left; }
  .small { font-size: 12px; color: #666; }
  pre { white-space: pre-wrap; background: #f8f8f8; padding: 10px; border: 1px solid #eee; border-radius: 8px; }
"@

  $rows = foreach ($r in $Results) {
@"
<tr>
  <td style="width: 220px;"><strong>$($r.name)</strong><div class="small">Weight: $($r.weight)</div></td>
  <td style="width: 110px;"><span class="badge $($r.status)">$($r.status)</span></td>
  <td>
    <div><strong>$([System.Web.HttpUtility]::HtmlEncode($r.summary))</strong></div>
    $(if ($r.details) { "<pre>$([System.Web.HttpUtility]::HtmlEncode($r.details))</pre>" } else { "" })
  </td>
</tr>
"@
  }

  @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>$Title</title>
  <style>$css</style>
</head>
<body>
  <h1>$Title</h1>
  <div class="meta">
    Domain: <strong>$($Meta.domain)</strong> |
    Host: <strong>$($Meta.host)</strong> |
    User: <strong>$($Meta.user)</strong> |
    Run: <strong>$($Meta.runUtc) UTC</strong>
  </div>

  <div>
    Overall: <span class="badge $($Score.overallStatus)">$($Score.overallStatus)</span>
    &nbsp;&nbsp; Score: <strong>$($Score.scorePercent)%</strong>
    <span class="small">(Penalty: $($Score.penalty) / Total Weight: $($Score.totalWeight))</span>
  </div>

  <table>
    <thead>
      <tr><th>Check</th><th>Status</th><th>Summary / Details</th></tr>
    </thead>
    <tbody>
      $($rows -join "`n")
    </tbody>
  </table>
</body>
</html>
"@
}

# -------------------------
# Main
# -------------------------
Ensure-OutputDir

$domainName = Get-DomainName
$nowUtc     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
$hostName   = $env:COMPUTERNAME
$userName   = "$($env:USERDOMAIN)\$($env:USERNAME)"

$meta = [pscustomobject]@{
  domain = $domainName
  host   = $hostName
  user   = $userName
  runUtc = $nowUtc
  script = "Invoke-ADHealthAudit.ps1"
  version = "1.0"
}

$results = New-Object System.Collections.Generic.List[object]

# 1) Replication summary
try {
  $r = Invoke-External -File "repadmin.exe" -ArgumentList @("/replsummary")

  if ($r.ExitCode -ne 0) {
    $results.Add((New-Result -Name "Replication Summary (repadmin /replsummary)" -Status "Red" -Weight 20 -Summary "repadmin exited with code $($r.ExitCode)" -Details ($r.StdErr + "`n" + $r.StdOut)))
  } else {
    # Heuristic: if it contains "fails" or "error" lines
$bad = ($r.StdOut -match "(?im)fail|error|unavailable|0x")
if ($bad) {
  $status = "Yellow"
  $sum    = "Replication summary contains warnings/failures. Review output."
} else {
  $status = "Green"
  $sum    = "Replication summary looks clean."
}

    $results.Add((New-Result -Name "Replication Summary (repadmin /replsummary)" -Status $status -Weight 20 -Summary $sum -Details $r.StdOut))
  }
} catch {
  $results.Add((New-Result -Name "Replication Summary (repadmin /replsummary)" -Status "Red" -Weight 20 -Summary "Failed to run repadmin" -Details $_.Exception.Message))
}

# 2) DCDIAG (enterprise-wide)
try {
  $r = Invoke-External -File "dcdiag.exe" -ArgumentList @("/e","/q")

  if ($r.ExitCode -ne 0) {
    $results.Add((New-Result -Name "DC Diagnostics (dcdiag /e /q)" -Status "Red" -Weight 20 -Summary "dcdiag exited with code $($r.ExitCode)" -Details ($r.StdErr + "`n" + $r.StdOut)))
  } else {
    # /q emits only errors; empty == good
    if ($r.StdOut -and $r.StdOut.Trim().Length -gt 0) {
      $results.Add((New-Result -Name "DC Diagnostics (dcdiag /e /q)" -Status "Red" -Weight 20 -Summary "dcdiag reported errors" -Details $r.StdOut))
    } else {
      $results.Add((New-Result -Name "DC Diagnostics (dcdiag /e /q)" -Status "Green" -Weight 20 -Summary "No dcdiag errors reported." -Details "dcdiag /e /q produced no output (good)."))
    }
  }
} catch {
  $results.Add((New-Result -Name "DC Diagnostics (dcdiag /e /q)" -Status "Red" -Weight 20 -Summary "Failed to run dcdiag" -Details $_.Exception.Message))
}

# 3) DNS SRV sanity
try {
  $srv = "_ldap._tcp.dc._msdcs.$domainName"

  $records = Resolve-DnsName -Name $srv -Type SRV -ErrorAction Stop

  # SRV records typically use NameHost, not NameTarget
$targets = @(
  $records |
    ForEach-Object {
      if ($_.PSObject.Properties.Name -contains "NameHost" -and $_.NameHost) { $_.NameHost }
      elseif ($_.PSObject.Properties.Name -contains "NameTarget" -and $_.NameTarget) { $_.NameTarget }
      else { $null }
    } |
    Where-Object { $_ } |
    Select-Object -Unique
)


  if (-not $targets -or $targets.Count -lt 1) {
    $results.Add((New-Result -Name "DNS SRV Records ($srv)" -Status "Red" -Weight 15 -Summary "No SRV targets returned." -Details ($records | Format-List * | Out-String)))
  } else {
    $details = ($records | Select-Object Name,NameHost,Priority,Weight,Port,TTL | Format-Table -AutoSize | Out-String)
    $results.Add((New-Result -Name "DNS SRV Records ($srv)" -Status "Green" -Weight 15 -Summary "SRV targets returned: $($targets.Count)" -Details $details))
  }
}
catch {
  $results.Add((New-Result -Name "DNS SRV Records (_ldap._tcp.dc._msdcs)" -Status "Red" -Weight 15 -Summary "Failed to resolve SRV records." -Details $_.Exception.Message))
}


# 4) Time skew
try {
  $r = Invoke-External -File "w32tm.exe" -ArgumentList @("/monitor")
  if ($r.ExitCode -ne 0) {
    $results.Add((New-Result -Name "Time Skew (w32tm /monitor)" -Status "Yellow" -Weight 10 -Summary "w32tm returned code $($r.ExitCode). Review." -Details ($r.StdErr + "`n" + $r.StdOut)))
  } else {
    # Heuristic: flag if any offset >= 2 seconds (tune for your standards)
    $offsets = Select-String -InputObject $r.StdOut -Pattern "(?i)Offset:\s*([\-0-9\.]+)s" -AllMatches |
      ForEach-Object { $_.Matches } | ForEach-Object { [double]$_.Groups[1].Value }
    $maxAbs = if ($offsets) { ($offsets | ForEach-Object { [math]::Abs($_) } | Measure-Object -Maximum).Maximum } else { 0 }
    $status =
      if ($maxAbs -ge 5) { "Red" }
      elseif ($maxAbs -ge 2) { "Yellow" }
      else { "Green" }
    $sum = "Max observed offset: ${maxAbs}s (thresholds: Yellow>=2s, Red>=5s)"
    $results.Add((New-Result -Name "Time Skew (w32tm /monitor)" -Status $status -Weight 10 -Summary $sum -Details $r.StdOut))
  }
} catch {
  $results.Add((New-Result -Name "Time Skew (w32tm /monitor)" -Status "Yellow" -Weight 10 -Summary "Failed to run w32tm monitor." -Details $_.Exception.Message))
}

# 5) SYSVOL / DFSR quick state
try {
  $dfsrState = Invoke-External -File "dfsrmig.exe" -ArgumentList @("/getglobalstate")
  $stateText = $dfsrState.StdOut
  $status = "Info"
  $weight = 5
  $sum = "DFSR migration state captured."
  if ($stateText -match "(?i)Eliminated") { $status = "Green"; $weight = 10; $sum = "DFSR global state: Eliminated (good)." }
  elseif ($stateText -match "(?i)Prepared|Redirected") { $status = "Yellow"; $weight = 10; $sum = "DFSR migration not fully eliminated. Review if still using FRS/transition." }
  $results.Add((New-Result -Name "SYSVOL DFSR Migration State (dfsrmig /getglobalstate)" -Status $status -Weight $weight -Summary $sum -Details $stateText))
} catch {
  $results.Add((New-Result -Name "SYSVOL DFSR Migration State" -Status "Info" -Weight 5 -Summary "dfsrmig not available or failed." -Details $_.Exception.Message))
}

# 6) Optional DFSR backlog probe between DCs (can be slow/noisy)
if ($EnableDfsrBacklog.IsPresent) {
  try {
    Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    if ($dcs.Count -ge 2) {
      $a = $dcs[0]; $b = $dcs[1]
      $r = Invoke-External -File "dfsrdiag.exe" -ArgumentList @("backlog","/rgname:`"Domain System Volume`"","/rfname:`"SYSVOL Share`"","/smem:$a","/rmem:$b")
$bad = ($r.StdOut -match "(?im)backlog\s*:\s*[1-9]") -or ($r.StdOut -match "(?im)Error|Fail")
if ($bad) {
  $status = "Yellow"
  $sum    = "DFSR backlog may be present between $a and $b."
} else {
  $status = "Green"
  $sum    = "No obvious DFSR backlog signal between $a and $b."
}

      $results.Add((New-Result -Name "DFSR SYSVOL Backlog (dfsrdiag backlog)" -Status $status -Weight 10 -Summary $sum -Details $r.StdOut))
    } else {
      $results.Add((New-Result -Name "DFSR SYSVOL Backlog (dfsrdiag backlog)" -Status "Info" -Weight 5 -Summary "Not enough DCs detected for backlog check." -Details "Need at least 2 domain controllers."))
    }
  } catch {
    $results.Add((New-Result -Name "DFSR SYSVOL Backlog (dfsrdiag backlog)" -Status "Info" -Weight 5 -Summary "Backlog check failed or not available." -Details $_.Exception.Message))
  }
}

# 7) Secure channel (local machine to domain)
try {
  $r = Invoke-External -File "nltest.exe" -ArgumentList @("/sc_verify:$domainName")
if ($r.ExitCode -eq 0 -and $r.StdOut -match "(?i)success") {
  $status = "Green"
  $sum    = "Secure channel verified (this machine)."
} else {
  $status = "Yellow"
  $sum    = "Secure channel verify not clean (this machine)."
}
  $results.Add((New-Result -Name "Secure Channel (nltest /sc_verify) - local" -Status $status -Weight 10 -Summary $sum -Details ($r.StdOut + "`n" + $r.StdErr)))
} catch {
  $results.Add((New-Result -Name "Secure Channel (nltest /sc_verify) - local" -Status "Yellow" -Weight 10 -Summary "Failed to run nltest secure channel verify." -Details $_.Exception.Message))
}

# 8) Event log “predictors”
# Predictor Event IDs (DS/DNS/DFSR)
$startTime = (Get-Date).AddDays(-1 * [math]::Abs($DaysEvents))
try {
  $idsDirectoryServices = @(1311,1865,2087,2042,2092,2094)
  $idsDnsServer         = @(4013,4010,5501)
  $idsDfsReplication    = @(2213,2212,5002,5008)

  $dsEvents = @(
    Get-WinEvent -FilterHashtable @{ LogName="Directory Service"; StartTime=$startTime } -ErrorAction Stop |
      Where-Object { $idsDirectoryServices -contains $_.Id } |
      Select-Object TimeCreated,Id,LevelDisplayName,Message -First 50
  )

  $dnsEvents = @()
  try {
    $dnsEvents = @(
      Get-WinEvent -FilterHashtable @{ LogName="DNS Server"; StartTime=$startTime } -ErrorAction Stop |
        Where-Object { $idsDnsServer -contains $_.Id } |
        Select-Object TimeCreated,Id,LevelDisplayName,Message -First 50
    )
  } catch {
    $dnsEvents = @() # log may not exist on this host
  }

  $dfsrEvents = @()
  try {
    $dfsrEvents = @(
      Get-WinEvent -FilterHashtable @{ LogName="DFS Replication"; StartTime=$startTime } -ErrorAction Stop |
        Where-Object { $idsDfsReplication -contains $_.Id } |
        Select-Object TimeCreated,Id,LevelDisplayName,Message -First 50
    )
  } catch {
    $dfsrEvents = @()
  }

  $dsCount   = @($dsEvents).Count
  $dnsCount  = @($dnsEvents).Count
  $dfsrCount = @($dfsrEvents).Count
  $count     = $dsCount + $dnsCount + $dfsrCount

  if ($count -eq 0) { $status = "Green" }
  elseif ($count -le 5) { $status = "Yellow" }
  else { $status = "Red" }

  $detailsParts = @()
  if ($dsCount -gt 0)   { $detailsParts += "Directory Service events:`n" + ($dsEvents | Format-Table -AutoSize | Out-String) }
  if ($dnsCount -gt 0)  { $detailsParts += "DNS Server events:`n" + ($dnsEvents | Format-Table -AutoSize | Out-String) }
  if ($dfsrCount -gt 0) { $detailsParts += "DFS Replication events:`n" + ($dfsrEvents | Format-Table -AutoSize | Out-String) }

  if ($count -eq 0) { $sum = "No key predictor events found in last $DaysEvents day(s)." }
  else { $sum = "Found $count key predictor event(s) in last $DaysEvents day(s). Review." }

  $results.Add((New-Result -Name "Predictor Event IDs (DS/DNS/DFSR)" -Status $status -Weight 15 -Summary $sum -Details ($detailsParts -join "`n`n")))
}
catch {
  $results.Add((New-Result -Name "Predictor Event IDs (DS/DNS/DFSR)" -Status "Yellow" -Weight 10 -Summary "Failed to scan event logs." -Details $_.Exception.Message))
}


# 9) Basic DC resource signals (only meaningful if run on a DC)
try {
  $isDc = $false
  try {
    $role = (Get-CimInstance Win32_ComputerSystem).DomainRole
    # 4 = Backup DC, 5 = Primary DC
    $isDc = ($role -eq 4 -or $role -eq 5)
  } catch { }

  if ($isDc) {
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $os  = Get-CimInstance Win32_OperatingSystem
    $memTotal = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $memFree  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $memUsedPct = if ($memTotal -gt 0) { [math]::Round((($memTotal - $memFree) / $memTotal) * 100, 0) } else { 0 }

    $lsass = Get-Process -Name lsass -ErrorAction SilentlyContinue
    $lsassMb = if ($lsass) { [math]::Round($lsass.WorkingSet64 / 1MB, 0) } else { 0 }

    $status =
      if ($cpu -ge 90 -or $memUsedPct -ge 95) { "Red" }
      elseif ($cpu -ge 70 -or $memUsedPct -ge 90) { "Yellow" }
      else { "Green" }

    $sum = "CPU avg: $cpu% | Mem used: $memUsedPct% | LSASS WS: ${lsassMb}MB"
    $results.Add((New-Result -Name "DC Resource Signals (CPU/Mem/LSASS)" -Status $status -Weight 10 -Summary $sum -Details $sum))
  } else {
    $results.Add((New-Result -Name "DC Resource Signals (CPU/Mem/LSASS)" -Status "Info" -Weight 5 -Summary "Not running on a DC; skipping DC-only resource signals." -Details "Run on a DC to capture LSASS + DC resource signals."))
  }
} catch {
  $results.Add((New-Result -Name "DC Resource Signals (CPU/Mem/LSASS)" -Status "Info" -Weight 5 -Summary "Resource signal check failed." -Details $_.Exception.Message))
}

# Score + output
$score = Score-Results -Results $results

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
$baseName = "ADHealth_$($domainName.Replace('.','_'))_$stamp"
$jsonPath = Join-Path $OutputDir "$baseName.json"
$htmlPath = Join-Path $OutputDir "$baseName.html"

$report = [pscustomobject]@{
  meta    = $meta
  score   = $score
  results = $results
}

$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8

$title = "AD Health Audit - $domainName"
$html  = ConvertTo-HtmlReport -Title $title -Meta $meta -Score $score -Results $results
$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host "Overall: $($score.overallStatus) ($($score.scorePercent)%)"
Write-Host "JSON: $jsonPath"
Write-Host "HTML: $htmlPath"
