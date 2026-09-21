#requires -Version 5.1
# Fabricated identities only. Translation is mocked; no directory or network access.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. "$root/Scripts/Audit.Common.ps1"
. "$root/Scripts/Audit.Identity.ps1"
$checks = 0
function Assert-Equal($Actual, $Expected, $Message) {
    if ($Actual -ne $Expected) { throw "FAIL: $Message (expected $Expected; got $Actual)" }
    $script:checks++
}
$domainSid = 'S-1-5-21-1000000001-1000000002-1000000003-500'
$localSid = 'S-1-5-21-2000000001-2000000002-2000000003-500'
function ConvertTo-AuditSid {
    param($Identity)
    switch -Regex ($Identity) {
        '^(EXAMPLE\\Administrator|example.test\\Administrator|Administrator@example.test)$' { return [pscustomobject]@{ Value = $domainSid } }
        '^APP01\\Administrator$' { return [pscustomobject]@{ Value = $localSid } }
        '^NT SERVICE\\Demo$' { return [pscustomobject]@{ Value = 'S-1-5-80-100-200-300-400-500' } }
        '^S-1-' { return [pscustomobject]@{ Value = $Identity } }
        default { throw 'Simulated account lookup failure' }
    }
}
function ConvertFrom-AuditSid {
    param($Sid)
    switch ($Sid.Value) {
        $domainSid { return 'EXAMPLE\Administrator' }
        $localSid { return 'APP01\Administrator' }
        'S-1-5-18' { return 'NT AUTHORITY\SYSTEM' }
        'S-1-5-19' { return 'NT AUTHORITY\LOCAL SERVICE' }
        'S-1-5-20' { return 'NT AUTHORITY\NETWORK SERVICE' }
        'S-1-5-80-100-200-300-400-500' { return 'NT SERVICE\Demo' }
        default { throw 'Simulated orphaned SID' }
    }
}
foreach ($name in @('EXAMPLE\Administrator','example.test\Administrator','example\ADMINISTRATOR','Administrator@example.test',$domainSid)) {
    $r = Resolve-TargetAuditIdentity $name APP01 3
    Assert-Equal $r.ResolvedAccountType Domain "Domain scope: $name"
    Assert-Equal $r.AccountSID $domainSid "Domain SID: $name"
}
foreach ($name in @('.\Administrator','APP01\Administrator',$localSid)) {
    $r = Resolve-TargetAuditIdentity $name APP01 3
    Assert-Equal $r.ResolvedAccountType Local "Local scope: $name"
    Assert-Equal $r.AccountSID $localSid "Local SID: $name"
}
$r = Resolve-TargetAuditIdentity 'EXAMPLE\Administrator' EXAMPLE 5
Assert-Equal $r.ResolvedAccountType Domain 'DC has no local SAM user scope'
foreach ($name in @('LocalSystem','NT AUTHORITY\SYSTEM','LocalService','NT AUTHORITY\NETWORK SERVICE','NT SERVICE\Demo')) {
    Assert-Equal (Resolve-TargetAuditIdentity $name APP01 3).ResolvedAccountType BuiltIn "Built-in scope: $name"
}
foreach ($name in @('Administrator','OTHER\Administrator','', 'S-1-5-21-3000000001-3000000002-3000000003-500')) {
    $r = Resolve-TargetAuditIdentity $name APP01 3
    Assert-Equal $r.ResolvedAccountType Unresolved "Resolution failure: $name"
    Assert-Equal ([bool]$r.ResolutionError) $true 'Failure reason retained'
}
$orphan = Resolve-TargetAuditIdentity 'S-1-5-21-3000000001-3000000002-3000000003-500' APP01 3
Assert-Equal $orphan.AccountSID 'S-1-5-21-3000000001-3000000002-3000000003-500' 'Orphan SID preserved'
$item = [pscustomobject]@{ Type = 'Services'; Resource = 'Demo'; State = 'Running'; StartMode = 'Auto'; ResolvedAccountType = 'Domain'; LogonType = '' }
Assert-Equal (Get-AuditDependencyFinding $item True).Severity Critical 'Running automatic privileged domain service'
$item.StartMode = 'Manual'
Assert-Equal (Get-AuditDependencyFinding $item True).Severity High 'Running manual privileged service'
$item.StartMode = 'Auto'; $item.State = 'Stopped'
Assert-Equal (Get-AuditDependencyFinding $item True).Severity Review 'Stopped automatic privileged service'
$item.State = 'Paused'
Assert-Equal (Get-AuditDependencyFinding $item True).Severity Review 'Non-running service reviewed'
$item.ResolvedAccountType = 'Unresolved'; $item.State = 'Running'
Assert-Equal (Get-AuditDependencyFinding $item Unknown).Severity Review 'Unresolved running service'
$item.ResolvedAccountType = 'Local'
Assert-Equal (Get-AuditDependencyFinding $item False).Severity Informational 'Local identity not promoted to domain privilege'
$item.State = 'Stopped'
Assert-Equal (Get-AuditDependencyFinding $item False).Severity Review 'Stopped automatic service still reviewed without domain privilege match'
$item.Type = 'ScheduledTasks'; $item.LogonType = 'Interactive'; $item.ResolvedAccountType = 'Domain'
foreach ($name in @('OneDrive Startup Task-S-1-5-demo','OneDrive Reporting Task-S-1-5-demo','CreateExplorerShellUnelevatedTask','User_Feed_Synchronization-{00000000-0000-0000-0000-000000000001}','GoogleUserPEH','GoogleUserPEHCoreTask-S-1-5-demo')) {
    $item.Resource = '\' + $name
    $finding = Get-AuditDependencyFinding $item True
    Assert-Equal $finding.Classification UserProfileArtifact "Profile task: $name"
    Assert-Equal $finding.Severity Informational "Profile task severity: $name"
}
$item.LogonType = 'Password'
Assert-Equal (Get-AuditDependencyFinding $item True).Severity Review 'Non-interactive profile-like task needs review'
$item.Resource = '\NightlyDemo'; $item.State = 'Ready'
Assert-Equal (Get-AuditDependencyFinding $item True).Severity High 'Real privileged scheduled task'
$item.State = 'Disabled'
Assert-Equal (Get-AuditDependencyFinding $item True).Severity Review 'Disabled task configuration retained'
Write-Output "PASS: $checks identity and dependency regression checks. Windows translation and AD connectivity are mocked."
