#requires -Version 5.1
# Offline integration fixtures: no AD, network calls or production data.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('audit-workflow-' + [guid]::NewGuid())
$domainSid = 'S-1-5-21-1000000001-1000000002-1000000003'
$failTargetDiscovery = $false
$failMembershipRead = $false
function Import-Module { param($Name, $ErrorAction) }
function Get-ADDomain {
    param($Server,$Current,$ErrorAction)
    [pscustomobject]@{ DomainSID = $domainSid; NetBIOSName = 'EXAMPLE'; DNSRoot = 'example.test' }
}
function Get-ADForest { param($Server) [pscustomobject]@{ RootDomain = 'example.test' } }
function Get-ADComputer {
    param($Server,$Filter,$Properties,$ErrorAction)
    if ($failTargetDiscovery) { throw 'Simulated AD computer query failure' }
    [pscustomobject]@{ Name = 'app'; DNSHostName = 'app.example.test'; OperatingSystem = 'Windows Server 2022' }
    [pscustomobject]@{ Name = 'offline'; DNSHostName = 'offline.example.test'; OperatingSystem = 'Windows Server 2022' }
    [pscustomobject]@{ Name = 'dc'; DNSHostName = 'dc.example.test'; OperatingSystem = 'Windows Server 2022' }
    [pscustomobject]@{ Name = 'missing'; DNSHostName = ''; OperatingSystem = 'Windows Server 2022' }
}
function Get-ADDomainController {
    param($Server,$Filter,$ErrorAction)
    [pscustomobject]@{ Name = 'dc'; HostName = 'dc.example.test' }
}
function Get-ADGroup {
    param($Identity, $Server)
    $name = 'Root'
    $sid = [string]$Identity
    if ($sid -like 'CN=Nested*') { $name = 'Nested'; $sid = "$domainSid-1200" }
    if ($sid -like 'CN=Root*') { $sid = "$domainSid-512" }
    [pscustomobject]@{ Name = $name; SID = [pscustomobject]@{ Value = $sid }; DistinguishedName = "CN=$name,DC=example,DC=test"; objectClass = 'group' }
}
function Get-ADUser {
    param($Identity, $Server, $Properties, $LDAPFilter)
    if ($LDAPFilter -and $LDAPFilter -ne '(primaryGroupID=1200)') { return }
    $rid = 1101
    if ($LDAPFilter -or $Identity -like '*Primary*' -or $Identity -like '*-1102') { $rid = 1102 }
    $name = 'demo'
    if ($rid -eq 1102) { $name = 'Primary' }
    [pscustomobject]@{
        SID = [pscustomobject]@{ Value = "$domainSid-$rid" }; DistinguishedName = "CN=$name,DC=example,DC=test"
        objectClass = 'user'; SamAccountName = $name; UserPrincipalName = "$name@example.test"; DisplayName = 'Fictitious User'
        Enabled = $false; LastLogonDate = $null; PasswordLastSet = $null
        PasswordNeverExpires = $true; PasswordNotRequired = $false; DoesNotRequirePreAuth = $true
        TrustedForDelegation = $false; TrustedToAuthForDelegation = $false; AccountNotDelegated = $true
        ServicePrincipalName = @(); SIDHistory = @()
    }
}
function Get-ADGroupMember {
    param($Identity, $Server)
    if ($Identity.SID.Value -eq "$domainSid-512") {
        Get-ADUser -Identity demo
        Get-ADGroup -Identity 'CN=Nested,DC=example,DC=test'
    }
    elseif ($Identity.SID.Value -eq "$domainSid-1200") {
        if ($failMembershipRead) { throw 'Simulated nested membership denial' }
        Get-ADGroup -Identity 'CN=Root,DC=example,DC=test'
        Get-ADUser -Identity demo
    }
}
function New-PSSessionOption { param($OpenTimeout,$OperationTimeout) @{} }
function New-PSSession {
    param($ComputerName,$ConfigurationName,$SessionOption,$ErrorAction)
    if ($ComputerName -eq 'offline.example.test') { throw 'Simulated unavailable server' }
    [pscustomobject]@{ ComputerName = $ComputerName }
}
function Remove-PSSession { param($Session,$ErrorAction) }
function Invoke-Command {
    param($Session,$ScriptBlock,$ArgumentList,$ErrorAction)
    [pscustomobject]@{ Kind = 'Inventory'; Type = 'Services'; Resource = 'FakeService'; Account = 'EXAMPLE\demo'; State = 'Stopped'; Details = 'Fixture' }
    [pscustomobject]@{ Kind = 'Inventory'; Type = 'Services'; Resource = 'LocalService'; Account = 'LOCAL\demo'; State = 'Running'; Details = 'Fixture' }
    foreach ($type in @('Services','ScheduledTasks','IIS','LocalAdministrators','Processes')) {
        $state = 'Success'
        if ($type -eq 'Processes') { $state = 'Skipped' }
        [pscustomobject]@{ Kind = 'Status'; Type = $type; Status = $state; Message = '' }
    }
}
try {
    & "$root/Start-Audit.ps1" -OutputFolder $temp
    $csv = Join-Path $temp '01-PrivilegedUsers.csv'
    $users = @(Import-Csv $csv -Delimiter ';')
    if ($users.Count -ne 2) { throw "Discovery expected 2 unique user/root pairs, got $($users.Count)." }
    $run = @(Import-Csv (Join-Path $temp 'RunStatus.csv') -Delimiter ';')
    if ($run.Count -ne 3 -or @($run | Where-Object Status -eq 'Failed').Count) { throw 'Automatic entry point failed.' }
    $targets = @(Import-Csv (Join-Path $temp 'ServerDiscovery.csv') -Delimiter ';')
    if (@($targets | Where-Object Status -eq 'MissingDNSHostName').Count -ne 1) { throw 'Missing DNS coverage not recorded.' }
    $automaticScan = @(Import-Csv (Join-Path $temp '06-ServerScanStatus.csv') -Delimiter ';')
    if ($automaticScan.Count -ne 15) { throw 'Automatic targets should include three unique servers, including the DC.' }
    if (@($users | Where-Object MembershipType -eq 'NestedPrimaryGroup').Count -ne 1) { throw 'Nested primary group not discovered.' }
    $summary = Import-Csv (Join-Path $temp '04-PrivilegedGroupSummary.csv') -Delimiter ';'
    if (@($summary | Where-Object { $_.Group -eq "$domainSid-512" -and $_.GroupsVisited -eq 2 -and $_.Status -eq 'Complete' }).Count -ne 1) { throw 'Cycle traversal summary incorrect.' }
    & "$root/Scripts/Get-PrivilegedAccountDependencies.ps1" -PrivilegedCsv $csv -ComputerName app.example.test,offline.example.test -OutputFolder $temp
    $dependencies = @(Import-Csv (Join-Path $temp '05-PrivilegedAccountDependencies.csv') -Delimiter ';')
    if ($dependencies.Count -ne 1 -or $dependencies[0].ResourceStatus -ne 'Stopped') { throw 'Dependency integration match incorrect.' }
    $scan = @(Import-Csv (Join-Path $temp '06-ServerScanStatus.csv') -Delimiter ';')
    if (@($scan | Where-Object Status -eq 'Failed').Count -ne 5) { throw 'Unavailable target must fail all collectors.' }
    & "$root/Scripts/Get-PrivilegedAccountRisks.ps1" -PrivilegedCsv $csv -OutputFolder $temp
    $risks = @(Import-Csv (Join-Path $temp '07-PrivilegedAccountRisks.csv') -Delimiter ';')
    if ($risks.Count -ne 2 -or $risks[0].Findings -notlike '*DoesNotRequirePreAuth*') { throw 'Risk integration incorrect.' }
    $failTargetDiscovery = $true
    $failed = $false
    try { & "$root/Start-Audit.ps1" -OutputFolder $temp } catch { $failed = $true }
    if (!$failed) { throw 'Entry point must signal failed target discovery.' }
    $retry = @(Import-Csv (Join-Path $temp 'RunStatus.csv') -Delimiter ';')
    if (@($retry | Where-Object { $_.Stage -eq 'Risks' -and $_.Status -eq 'Completed' }).Count -ne 1) { throw 'Risk checks must continue after dependency discovery failure.' }
    if (Test-Path (Join-Path $temp '05-PrivilegedAccountDependencies.csv')) { throw 'Old dependency results were not archived.' }
    if (@(Get-ChildItem (Join-Path $temp 'History') -Filter '05-PrivilegedAccountDependencies.csv' -Recurse).Count -ne 1) { throw 'Previous results missing from history.' }
    if (@(Get-ChildItem (Join-Path $temp 'History') -Filter '02-PrivilegedUserReview.xlsx' -Recurse).Count -ne 1) { throw 'Review workbook missing from history.' }
    $failTargetDiscovery = $false
    $failMembershipRead = $true
    & "$root/Start-Audit.ps1" -OutputFolder $temp
    $partialRun = @(Import-Csv (Join-Path $temp 'RunStatus.csv') -Delimiter ';')
    if (@($partialRun | Where-Object { $_.Stage -eq 'Discovery' -and $_.Status -eq 'Partial' }).Count -ne 1) { throw 'Partial discovery must propagate to RunStatus.' }
    if (@($partialRun | Where-Object { $_.Stage -eq 'Risks' -and $_.Status -eq 'Completed' }).Count -ne 1) { throw 'Partial discovery should retain downstream compatibility.' }
    Write-Output 'PASS: 16 simulated workflow checks including partial discovery and review workbook history. Remote collector bodies still require live lab validation.'
}
finally {
    if (Test-Path -LiteralPath $temp) {
        Get-ChildItem -LiteralPath $temp -File -Recurse | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
        Get-ChildItem -LiteralPath $temp -Directory -Recurse | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
        Remove-Item -LiteralPath $temp
    }
}
