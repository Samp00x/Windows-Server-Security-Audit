#requires -Version 5.1
# Offline integration fixtures: no AD, network calls or production data.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('audit-workflow-' + [guid]::NewGuid())
$domainSid = 'S-1-5-21-1000000001-1000000002-1000000003'
function Import-Module { param($Name, $ErrorAction) }
function Get-ADDomain {
    param($Server)
    [pscustomobject]@{ DomainSID = $domainSid; NetBIOSName = 'EXAMPLE'; DNSRoot = 'example.test' }
}
function Get-ADForest { param($Server) [pscustomobject]@{ RootDomain = 'example.test' } }
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
    # Run the actual remote collector with fabricated OS responses and translation.
    $fakeTranslation = @'
function ConvertTo-AuditSid {
    param($Identity)
    if ($Identity -eq 'EXAMPLE\demo') { return [pscustomobject]@{ Value = 'S-1-5-21-1000000001-1000000002-1000000003-1101' } }
    if ($Identity -eq 'APP01\demo') { return [pscustomobject]@{ Value = 'S-1-5-21-2000000001-2000000002-2000000003-1101' } }
    throw 'Simulated unmapped identity'
}
function ConvertFrom-AuditSid {
    param($Sid)
    if ($Sid.Value -like '*-1000000003-*') { return 'EXAMPLE\demo' }
    return 'APP01\demo'
}
'@
    & $ScriptBlock $ArgumentList[0] ($ArgumentList[1] + "`n" + $fakeTranslation)
}
function Get-CimInstance {
    param($ClassName,$ErrorAction)
    if ($Session.ComputerName -eq 'empty.example.test' -and $ClassName -ne 'Win32_ComputerSystem') { return }
    switch ($ClassName) {
        'Win32_ComputerSystem' { [pscustomobject]@{ Name = 'APP01'; DomainRole = 3 } }
        'Win32_Service' {
            [pscustomobject]@{ Name = 'FakeService'; DisplayName = 'Fictitious Service'; StartName = 'EXAMPLE\demo'; State = 'Stopped'; StartMode = 'Auto' }
            [pscustomobject]@{ Name = 'LocalService'; DisplayName = 'Fictitious Local'; StartName = '.\demo'; State = 'Running'; StartMode = 'Auto' }
            [pscustomobject]@{ Name = 'UnknownService'; DisplayName = 'Fictitious Unknown'; StartName = 'OTHER\missing'; State = 'Running'; StartMode = 'Auto' }
        }
    }
}
function Get-ScheduledTask {
    if ($Session.ComputerName -eq 'empty.example.test') { return }
    [pscustomobject]@{ TaskName = 'OneDrive Startup Task-S-1-5-21-demo'; TaskPath = '\'; State = 'Ready'; Principal = [pscustomobject]@{ UserId = 'EXAMPLE\demo'; LogonType = 'Interactive'; RunLevel = 'Limited' } }
}
function Get-LocalGroupMember {
    param($SID)
    if ($Session.ComputerName -eq 'empty.example.test') { return }
    throw 'Simulated collector access denied'
}
try {
    & "$root/Scripts/Get-PrivilegedUsers.ps1" -Server example.test -OutputFolder $temp
    $csv = Join-Path $temp '01-Privileged-Users.csv'
    $users = @(Import-Csv $csv -Delimiter ';')
    if ($users.Count -ne 2) { throw "Discovery expected 2 unique user/root pairs, got $($users.Count)." }
    if (@($users | Where-Object MembershipType -eq 'NestedPrimaryGroup').Count -ne 1) { throw 'Nested primary group not discovered.' }
    $summary = Import-Csv (Join-Path $temp '02-Privileged-Groups-Summary.csv') -Delimiter ';'
    if (@($summary | Where-Object { $_.Group -eq "$domainSid-512" -and $_.GroupsVisited -eq 2 -and $_.Status -eq 'Complete' }).Count -ne 1) { throw 'Cycle traversal summary incorrect.' }
    & "$root/Scripts/Get-PrivilegedAccountDependencies.ps1" -PrivilegedCsv $csv -ComputerName app.example.test,offline.example.test -OutputFolder $temp
    $dependencies = @(Import-Csv (Join-Path $temp '03-Privileged-Service-Dependencies.csv') -Delimiter ';')
    if ($dependencies.Count -ne 3) { throw 'Service inventory must retain all services.' }
    $matched = @($dependencies | Where-Object IsPrivileged -eq 'True')
    if ($matched.Count -ne 1 -or $matched[0].State -ne 'Stopped' -or $matched[0].DependencySeverity -ne 'Review') { throw 'Stopped automatic service match incorrect.' }
    if (@($dependencies | Where-Object { $_.ResolvedAccountType -eq 'Local' -and $_.IsPrivileged -eq 'False' }).Count -ne 1) { throw 'Local collision incorrectly matched.' }
    if (@($dependencies | Where-Object { $_.IsPrivileged -eq 'Unknown' -and $_.DependencySeverity -eq 'Review' }).Count -ne 1) { throw 'Unresolved identity lost.' }
    $tasks = @(Import-Csv (Join-Path $temp '04-Scheduled-Task-Dependencies.csv') -Delimiter ';')
    if ($tasks.Count -ne 1 -or $tasks[0].DependencyClassification -ne 'UserProfileArtifact' -or $tasks[0].DependencySeverity -ne 'Informational') { throw 'Profile artifact incorrectly promoted.' }
    $scan = @(Import-Csv (Join-Path $temp '05-Server-Scan-Status.csv') -Delimiter ';')
    if (@($scan | Where-Object { $_.Server -eq 'offline.example.test' -and $_.Status -eq 'Failed' }).Count -ne 5) { throw 'Unavailable target must fail all collectors.' }
    if (@($scan | Where-Object { $_.Collector -eq 'Services' -and $_.Status -eq 'Partial' -and $_.ObservedCount -eq 3 -and $_.UnresolvedIdentityCount -eq 1 }).Count -ne 1) { throw 'Resolution gap missing from coverage.' }
    if (@($scan | Where-Object { $_.Server -eq 'app.example.test' -and $_.Collector -eq 'LocalAdministrators' -and $_.Status -eq 'Failed' }).Count -ne 1) { throw 'Independent collector failure missing.' }
    & "$root/Scripts/Get-PrivilegedAccountDependencies.ps1" -PrivilegedCsv $csv -ComputerName empty.example.test -OutputFolder $temp
    foreach ($report in @('03-Privileged-Service-Dependencies.csv','04-Scheduled-Task-Dependencies.csv')) {
        $file = Join-Path $temp $report
        if (@(Import-Csv $file -Delimiter ';').Count -ne 0 -or (Get-Content $file -First 1) -notlike '*ResolutionError*') { throw 'Empty dependency report must retain stable headers.' }
    }
    $scan = @(Import-Csv (Join-Path $temp '05-Server-Scan-Status.csv') -Delimiter ';')
    if (@($scan | Where-Object { $_.Collector -eq 'Services' -and $_.Status -eq 'Success' -and $_.ObservedCount -eq 0 }).Count -ne 1) { throw 'Successful empty scan must differ from failure.' }
    & "$root/Scripts/Get-PrivilegedAccountRisks.ps1" -PrivilegedCsv $csv -OutputFolder $temp
    $risks = @(Import-Csv (Join-Path $temp '06-Privileged-Account-Risks.csv') -Delimiter ';')
    if ($risks.Count -ne 2 -or $risks[0].Findings -notlike '*DoesNotRequirePreAuth*') { throw 'Risk integration incorrect.' }
    Write-Output 'PASS: simulated discovery, remote collector, split reports, identity gaps, collector failures and risks. Live AD/WinRM not tested.'
}
finally {
    if (Test-Path -LiteralPath $temp) {
        Get-ChildItem -LiteralPath $temp -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
        Remove-Item -LiteralPath $temp
    }
}
