#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. "$root/Scripts/Audit.Common.ps1"
$checks = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (!$Condition) { throw "FAIL: $Message" }
    $script:checks++
}
foreach ($file in (Get-ChildItem $root -Filter '*.ps1' -Recurse)) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    Assert-True ($errors.Count -eq 0) "Syntax: $($file.Name): $errors"
}
$accounts = @(
    [pscustomobject]@{ SID = 'S-1-5-21-1000000001-1000000002-1000000003-1101'; DirectoryServer = 'example.test'; DomainNetBIOS = 'EXAMPLE'; SamAccountName = 'audit.admin'; UserPrincipalName = 'audit.admin@example.test'; PrivilegedGroup = 'Domain Admins' }
)
Assert-True ($null -ne (Resolve-AuditAccount 'EXAMPLE\AUDIT.ADMIN' $accounts)) 'Qualified match is case-insensitive'
Assert-True ($null -ne (Resolve-AuditAccount 'audit.admin@example.test' $accounts)) 'UPN match'
Assert-True ($null -ne (Resolve-AuditAccount $accounts[0].SID $accounts)) 'SID match'
Assert-True ($null -eq (Resolve-AuditAccount 'OTHER\audit.admin' $accounts)) 'Cross-domain collision rejected'
Assert-True ($null -eq (Resolve-AuditAccount '.\audit.admin' $accounts)) 'Local collision rejected'
Assert-True ($null -eq (Resolve-AuditAccount 'audit.admin' $accounts)) 'Bare username rejected'
$duplicate = $accounts[0].PSObject.Copy()
$duplicate.SID = 'S-1-5-21-2000000001-2000000002-2000000003-1101'
Assert-True ($null -eq (Resolve-AuditAccount 'EXAMPLE\audit.admin' ($accounts + $duplicate))) 'Ambiguous qualified alias rejected'
$now = [datetime]'2026-01-01T00:00:00'
$user = [pscustomobject]@{
    Enabled = $true; LastLogonDate = $now; PasswordLastSet = $now
    PasswordNeverExpires = $false; PasswordNotRequired = $false; DoesNotRequirePreAuth = $false
    TrustedForDelegation = $false; TrustedToAuthForDelegation = $false; AccountNotDelegated = $true
    ServicePrincipalName = @(); SIDHistory = @()
}
Assert-True (@(Get-AuditRiskFinding $user -Now $now).Count -eq 0) 'No configured indicators'
$user.Enabled = $false; $user.LastLogonDate = $null; $user.DoesNotRequirePreAuth = $true
$findings = @(Get-AuditRiskFinding $user -Now $now)
Assert-True ($findings -contains 'DisabledPrivilegedAccount') 'Disabled flag'
Assert-True ($findings -contains 'NoReplicatedLogonRecorded') 'Unknown logon preserved'
Assert-True ($findings -contains 'DoesNotRequirePreAuth') 'Pre-authentication flag'
$user.LastLogonDate = $now.AddDays(-91)
Assert-True (@(Get-AuditRiskFinding $user -Now $now) -contains 'StaleReplicatedLogon') 'Stale threshold'
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('audit-tests-' + [guid]::NewGuid())
try {
    $path = Join-Path $temp 'empty.csv'
    Export-AuditCsv -Rows @() -Columns SID,DirectoryServer -Path $path
    Assert-True ((Get-Content $path -First 1) -eq '"SID";"DirectoryServer"') 'Empty reports retain headers'
    $path = Join-Path $temp 'accounts.csv'
    Export-AuditCsv -Rows $accounts -Columns SID,DirectoryServer,DomainNetBIOS,SamAccountName,UserPrincipalName,PrivilegedGroup -Path $path
    Assert-True (@(Import-AuditAccounts $path).Count -eq 1) 'Account CSV round trip'
    Set-Content $path '"SamAccountName";"PrivilegedGroup"', '"fake";"Fake Group"'
    $rejected = $false
    try { Import-AuditAccounts $path | Out-Null } catch { $rejected = $true }
    Assert-True $rejected 'Legacy schema rejected'
}
finally {
    # Delete only files this test created; no recursive cleanup.
    foreach ($name in @('empty.csv','accounts.csv')) {
        $file = Join-Path $temp $name
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp }
}
Write-Output "PASS: $checks offline regression checks. Live AD and remoting were not tested."
# Include dependency checks in the existing Windows CI entry point.
& "$PSScriptRoot/Test-Dependencies.ps1"
