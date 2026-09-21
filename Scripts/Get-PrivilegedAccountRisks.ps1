#requires -Version 5.1
<#
.SYNOPSIS
Re-queries discovered users by SID and exports review indicators and query status.
.EXAMPLE
.\Get-PrivilegedAccountRisks.ps1 -PrivilegedCsv C:\Audit\Run01\01-PrivilegedUsers.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PrivilegedCsv,
    [ValidateRange(1,3650)][int]$InactiveDays = 90,
    [ValidateRange(1,3650)][int]$PasswordAgeDays = 180,
    [string]$OutputFolder = (Join-Path $PSScriptRoot '../Output')
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Audit.Common.ps1"
Import-Module ActiveDirectory -ErrorAction Stop
$accounts = @(Import-AuditAccounts $PrivilegedCsv)
$results = [System.Collections.Generic.List[object]]::new()
$status = [System.Collections.Generic.List[object]]::new()
$properties = @('LastLogonDate','PasswordLastSet','PasswordNeverExpires','PasswordNotRequired','DoesNotRequirePreAuth','TrustedForDelegation','TrustedToAuthForDelegation','AccountNotDelegated','ServicePrincipalName','SIDHistory')
foreach ($account in ($accounts | Sort-Object SID -Unique)) {
    try {
        $user = Get-ADUser -Identity $account.SID -Server $account.DirectoryServer -Properties $properties
        $findings = @(Get-AuditRiskFinding -User $user -InactiveDays $InactiveDays -PasswordAgeDays $PasswordAgeDays)
        $results.Add([pscustomobject]@{
            SID = $account.SID; SamAccountName = $user.SamAccountName; Enabled = $user.Enabled
            PrivilegedGroups = (($accounts | Where-Object SID -eq $account.SID | Select-Object -ExpandProperty PrivilegedGroup -Unique) -join ' | ')
            FindingCount = $findings.Count; Findings = $findings -join ' | '
            LastLogonDate = $(if ($user.LastLogonDate) { $user.LastLogonDate.ToString('o') })
            PasswordLastSet = $(if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('o') })
            SPNs = $user.ServicePrincipalName -join ' | '; SIDHistory = $user.SIDHistory -join ' | '
        })
        $status.Add([pscustomobject]@{ SID = $account.SID; Status = 'Success'; Message = '' })
    }
    catch { $status.Add([pscustomobject]@{ SID = $account.SID; Status = 'Failed'; Message = $_.Exception.Message }) }
}
Export-AuditCsv -Rows $results.ToArray() -Columns SID,SamAccountName,Enabled,PrivilegedGroups,FindingCount,Findings,LastLogonDate,PasswordLastSet,SPNs,SIDHistory -Path (Join-Path $OutputFolder '07-PrivilegedAccountRisks.csv')
Export-AuditCsv -Rows $status.ToArray() -Columns SID,Status,Message -Path (Join-Path $OutputFolder 'RiskQueryStatus.csv')
if (@($status | Where-Object Status -eq 'Failed').Count) { Write-Warning 'Some accounts could not be assessed. Review RiskQueryStatus.csv.' }
