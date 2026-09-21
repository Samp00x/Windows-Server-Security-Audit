#requires -Version 5.1
<#
.SYNOPSIS
Exports privileged AD users and group coverage without changing AD.
.DESCRIPTION
Traverses nested groups with cycle detection and checks primaryGroupID.
Queries the selected domain plus forest-root privileged groups.
.EXAMPLE
.\Get-PrivilegedUsers.ps1 -Server dc01.example.test -OutputFolder C:\Audit\Run01
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [string[]]$AdditionalGroup = @(),
    [ValidateRange(1,3650)][int]$InactiveDays = 90,
    [string]$OutputFolder = (Join-Path $PSScriptRoot '../Output')
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Audit.Common.ps1"
Import-Module ActiveDirectory -ErrorAction Stop
$domain = Get-ADDomain -Server $Server
$forest = Get-ADForest -Server $Server
$rows = [System.Collections.Generic.List[object]]::new()
$status = [System.Collections.Generic.List[object]]::new()
$summary = [System.Collections.Generic.List[object]]::new()
$now = Get-Date
function Get-ObjectDomain {
    param([string]$DistinguishedName)
    (($DistinguishedName -split ',' | Where-Object { $_ -match '^DC=' }) -replace '^DC=', '') -join '.'
}
$targets = @(
    foreach ($rid in @(512,520)) { [pscustomobject]@{ Identity = "$($domain.DomainSID)-$rid"; Server = $Server } }
    foreach ($rid in @(544,548,549,550,551)) { [pscustomobject]@{ Identity = "S-1-5-32-$rid"; Server = $Server } }
    foreach ($name in (@('DnsAdmins') + $AdditionalGroup)) { [pscustomobject]@{ Identity = $name; Server = $Server } }
)
try {
    $root = Get-ADDomain -Server $forest.RootDomain
    foreach ($rid in @(518,519)) { $targets += [pscustomobject]@{ Identity = "$($root.DomainSID)-$rid"; Server = $forest.RootDomain } }
}
catch { $status.Add([pscustomobject]@{ Target = $forest.RootDomain; Stage = 'ForestRoot'; Status = 'Failed'; Message = $_.Exception.Message }) }
foreach ($target in $targets) {
    $before = $status.Count
    $rootGroup = $null
    $found = @{}
    $visited = @{}
    try {
        $rootGroup = Get-ADGroup -Identity $target.Identity -Server $target.Server
        $queue = [System.Collections.Generic.Queue[object]]::new()
        $queue.Enqueue([pscustomobject]@{ Group = $rootGroup; Depth = 0; Server = $target.Server })
        while ($queue.Count) {
            $node = $queue.Dequeue()
            $group = $node.Group
            if ($visited.ContainsKey($group.SID.Value)) { continue }
            $visited[$group.SID.Value] = $true
            try {
                $members = @(Get-ADGroupMember -Identity $group -Server $node.Server)
                $primary = @()
                if ($group.SID.Value -like 'S-1-5-21-*') {
                    $rid = ($group.SID.Value -split '-')[-1]
                    $primary = @(Get-ADUser -LDAPFilter "(primaryGroupID=$rid)" -Server $node.Server)
                }
                foreach ($member in (@($members) + @($primary))) {
                    $memberServer = Get-ObjectDomain $member.DistinguishedName
                    if (!$memberServer) { throw "Unresolved member: $($member.SID)" }
                    if ($member.objectClass -eq 'group') {
                        $nested = Get-ADGroup -Identity $member.DistinguishedName -Server $memberServer
                        $queue.Enqueue([pscustomobject]@{ Group = $nested; Depth = $node.Depth + 1; Server = $memberServer })
                    }
                    elseif ($member.objectClass -eq 'user') {
                        $sid = $member.SID.Value
                        if ($found.ContainsKey($sid)) { continue }
                        $user = Get-ADUser -Identity $member.DistinguishedName -Server $memberServer -Properties DisplayName,LastLogonDate,PasswordLastSet
                        $userDomain = Get-ADDomain -Server $memberServer
                        $activity = 'Active'
                        if (!$user.Enabled) { $activity = 'Disabled' }
                        elseif (!$user.LastLogonDate) { $activity = 'NoReplicatedLogonRecorded' }
                        elseif ($user.LastLogonDate -lt $now.AddDays(-$InactiveDays)) { $activity = 'StaleReplicatedLogon' }
                        $membership = 'Nested'
                        if ($node.Depth -eq 0) { $membership = 'Direct' }
                        if (@($primary | Where-Object { $_.SID.Value -eq $sid }).Count) { $membership += 'PrimaryGroup' }
                        $found[$sid] = [pscustomobject]@{
                            SID = $sid; DirectoryServer = $memberServer; DomainNetBIOS = $userDomain.NetBIOSName
                            SamAccountName = $user.SamAccountName; UserPrincipalName = $user.UserPrincipalName
                            DisplayName = $user.DisplayName; Enabled = $user.Enabled; ActivityStatus = $activity
                            LastLogonDate = $(if ($user.LastLogonDate) { $user.LastLogonDate.ToString('o') })
                            PasswordLastSet = $(if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('o') })
                            PrivilegedGroup = $rootGroup.Name; GroupSID = $rootGroup.SID.Value; MembershipType = $membership
                        }
                    }
                    else {
                        $status.Add([pscustomobject]@{ Target = $member.DistinguishedName; Stage = 'Member'; Status = 'Unsupported'; Message = "Object class $($member.objectClass); review separately." })
                    }
                }
            }
            catch { $status.Add([pscustomobject]@{ Target = $group.DistinguishedName; Stage = 'Members'; Status = 'Failed'; Message = $_.Exception.Message }) }
        }
    }
    catch { $status.Add([pscustomobject]@{ Target = $target.Identity; Stage = 'Group'; Status = 'Failed'; Message = $_.Exception.Message }) }
    foreach ($row in $found.Values) { $rows.Add($row) }
    $coverage = 'Complete'
    if ($status.Count -gt $before) { $coverage = 'Partial' }
    if (!$rootGroup) { $coverage = 'Failed' }
    $summary.Add([pscustomobject]@{ Group = $target.Identity; DirectoryServer = $target.Server; UniqueUsers = $found.Count; GroupsVisited = $visited.Count; Status = $coverage })
}
Export-AuditCsv -Rows @($rows.ToArray() | Sort-Object PrivilegedGroup,SamAccountName) -Columns SID,DirectoryServer,DomainNetBIOS,SamAccountName,UserPrincipalName,DisplayName,Enabled,ActivityStatus,LastLogonDate,PasswordLastSet,PrivilegedGroup,GroupSID,MembershipType -Path (Join-Path $OutputFolder '01-PrivilegedUsers.csv')
Export-AuditCsv -Rows $summary.ToArray() -Columns Group,DirectoryServer,UniqueUsers,GroupsVisited,Status -Path (Join-Path $OutputFolder '04-PrivilegedGroupSummary.csv')
Export-AuditCsv -Rows $status.ToArray() -Columns Target,Stage,Status,Message -Path (Join-Path $OutputFolder 'DiscoveryStatus.csv')
if ($status.Count) { Write-Warning 'Discovery has coverage gaps. Review DiscoveryStatus.csv and the group summary.' }
