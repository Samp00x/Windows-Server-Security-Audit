#requires -Version 5.1
<#
.SYNOPSIS
Discovers privileged users and every simple path from selected administrative groups.
.DESCRIPTION
Cycles are stopped per path. Alternative paths are preserved.
LastLogonDate is replicated and approximate, independent of Enabled.
.EXAMPLE
.\Get-PrivilegedUsers.ps1
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string[]]$AdditionalGroup = @(),
    [ValidateRange(1,3650)][int]$InactiveDays = 90,
    [string]$OutputFolder = 'C:\scriptsDC'
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Audit.Common.ps1"
. "$PSScriptRoot/Export-AuditWorkbook.ps1"
Import-Module ActiveDirectory -ErrorAction Stop
if (!$Server) { $Server = (Get-ADDomain -Current LocalComputer).DNSRoot }
$domain = Get-ADDomain -Server $Server
$forest = Get-ADForest -Server $Server
$rows = [System.Collections.Generic.List[object]]::new()
$paths = [System.Collections.Generic.List[object]]::new()
$status = [System.Collections.Generic.List[object]]::new()
$summary = [System.Collections.Generic.List[object]]::new()
$users = @{}
$now = Get-Date
function Get-ObjectDomain {
    param([string]$DistinguishedName)
    (($DistinguishedName -split ',' | Where-Object { $_ -match '^DC=' }) -replace '^DC=', '') -join '.'
}
function Add-DiscoveryIssue {
    param([string]$Target, [string]$Stage, [string]$State, [string]$Message)
    $status.Add([pscustomobject]@{ Target = $Target; Stage = $Stage; Status = $State; Message = $Message })
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
catch { Add-DiscoveryIssue $forest.RootDomain 'ForestRoot' 'Failed' $_.Exception.Message }
$rootKeys = @{}
foreach ($target in $targets) {
    $before = $status.Count
    $rootGroup = $null
    $found = @{}
    $visited = @{}
    $memberCache = @{}
    $rootPaths = [System.Collections.Generic.List[object]]::new()
    $pathKeys = @{}
    try {
        $rootGroup = Get-ADGroup -Identity $target.Identity -Server $target.Server
        # Builtin SIDs repeat between domains; include the DN.
        $rootKey = "$($rootGroup.SID.Value)|$($rootGroup.DistinguishedName)"
        if ($rootKeys.ContainsKey($rootKey)) { continue }
        $rootKeys[$rootKey] = $true
        $queue = [System.Collections.Generic.Queue[object]]::new()
        $queue.Enqueue([pscustomobject]@{
            Group = $rootGroup; Server = $target.Server
            Names = @($rootGroup.Name); DNs = @($rootGroup.DistinguishedName); SIDs = @($rootGroup.SID.Value)
        })
        while ($queue.Count) {
            $node = $queue.Dequeue()
            $group = $node.Group
            $groupKey = $group.DistinguishedName
            $visited[$groupKey] = $true
            if (!$memberCache.ContainsKey($groupKey)) {
                $edges = [System.Collections.Generic.List[object]]::new()
                # Independent reads preserve normal members when primary-group queries fail.
                try {
                    foreach ($member in (Get-ADGroupMember -Identity $group -Server $node.Server)) {
                        $edges.Add([pscustomobject]@{ Member = $member; Type = 'Member' })
                    }
                }
                catch { Add-DiscoveryIssue $groupKey 'Members' 'Failed' $_.Exception.Message }
                if ($group.SID.Value -like 'S-1-5-21-*') {
                    $rid = ($group.SID.Value -split '-')[-1]
                    try {
                        foreach ($member in (Get-ADUser -LDAPFilter "(primaryGroupID=$rid)" -Server $node.Server)) {
                            $edges.Add([pscustomobject]@{ Member = $member; Type = 'PrimaryGroup' })
                        }
                    }
                    catch { Add-DiscoveryIssue $groupKey 'PrimaryGroup' 'Failed' $_.Exception.Message }
                }
                $memberCache[$groupKey] = $edges.ToArray()
            }
            foreach ($edge in $memberCache[$groupKey]) {
                $member = $edge.Member
                try {
                    $memberServer = Get-ObjectDomain $member.DistinguishedName
                    if (!$memberServer) { throw "Unresolved member: $($member.SID)" }
                    if ($member.objectClass -eq 'group') {
                        if ($node.DNs -contains $member.DistinguishedName) {
                            Add-DiscoveryIssue $member.DistinguishedName 'Cycle' 'CycleDetected' (($node.DNs + $member.DistinguishedName) -join ' -> ')
                            continue
                        }
                        $nested = Get-ADGroup -Identity $member.DistinguishedName -Server $memberServer
                        $queue.Enqueue([pscustomobject]@{
                            Group = $nested; Server = $memberServer
                            Names = @($node.Names) + $nested.Name; DNs = @($node.DNs) + $nested.DistinguishedName
                            SIDs = @($node.SIDs) + $nested.SID.Value
                        })
                    }
                    elseif ($member.objectClass -eq 'user') {
                        $sid = $member.SID.Value
                        if (!$users.ContainsKey($sid)) {
                            try {
                                $user = Get-ADUser -Identity $member.DistinguishedName -Server $memberServer -Properties DisplayName,LastLogonDate,PasswordLastSet
                                $userDomain = Get-ADDomain -Server $memberServer
                                $activity = 'Active'
                                if (!$user.LastLogonDate) { $activity = 'NoReplicatedLogonRecorded' }
                                elseif ($user.LastLogonDate -lt $now.AddDays(-$InactiveDays)) { $activity = 'StaleReplicatedLogon' }
                                $users[$sid] = [pscustomobject]@{
                                    User = $user; Server = $memberServer; NetBIOS = $userDomain.NetBIOSName
                                    Activity = $activity; Status = 'Success'; Name = $user.SamAccountName
                                }
                            }
                            catch {
                                $users[$sid] = [pscustomobject]@{ User = $null; Server = $memberServer; NetBIOS = ''; Activity = 'Unknown'; Status = 'Failed'; Name = $member.SamAccountName }
                                Add-DiscoveryIssue $member.DistinguishedName 'UserDetails' 'Failed' $_.Exception.Message
                            }
                        }
                        $info = $users[$sid]
                        if ($info.Status -ne 'Success') { Add-DiscoveryIssue $member.DistinguishedName 'UserDetails' 'Failed' 'Details unavailable; membership evidence retained.' }
                        $membership = 'Nested'
                        if ($node.DNs.Count -eq 1) { $membership = 'Direct' }
                        if ($edge.Type -eq 'PrimaryGroup') { $membership += 'PrimaryGroup' }
                        $key = (@($node.DNs) + $sid + $edge.Type) -join '|'
                        if ($pathKeys.ContainsKey($key)) { continue }
                        $pathKeys[$key] = $true
                        $rootPaths.Add([pscustomobject]@{
                            SID = $sid; SamAccountName = $info.Name; DirectoryServer = $memberServer
                            PrivilegedGroup = $rootGroup.Name; GroupSID = $rootGroup.SID.Value
                            RootGroupDN = $rootGroup.DistinguishedName; MembershipType = $membership
                            Depth = $node.DNs.Count; MembershipPath = (@($node.Names) + $info.Name) -join ' -> '
                            GroupSIDPath = $node.SIDs -join ' -> '; GroupDNPath = $node.DNs -join ' -> '
                            UserDetailsStatus = $info.Status; CollectionStatus = ''
                        })
                        # Preserve CSV 01 cardinality, preferring a direct path when both exist.
                        if ($info.Status -eq 'Success' -and (!$found.ContainsKey($sid) -or ($membership -like 'Direct*' -and $found[$sid].MembershipType -like 'Nested*'))) {
                            $user = $info.User
                            $found[$sid] = [pscustomobject]@{
                                SID = $sid; DirectoryServer = $memberServer; DomainNetBIOS = $info.NetBIOS
                                SamAccountName = $user.SamAccountName; UserPrincipalName = $user.UserPrincipalName
                                DisplayName = $user.DisplayName; Enabled = $user.Enabled; ActivityStatus = $info.Activity
                                LastLogonDate = $(if ($user.LastLogonDate) { $user.LastLogonDate.ToString('o') })
                                PasswordLastSet = $(if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('o') })
                                PrivilegedGroup = $rootGroup.Name; GroupSID = $rootGroup.SID.Value; MembershipType = $membership
                            }
                        }
                    }
                    else { Add-DiscoveryIssue $member.DistinguishedName 'Member' 'Unsupported' "Object class $($member.objectClass); review separately." }
                }
                catch { Add-DiscoveryIssue $member.DistinguishedName 'Member' 'Failed' $_.Exception.Message }
            }
        }
    }
    catch { Add-DiscoveryIssue $target.Identity 'Group' 'Failed' $_.Exception.Message }
    foreach ($row in $found.Values) { $rows.Add($row) }
    $coverage = 'Complete'
    if (@($status.ToArray() | Select-Object -Skip $before | Where-Object Status -ne 'CycleDetected').Count) { $coverage = 'Partial' }
    if (!$rootGroup) { $coverage = 'Failed' }
    foreach ($path in $rootPaths) { $path.CollectionStatus = $coverage; $paths.Add($path) }
    $summary.Add([pscustomobject]@{ Group = $target.Identity; DirectoryServer = $target.Server; UniqueUsers = $found.Count; GroupsVisited = $visited.Count; Status = $coverage })
}
$coverage = 'Complete'
if (@($status | Where-Object Status -ne 'CycleDetected').Count) { $coverage = 'Partial' }
$review = @(
    foreach ($sid in ($users.Keys | Sort-Object)) {
        $info = $users[$sid]
        $userPaths = @($paths | Where-Object SID -eq $sid)
        $accountStatus = 'Unknown'; $upn = ''; $lastLogon = $null; $password = $null
        if ($info.Status -eq 'Success') {
            $accountStatus = 'Disabled'
            if ($info.User.Enabled) { $accountStatus = 'Enabled' }
            $upn = $info.User.UserPrincipalName
            $lastLogon = $info.User.LastLogonDate; $password = $info.User.PasswordLastSet
        }
        [pscustomobject]@{
            SID = $sid; SamAccountName = $info.Name; UserPrincipalName = $upn
            AccountStatus = $accountStatus; LastLogonDate = $lastLogon; PasswordLastSet = $password
            LoginActivity = $info.Activity
            DirectAdministrativeGroups = (($userPaths | Where-Object MembershipType -like 'Direct*' | ForEach-Object { "$($_.PrivilegedGroup) [$($_.RootGroupDN)]" } | Sort-Object -Unique) -join "`n")
            IndirectPaths = (($userPaths | Where-Object MembershipType -like 'Nested*' | ForEach-Object { "$($_.MembershipPath) [$($_.GroupDNPath); $($_.MembershipType)]" }) -join "`n")
            OwnerDecision = ''; Notes = ''; CollectionStatus = $coverage; UserDetailsStatus = $info.Status
        }
    }
)
$reviewColumns = @('SID','SamAccountName','UserPrincipalName','AccountStatus','LastLogonDate','PasswordLastSet','LoginActivity','DirectAdministrativeGroups','IndirectPaths','OwnerDecision','Notes','CollectionStatus','UserDetailsStatus')
Export-AuditCsv -Rows @($rows.ToArray() | Sort-Object PrivilegedGroup,SamAccountName) -Columns SID,DirectoryServer,DomainNetBIOS,SamAccountName,UserPrincipalName,DisplayName,Enabled,ActivityStatus,LastLogonDate,PasswordLastSet,PrivilegedGroup,GroupSID,MembershipType -Path (Join-Path $OutputFolder '01-PrivilegedUsers.csv')
Export-AuditCsv -Rows $summary.ToArray() -Columns Group,DirectoryServer,UniqueUsers,GroupsVisited,Status -Path (Join-Path $OutputFolder '04-PrivilegedGroupSummary.csv')
Export-AuditCsv -Rows @($paths.ToArray() | Sort-Object RootGroupDN,SID,GroupDNPath,MembershipType) -Columns SID,SamAccountName,DirectoryServer,PrivilegedGroup,GroupSID,RootGroupDN,MembershipType,Depth,MembershipPath,GroupSIDPath,GroupDNPath,UserDetailsStatus,CollectionStatus -Path (Join-Path $OutputFolder '02-MembershipPaths.csv')
$reviewCsv = @(
    foreach ($item in $review) {
        $copy = $item.PSObject.Copy()
        foreach ($field in @('LastLogonDate','PasswordLastSet')) {
            if ($copy.$field) { $copy.$field = $copy.$field.ToString('o') }
        }
        $copy
    }
)
Export-AuditCsv -Rows $reviewCsv -Columns $reviewColumns -Path (Join-Path $OutputFolder '02-PrivilegedUserReview.csv')
$notes = @(
    [pscustomobject]@{ Field = 'CollectionStatus'; Value = $coverage }
    [pscustomobject]@{ Field = 'CollectedAt'; Value = $now.ToString('o') }
    [pscustomobject]@{ Field = 'Scope'; Value = "Selected privileged groups in $Server and forest-root groups; not all AD privilege mechanisms." }
    [pscustomobject]@{ Field = 'LastLogonDate'; Value = 'Replicated and approximate (lastLogonTimestamp). May lag; missing does not prove no use. Dates use the collection host local time.' }
    [pscustomobject]@{ Field = 'LoginActivity'; Value = "Independent of Enabled/Disabled. StaleReplicatedLogon: older than $InactiveDays days; Active: recent replicated evidence only." }
    [pscustomobject]@{ Field = 'Paths'; Value = 'All simple paths from selected administrative roots to users; repeated groups stop only that path and cycles are logged. Direction: administrative group -> nested groups -> user.' }
    [pscustomobject]@{ Field = 'Coverage'; Value = 'Partial: missing evidence may affect any user. Read DiscoveryStatus.csv and 04-PrivilegedGroupSummary.csv. Unknown users are omitted only from CSV 01.' }
    [pscustomobject]@{ Field = 'OwnerDecision / Notes'; Value = 'Editable review fields. Copy workbook before individual reruns; Start-Audit archives previous reports.' }
    [pscustomobject]@{ Field = 'Reference'; Value = 'https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp' }
)
$workbookStatus = 'Success'
try { Export-AuditWorkbook -Rows $review -Columns $reviewColumns -Notes $notes -Path (Join-Path $OutputFolder '02-PrivilegedUserReview.xlsx') }
catch {
    $workbookStatus = 'Failed'
    Add-DiscoveryIssue '02-PrivilegedUserReview.xlsx' 'Workbook' 'Failed' $_.Exception.Message
}
Export-AuditCsv -Rows $status.ToArray() -Columns Target,Stage,Status,Message -Path (Join-Path $OutputFolder 'DiscoveryStatus.csv')
Export-AuditCsv -Rows @([pscustomobject]@{ CollectedAt = $now.ToString('o'); CollectionStatus = $coverage; WorkbookStatus = $workbookStatus; UserCount = $review.Count; PathCount = $paths.Count }) -Columns CollectedAt,CollectionStatus,WorkbookStatus,UserCount,PathCount -Path (Join-Path $OutputFolder 'DiscoveryRun.csv')
if ($coverage -ne 'Complete' -or $workbookStatus -ne 'Success') { Write-Warning 'Discovery/export has gaps. Review DiscoveryRun.csv, DiscoveryStatus.csv and the group summary.' }
