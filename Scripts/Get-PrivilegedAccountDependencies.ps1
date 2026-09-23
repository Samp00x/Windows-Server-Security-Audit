#requires -Version 5.1
<#
.SYNOPSIS
Discovers servers through AD and scans configured privileged account dependencies.
.DESCRIPTION
Uses Windows PowerShell remoting. Collectors run independently and report gaps.
Local Administrators is identified by SID; membership is direct only.
.EXAMPLE
.\Get-PrivilegedAccountDependencies.ps1
#>
[CmdletBinding()]
param(
    [string]$PrivilegedCsv,
    [ValidateNotNullOrEmpty()][string[]]$ComputerName,
    [string]$Server,
    [pscredential]$Credential,
    [switch]$ScanProcesses,
    [ValidateRange(10,3600)][int]$OperationTimeoutSeconds = 180,
    [string]$OutputFolder = 'C:\scriptsDC'
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Audit.Common.ps1"
if (!$PrivilegedCsv) { $PrivilegedCsv = Join-Path $OutputFolder '01-PrivilegedUsers.csv' }
$accounts = @(Import-AuditAccounts $PrivilegedCsv)
if (!$ComputerName) { $ComputerName = @(Get-AuditServerTargets -Server $Server -OutputFolder $OutputFolder) }
if (!$ComputerName.Count) { throw 'No enabled Windows servers or domain controllers were found. Review ServerDiscovery.csv.' }
$results = [System.Collections.Generic.List[object]]::new()
$inventory = [System.Collections.Generic.List[object]]::new()
$status = [System.Collections.Generic.List[object]]::new()
$collector = {
    param([bool]$IncludeProcesses)
    $ErrorActionPreference = 'Stop'
    function New-InventoryRow {
        param($Type, $Resource, $Account, $State, $Details)
        [pscustomobject]@{ Kind = 'Inventory'; Type = $Type; Resource = $Resource; Account = [string]$Account; State = [string]$State; Details = [string]$Details }
    }
    foreach ($type in @('Services','ScheduledTasks','IIS','LocalAdministrators','Processes')) {
        $coverage = 'Success'
        $message = ''
        try {
            switch ($type) {
                'Services' {
                    foreach ($service in (Get-CimInstance Win32_Service)) {
                        New-InventoryRow $type $service.Name $service.StartName $service.State "StartMode=$($service.StartMode)"
                    }
                }
                'ScheduledTasks' {
                    foreach ($task in (Get-ScheduledTask)) {
                        $identity = $task.Principal.UserId
                        if (!$identity) { $identity = $task.Principal.GroupId }
                        New-InventoryRow $type "$($task.TaskPath)$($task.TaskName)" $identity $task.State "LogonType=$($task.Principal.LogonType);RunLevel=$($task.Principal.RunLevel)"
                    }
                }
                'IIS' {
                    $config = Join-Path $env:windir 'System32/inetsrv/config/applicationHost.config'
                    if (!(Test-Path -LiteralPath $config)) {
                        $coverage = 'NotApplicable'; $message = 'IIS configuration not present.'
                    }
                    else {
                        Import-Module WebAdministration -ErrorAction Stop
                        foreach ($pool in (Get-ChildItem IIS:\AppPools)) {
                            $identity = [string]$pool.processModel.identityType
                            $account = "IIS APPPOOL\$($pool.Name)"
                            if ($identity -eq 'SpecificUser' -or $identity -eq '3') { $account = $pool.processModel.userName }
                            elseif ($identity -ne 'ApplicationPoolIdentity' -and $identity -ne '4') { $account = $identity }
                            New-InventoryRow $type $pool.Name $account $pool.State "IdentityType=$identity"
                        }
                    }
                }
                'LocalAdministrators' {
                    $system = Get-CimInstance Win32_ComputerSystem
                    if ($system.DomainRole -ge 4) {
                        $coverage = 'NotApplicable'; $message = 'Domain controller: review domain Builtin Administrators in discovery.'
                    }
                    else {
                        foreach ($member in (Get-LocalGroupMember -SID 'S-1-5-32-544')) {
                            New-InventoryRow $type 'S-1-5-32-544' $member.SID.Value 'DirectMember' "Name=$($member.Name);ObjectClass=$($member.ObjectClass)"
                        }
                    }
                }
                'Processes' {
                    if (!$IncludeProcesses) { $coverage = 'Skipped'; $message = 'Use -ScanProcesses to enable.' }
                    else {
                        $failed = 0
                        foreach ($process in (Get-CimInstance Win32_Process)) {
                            try {
                                $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
                                if ($owner.ReturnValue -ne 0 -or !$owner.User) { $failed++; continue }
                                New-InventoryRow $type "$($process.Name):$($process.ProcessId)" "$($owner.Domain)\$($owner.User)" 'Running' 'Point-in-time owner'
                            }
                            catch { $failed++ }
                        }
                        if ($failed) { $coverage = 'Partial'; $message = "$failed process owners unavailable (access denied or process exited)." }
                    }
                }
            }
        }
        catch { $coverage = 'Failed'; $message = $_.Exception.Message }
        [pscustomobject]@{ Kind = 'Status'; Type = $type; Status = $coverage; Message = $message }
    }
}
foreach ($computer in ($ComputerName | Sort-Object -Unique)) {
    if ([string]::IsNullOrWhiteSpace($computer)) { throw 'ComputerName contains an empty target.' }
    $session = $null
    $seen = @{}
    try {
        $options = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout ($OperationTimeoutSeconds * 1000)
        $parameters = @{ ComputerName = $computer; ConfigurationName = 'Microsoft.PowerShell'; SessionOption = $options; ErrorAction = 'Stop' }
        if ($Credential) { $parameters.Credential = $Credential }
        $session = New-PSSession @parameters
        Invoke-Command -Session $session -ScriptBlock $collector -ArgumentList ([bool]$ScanProcesses) -ErrorAction Stop | ForEach-Object {
            $item = $_
            if ($item.Kind -eq 'Status') {
                $seen[$item.Type] = $true
                $status.Add([pscustomobject]@{ Server = $computer; Collector = $item.Type; Status = $item.Status; Message = $item.Message })
            }
            else {
                $match = Resolve-AuditAccount -Identity $item.Account -Accounts $accounts
                $classification = 'NotMatched'
                if (!$item.Account -or ($item.Account -notmatch '\\|@|^S-1-')) { $classification = 'UnqualifiedOrBuiltIn' }
                if ($match) { $classification = 'Matched' }
                $inventory.Add([pscustomobject]@{ Server = $computer; UsageType = $item.Type; Resource = $item.Resource; AccountConfigured = $item.Account; ResourceStatus = $item.State; MatchStatus = $classification; Details = $item.Details })
                if ($match) {
                    $results.Add([pscustomobject]@{
                        Server = $computer; UsageType = $item.Type; Resource = $item.Resource; AccountConfigured = $item.Account
                        SID = $match.SID; SamAccountName = $match.SamAccountName; ResourceStatus = $item.State
                        PrivilegedGroups = (($accounts | Where-Object SID -eq $match.SID | Select-Object -ExpandProperty PrivilegedGroup -Unique) -join ' | ')
                        Details = $item.Details
                    })
                }
            }
        }
    }
    catch {
        foreach ($type in @('Services','ScheduledTasks','IIS','LocalAdministrators','Processes')) {
            if (!$seen.ContainsKey($type)) {
                $status.Add([pscustomobject]@{ Server = $computer; Collector = $type; Status = 'Failed'; Message = $_.Exception.Message })
            }
        }
    }
    finally { if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } }
}
Export-AuditCsv -Rows $results.ToArray() -Columns Server,UsageType,Resource,AccountConfigured,SID,SamAccountName,ResourceStatus,PrivilegedGroups,Details -Path (Join-Path $OutputFolder '05-PrivilegedAccountDependencies.csv')
Export-AuditCsv -Rows $status.ToArray() -Columns Server,Collector,Status,Message -Path (Join-Path $OutputFolder '06-ServerScanStatus.csv')
Export-AuditCsv -Rows $inventory.ToArray() -Columns Server,UsageType,Resource,AccountConfigured,ResourceStatus,MatchStatus,Details -Path (Join-Path $OutputFolder 'DependencyInventory.csv')
if (@($status | Where-Object { $_.Status -in @('Failed','Partial') }).Count) { Write-Warning 'Server coverage is incomplete. Review 06-ServerScanStatus.csv.' }
