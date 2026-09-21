#requires -Version 5.1
<#
.SYNOPSIS
Scans an explicit server list for configured privileged account dependencies.
.DESCRIPTION
Uses Windows PowerShell remoting. Collectors run independently and report gaps.
Local Administrators is identified by SID; membership is direct only.
.EXAMPLE
.\Get-PrivilegedAccountDependencies.ps1 -PrivilegedCsv .\Output\01-Privileged-Users.csv -ComputerName web01.example.test -ScanProcesses
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PrivilegedCsv,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$ComputerName,
    [pscredential]$Credential,
    [switch]$ScanProcesses,
    [ValidateRange(10,3600)][int]$OperationTimeoutSeconds = 180,
    [string]$OutputFolder = (Join-Path $PSScriptRoot '../Output')
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Audit.Common.ps1"
$accounts = @(Import-AuditAccounts $PrivilegedCsv)
$results = [System.Collections.Generic.List[object]]::new()
$services = [System.Collections.Generic.List[object]]::new()
$tasks = [System.Collections.Generic.List[object]]::new()
$inventory = [System.Collections.Generic.List[object]]::new()
$status = [System.Collections.Generic.List[object]]::new()
$identityCode = Get-Content -LiteralPath "$PSScriptRoot/Audit.Identity.ps1" -Raw
$collector = {
    param([bool]$IncludeProcesses, [string]$IdentityCode)
    $ErrorActionPreference = 'Stop'
    . ([scriptblock]::Create($IdentityCode))
    $identityCache = @{}
    $system = $null
    $systemError = ''
    try { $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
    catch { $systemError = $_.Exception.Message }
    function New-InventoryRow {
        param($Type, $Resource, $Account, $State, $Details, $DisplayName = '', $StartMode = '', $LogonType = '')
        $key = [string]$Account
        if (!$identityCache.ContainsKey($key)) {
            if ($system) {
                $identityCache[$key] = Resolve-TargetAuditIdentity -Identity $key -MachineName $system.Name -DomainRole $system.DomainRole
            }
            else {
                $identityCache[$key] = [pscustomobject]@{ ResolvedAccountType = 'Unresolved'; ResolvedDomain = ''; ResolvedSamAccountName = ''; AccountSID = ''; ResolutionStatus = 'Unresolved'; ResolutionError = "Target context unavailable: $systemError" }
            }
        }
        $resolved = $identityCache[$key]
        [pscustomobject]@{
            Kind = 'Inventory'; Type = $Type; Resource = $Resource; Account = $key; State = [string]$State; Details = [string]$Details
            DisplayName = $DisplayName; StartMode = $StartMode; LogonType = [string]$LogonType
            ResolvedAccountType = $resolved.ResolvedAccountType; ResolvedDomain = $resolved.ResolvedDomain
            ResolvedSamAccountName = $resolved.ResolvedSamAccountName; AccountSID = $resolved.AccountSID
            ResolutionStatus = $resolved.ResolutionStatus; ResolutionError = $resolved.ResolutionError
        }
    }
    foreach ($type in @('Services','ScheduledTasks','IIS','LocalAdministrators','Processes')) {
        $coverage = 'Success'
        $message = ''
        try {
            switch ($type) {
                'Services' {
                    foreach ($service in (Get-CimInstance Win32_Service)) {
                        New-InventoryRow $type $service.Name $service.StartName $service.State "StartMode=$($service.StartMode)" $service.DisplayName $service.StartMode
                    }
                }
                'ScheduledTasks' {
                    foreach ($task in (Get-ScheduledTask)) {
                        $identity = $task.Principal.UserId
                        if (!$identity) { $identity = $task.Principal.GroupId }
                        New-InventoryRow $type "$($task.TaskPath)$($task.TaskName)" $identity $task.State "LogonType=$($task.Principal.LogonType);RunLevel=$($task.Principal.RunLevel)" '' '' $task.Principal.LogonType
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
        Invoke-Command -Session $session -ScriptBlock $collector -ArgumentList ([bool]$ScanProcesses),$identityCode -ErrorAction Stop | ForEach-Object {
            $item = $_
            if ($item.Kind -eq 'Status') {
                $seen[$item.Type] = $true
                $status.Add([pscustomobject]@{ Server = $computer; Collector = $item.Type; Status = $item.Status; Message = $item.Message })
            }
            else {
                # SID is authoritative; never turn an unresolved name into a confirmed dependency.
                $match = Resolve-AuditAccount -Identity $item.AccountSID -Accounts $accounts
                $classification = 'NotMatched'
                if (!$item.Account -or ($item.Account -notmatch '\\|@|^S-1-')) { $classification = 'UnqualifiedOrBuiltIn' }
                if ($match) { $classification = 'Matched' }
                $groups = (($accounts | Where-Object SID -eq $item.AccountSID | Select-Object -ExpandProperty PrivilegedGroup -Unique) -join ' | ')
                $privileged = 'Unknown'
                if ($item.ResolutionStatus -eq 'Resolved') { $privileged = 'False' }
                if ($match) { $privileged = 'True' }
                $finding = Get-AuditDependencyFinding -Item $item -IsPrivileged $privileged
                $inventory.Add([pscustomobject]@{ Server = $computer; UsageType = $item.Type; Resource = $item.Resource; AccountConfigured = $item.Account; ResourceStatus = $item.State; MatchStatus = $classification; AccountSID = $item.AccountSID; ResolutionStatus = $item.ResolutionStatus; ResolutionError = $item.ResolutionError; Details = $item.Details })
                $row = [pscustomobject]@{
                    Server = $computer; ServiceName = $item.Resource; DisplayName = $item.DisplayName; State = $item.State
                    StartMode = $item.StartMode; StartNameRaw = $item.Account; ResolvedAccountType = $item.ResolvedAccountType
                    ResolvedDomain = $item.ResolvedDomain; ResolvedSamAccountName = $item.ResolvedSamAccountName; AccountSID = $item.AccountSID
                    IsPrivileged = $privileged; PrivilegedGroups = $groups; DependencySeverity = $finding.Severity; WhyItMatters = $finding.Reason
                    TaskPathAndName = $item.Resource; PrincipalRaw = $item.Account; LogonType = $item.LogonType
                    DependencyClassification = $finding.Classification; ResolutionStatus = $item.ResolutionStatus; ResolutionError = $item.ResolutionError
                }
                if ($item.Type -eq 'Services') { $services.Add($row) }
                elseif ($item.Type -eq 'ScheduledTasks') { $tasks.Add($row) }
                elseif ($match) {
                    $results.Add([pscustomobject]@{
                        Server = $computer; UsageType = $item.Type; Resource = $item.Resource; AccountConfigured = $item.Account
                        SID = $match.SID; SamAccountName = $match.SamAccountName; ResourceStatus = $item.State
                        PrivilegedGroups = $groups
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
    foreach ($type in @('Services','ScheduledTasks','IIS','LocalAdministrators','Processes')) {
        $unresolved = @($inventory | Where-Object { $_.Server -eq $computer -and $_.UsageType -eq $type -and $_.ResolutionStatus -ne 'Resolved' }).Count
        foreach ($entry in ($status | Where-Object { $_.Server -eq $computer -and $_.Collector -eq $type })) {
            $entry | Add-Member -NotePropertyName ObservedCount -NotePropertyValue (@($inventory | Where-Object { $_.Server -eq $computer -and $_.UsageType -eq $type }).Count)
            $entry | Add-Member -NotePropertyName UnresolvedIdentityCount -NotePropertyValue $unresolved
            if ($unresolved) {
                if ($entry.Status -eq 'Success') { $entry.Status = 'Partial' }
                $entry.Message = ($entry.Message + " $unresolved configured identities unresolved; see inventory resolution errors.").Trim()
            }
        }
    }
}
$severityOrder = @{ Critical = 0; High = 1; Review = 2; Informational = 3 }
$orderedServices = @($services | Sort-Object @{ Expression = { $severityOrder[$_.DependencySeverity] } },Server,ServiceName)
Export-AuditCsv -Rows $orderedServices -Columns Server,ServiceName,DisplayName,State,StartMode,StartNameRaw,ResolvedAccountType,ResolvedDomain,ResolvedSamAccountName,AccountSID,IsPrivileged,PrivilegedGroups,DependencySeverity,WhyItMatters,ResolutionStatus,ResolutionError -Path (Join-Path $OutputFolder '03-Privileged-Service-Dependencies.csv')
Export-AuditCsv -Rows $tasks.ToArray() -Columns Server,TaskPathAndName,State,PrincipalRaw,LogonType,ResolvedAccountType,ResolvedDomain,ResolvedSamAccountName,AccountSID,IsPrivileged,PrivilegedGroups,DependencyClassification,DependencySeverity,WhyItMatters,ResolutionStatus,ResolutionError -Path (Join-Path $OutputFolder '04-Scheduled-Task-Dependencies.csv')
Export-AuditCsv -Rows $results.ToArray() -Columns Server,UsageType,Resource,AccountConfigured,SID,SamAccountName,ResourceStatus,PrivilegedGroups,Details -Path (Join-Path $OutputFolder 'Other-Privileged-Dependencies.csv')
Export-AuditCsv -Rows $status.ToArray() -Columns Server,Collector,Status,ObservedCount,UnresolvedIdentityCount,Message -Path (Join-Path $OutputFolder '05-Server-Scan-Status.csv')
Export-AuditCsv -Rows $inventory.ToArray() -Columns Server,UsageType,Resource,AccountConfigured,ResourceStatus,MatchStatus,AccountSID,ResolutionStatus,ResolutionError,Details -Path (Join-Path $OutputFolder 'DependencyInventory.csv')
if (@($status | Where-Object { $_.Status -in @('Failed','Partial') }).Count) { Write-Warning 'Server coverage is incomplete. Review 05-Server-Scan-Status.csv.' }
