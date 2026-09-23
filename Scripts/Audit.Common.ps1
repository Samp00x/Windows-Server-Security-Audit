# Shared helpers. No directory or server changes are performed.
Set-StrictMode -Version Latest

function Get-AuditServerTargets {
    [CmdletBinding()]
    param([string]$Server, [string]$OutputFolder = 'C:\scriptsDC')
    Import-Module ActiveDirectory -ErrorAction Stop
    if (!$Server) { $Server = (Get-ADDomain -Current LocalComputer -ErrorAction Stop).DNSRoot }
    $targets = [System.Collections.Generic.List[object]]::new()
    try {
        $computers = @(Get-ADComputer -Server $Server -Filter 'Enabled -eq $true -and OperatingSystem -like "*Windows*Server*"' -Properties DNSHostName,OperatingSystem -ErrorAction Stop)
        foreach ($computer in $computers) {
            $state = 'Ready'
            if (!$computer.DNSHostName) { $state = 'MissingDNSHostName' }
            $targets.Add([pscustomobject]@{ Name = $computer.Name; DNSHostName = $computer.DNSHostName; Source = 'ADComputer'; Status = $state })
        }
        foreach ($dc in (Get-ADDomainController -Filter * -Server $Server -ErrorAction Stop)) {
            $state = 'Ready'
            if (!$dc.HostName) { $state = 'MissingDNSHostName' }
            $targets.Add([pscustomobject]@{ Name = $dc.Name; DNSHostName = $dc.HostName; Source = 'DomainController'; Status = $state })
        }
    }
    catch {
        $targets.Add([pscustomobject]@{ Name = $Server; DNSHostName = ''; Source = 'Discovery'; Status = "Failed: $($_.Exception.Message)" })
        Export-AuditCsv -Rows $targets.ToArray() -Columns Name,DNSHostName,Source,Status -Path (Join-Path $OutputFolder 'ServerDiscovery.csv')
        throw
    }
    Export-AuditCsv -Rows $targets.ToArray() -Columns Name,DNSHostName,Source,Status -Path (Join-Path $OutputFolder 'ServerDiscovery.csv')
    if (@($targets | Where-Object Status -ne 'Ready').Count) { Write-Warning 'Some AD computer objects have no DNS name. Review ServerDiscovery.csv.' }
    $targets | Where-Object Status -eq 'Ready' | Select-Object -ExpandProperty DNSHostName | Sort-Object -Unique
}

function Export-AuditCsv {
    [CmdletBinding()]
    param([object[]]$Rows, [string[]]$Columns, [string]$Path)
    $parent = Split-Path -Parent $Path
    if (!(Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
    }
    if (@($Rows).Count -gt 0) {
        $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $Path -Delimiter ';' -NoTypeInformation -Encoding UTF8
    }
    else {
        $header = ($Columns | ForEach-Object { '"' + $_ + '"' }) -join ';'
        Set-Content -LiteralPath $Path -Value $header -Encoding UTF8
    }
}

function Import-AuditAccounts {
    param([string]$Path)
    $rows = @(Import-Csv -LiteralPath $Path -Delimiter ';' -ErrorAction Stop)
    if (!$rows.Count) { throw 'Account CSV is empty. Check discovery status before continuing.' }
    foreach ($row in $rows) {
        foreach ($column in @('SID', 'DirectoryServer', 'SamAccountName', 'UserPrincipalName', 'DomainNetBIOS', 'PrivilegedGroup')) {
            if ($row.PSObject.Properties.Name -notcontains $column) { throw "Missing CSV column: $column" }
        }
        if ($row.SID -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or !$row.DirectoryServer) {
            throw 'Each account needs an AD SID and DirectoryServer. Use the discovery report.'
        }
    }
    $rows
}

function Resolve-AuditAccount {
    param([string]$Identity, [object[]]$Accounts)
    # Never discard domain qualifiers or equate local and domain accounts.
    if ([string]::IsNullOrWhiteSpace($Identity)) { return }
    $value = $Identity.Trim()
    $matches = @($Accounts | Where-Object {
        $_.SID -eq $value -or
        ($_.UserPrincipalName -and $_.UserPrincipalName -eq $value) -or
        ($_.DomainNetBIOS -and "$($_.DomainNetBIOS)\$($_.SamAccountName)" -eq $value)
    })
    if ($matches.Count -gt 0 -and @($matches | Select-Object -ExpandProperty SID -Unique).Count -eq 1) {
        $matches | Select-Object -First 1
    }
}

function Get-AuditRiskFinding {
    param($User, [datetime]$Now = (Get-Date), [int]$InactiveDays = 90, [int]$PasswordAgeDays = 180)
    if (!$User.Enabled) { 'DisabledPrivilegedAccount' }
    if (!$User.LastLogonDate) { 'NoReplicatedLogonRecorded' }
    elseif ($User.LastLogonDate -lt $Now.AddDays(-$InactiveDays)) { 'StaleReplicatedLogon' }
    if (!$User.PasswordLastSet) { 'PasswordLastSetMissing' }
    elseif ($User.PasswordLastSet -lt $Now.AddDays(-$PasswordAgeDays)) { 'OldPasswordReview' }
    foreach ($flag in @('PasswordNeverExpires', 'PasswordNotRequired', 'DoesNotRequirePreAuth', 'TrustedForDelegation', 'TrustedToAuthForDelegation')) {
        if ($User.$flag) { $flag }
    }
    if (!$User.AccountNotDelegated) { 'DelegationProtectionNotSet' }
    if (@($User.ServicePrincipalName).Count -gt 0) { 'ServicePrincipalNamePresent' }
    if (@($User.SIDHistory).Count -gt 0) { 'SIDHistoryPresent' }
}
