# Shared helpers. No directory or server changes are performed.
Set-StrictMode -Version Latest

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

function Get-AuditDependencyFinding {
    param($Item, [string]$IsPrivileged)
    $severity = 'Informational'
    $classification = 'ConfiguredDependency'
    $reason = 'Configured identity is not in the supplied privileged SID inventory; this does not prove least privilege.'
    if ($Item.Type -eq 'ScheduledTasks') {
        $name = ($Item.Resource -split '\\')[-1]
        $profileName = $name -match '^(OneDrive (Startup|Reporting)( Task)?(?:-|$)|CreateExplorerShellUnelevatedTask(?:-|$)|User_Feed_Synchronization(?:-|$)|GoogleUserPEH(?:Core)?(?:Task)?(?:-|$))'
        if ($profileName -and $Item.LogonType -in @('Interactive','InteractiveToken','3')) {
            return [pscustomobject]@{ Severity = 'Informational'; Classification = 'UserProfileArtifact'; Reason = 'Known per-user task name with interactive logon. Evidence of a user profile, not an unattended service-account dependency. Name is a heuristic, not a trust decision; inspect actions if unexpected.' }
        }
        if ($profileName) {
            return [pscustomobject]@{ Severity = 'Review'; Classification = 'Review'; Reason = 'Profile-like task name with non-interactive or unknown logon type; verify its principal and actions before treating it as a profile artifact.' }
        }
        if ($IsPrivileged -eq 'True') {
            $severity = 'High'
            if ($Item.State -eq 'Disabled') { $severity = 'Review' }
            $reason = 'Scheduled task is configured with a privileged SID. Validate workload ownership and required rights before changing the account.'
        }
    }
    elseif ($Item.Type -eq 'Services' -and $IsPrivileged -eq 'True') {
        $severity = 'Review'
        $reason = 'Service retains a privileged account configuration. It may need this identity at its next start; validate before account changes.'
        if ($Item.State -eq 'Running') {
            $severity = 'High'
            if ($Item.StartMode -in @('Auto','Automatic') -and $Item.ResolvedAccountType -eq 'Domain') { $severity = 'Critical' }
            $reason = 'Running Windows service uses a privileged account. Compromise can expose its privileges and account changes can interrupt the workload; migrate to a dedicated least-privilege identity after validation.'
        }
    }
    if ($Item.Type -eq 'Services' -and $Item.State -eq 'Stopped' -and $Item.StartMode -in @('Auto','Automatic')) {
        $severity = 'Review'
        $reason = 'Automatic service is stopped but retains a configured identity. Validate its expected startup behavior and account dependency before changes.'
    }
    if ($Item.ResolvedAccountType -eq 'Unresolved' -or $IsPrivileged -eq 'Unknown') {
        $severity = 'Review'
        $reason = 'Identity resolution is incomplete. Privilege and account scope cannot be cleared; inspect ResolutionError and scan coverage.'
    }
    elseif ($Item.ResolvedAccountType -eq 'Local') {
        $reason += ' Target-local account is distinct from a same-named domain account; review local rights separately.'
    }
    elseif ($Item.ResolvedAccountType -eq 'BuiltIn') {
        $reason += ' Windows built-in or virtual identity; Informational does not imply low local privileges.'
    }
    [pscustomobject]@{ Severity = $severity; Classification = $classification; Reason = $reason }
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
