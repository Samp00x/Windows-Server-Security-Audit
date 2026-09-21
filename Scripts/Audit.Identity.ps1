# Loaded on the target server: local identity translation must never run on the audit host.
function ConvertTo-AuditSid {
    param([string]$Identity)
    if ($Identity -match '^S-1-') {
        return [System.Security.Principal.SecurityIdentifier]::new($Identity)
    }
    [System.Security.Principal.NTAccount]::new($Identity).Translate([System.Security.Principal.SecurityIdentifier])
}

function ConvertFrom-AuditSid {
    param($Sid)
    $Sid.Translate([System.Security.Principal.NTAccount]).Value
}

function Resolve-TargetAuditIdentity {
    param([string]$Identity, [string]$MachineName, [int]$DomainRole)
    $result = [ordered]@{
        ResolvedAccountType = 'Unresolved'; ResolvedDomain = ''; ResolvedSamAccountName = ''
        AccountSID = ''; ResolutionStatus = 'Unresolved'; ResolutionError = ''
    }
    try {
        $value = $Identity.Trim()
        if (!$value) { throw 'No configured identity.' }
        switch -Regex ($value) {
            '^(LocalSystem|SYSTEM|NT AUTHORITY\\SYSTEM)$' { $value = 'S-1-5-18'; break }
            '^(LocalService|NT AUTHORITY\\LOCAL ?SERVICE)$' { $value = 'S-1-5-19'; break }
            '^(NetworkService|NT AUTHORITY\\NETWORK ?SERVICE)$' { $value = 'S-1-5-20'; break }
        }
        if ($value.StartsWith('.\')) { $value = $MachineName + $value.Substring(1) }
        if ($value -notmatch '\\|@|^S-1-') { throw 'Unqualified name: domain/local scope is ambiguous.' }
        $sid = ConvertTo-AuditSid $value
        $result.AccountSID = $sid.Value
        $qualified = ConvertFrom-AuditSid $sid
        $parts = $qualified -split '\\', 2
        if ($parts.Count -ne 2) { throw 'SID did not resolve to a qualified account.' }
        $result.ResolvedDomain = $parts[0]
        $result.ResolvedSamAccountName = $parts[1]
        if ($sid.Value -match '^S-1-5-(18|19|20)$|^S-1-5-(32|80|82)-') {
            $result.ResolvedAccountType = 'BuiltIn'
        }
        elseif ($sid.Value -match '^S-1-5-21-') {
            if ($parts[0] -eq $MachineName -and $DomainRole -lt 4) { $result.ResolvedAccountType = 'Local' }
            else { $result.ResolvedAccountType = 'Domain' }
        }
        else { throw 'Identity namespace is not classified by this toolkit.' }
        $result.ResolutionStatus = 'Resolved'
    }
    catch { $result.ResolutionError = $_.Exception.Message }
    [pscustomobject]$result
}
