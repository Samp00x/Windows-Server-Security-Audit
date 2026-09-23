#requires -Version 5.1
[CmdletBinding()]
param([string]$KeepOutput)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('audit-paths-' + [guid]::NewGuid())
$fixtureMode = 'Normal'
$domainSid = 'S-1-5-21-1000000001-1000000002-1000000003'
$groupNames = @{ '512' = 'Domain Admins'; '1200' = 'Team A'; '1201' = 'Team B'; '1202' = 'Shared' }
$checks = 0
function Assert-PathTest {
    param([bool]$Condition, [string]$Message)
    if (!$Condition) { throw "FAIL: $Message" }
    $script:checks++
}
function Import-Module { param($Name,$ErrorAction) }
function Get-ADDomain { param($Server,$Current) [pscustomobject]@{ DNSRoot = 'example.test'; DomainSID = $domainSid; NetBIOSName = 'EXAMPLE' } }
function Get-ADForest { param($Server) [pscustomobject]@{ RootDomain = 'example.test' } }
function Get-ADGroup {
    param($Identity,$Server)
    $rid = ([string]$Identity -split '-')[-1]
    foreach ($key in $groupNames.Keys) {
        if ($Identity -eq "CN=$($groupNames[$key]),DC=example,DC=test") { $rid = $key }
    }
    $name = "Empty-$rid"
    if ($groupNames.ContainsKey($rid)) { $name = $groupNames[$rid] }
    [pscustomobject]@{ Name = $name; SID = [pscustomobject]@{ Value = "$domainSid-$rid" }; DistinguishedName = "CN=$name,DC=example,DC=test"; objectClass = 'group' }
}
function New-FixtureUser {
    param([string]$Name)
    $rid = '1101'; $logon = (Get-Date).AddDays(-1)
    if ($Name -eq 'bob') { $rid = '1102'; $logon = $null }
    [pscustomobject]@{
        SID = [pscustomobject]@{ Value = "$domainSid-$rid" }; DistinguishedName = "CN=$Name,DC=example,DC=test"
        objectClass = 'user'; SamAccountName = $Name; UserPrincipalName = "$Name@example.test"; DisplayName = "Fictitious $Name"
        Enabled = $false; LastLogonDate = $logon; PasswordLastSet = (Get-Date).AddDays(-30)
    }
}
function Get-ADUser {
    param($Identity,$Server,$Properties,$LDAPFilter)
    if ($LDAPFilter) {
        if ($LDAPFilter -eq '(primaryGroupID=1202)' -and $fixtureMode -ne 'Empty') {
            if ($fixtureMode -eq 'PrimaryFailure') { throw 'Simulated primary-group failure' }
            New-FixtureUser bob
        }
        return
    }
    if ($Identity -like '*bob*') {
        if ($fixtureMode -eq 'UserFailure') { throw 'Simulated user read denial' }
        New-FixtureUser bob
    }
    else { New-FixtureUser alice }
}
function Get-ADGroupMember {
    param($Identity,$Server)
    if ($fixtureMode -eq 'Empty') { return }
    switch ($Identity.Name) {
        'Domain Admins' {
            New-FixtureUser alice
            Get-ADGroup "$domainSid-1200"
            Get-ADGroup "$domainSid-1201"
        }
        'Team A' {
            if ($fixtureMode -eq 'BranchFailure') { throw 'Simulated branch denial' }
            Get-ADGroup "$domainSid-1202"
            Get-ADGroup "$domainSid-1200" # Self-cycle
        }
        'Team B' { Get-ADGroup "$domainSid-1202" }
        'Shared' {
            New-FixtureUser alice
            Get-ADGroup "$domainSid-1201" # Longer cycle
        }
    }
}
try {
    & "$root/Scripts/Get-PrivilegedUsers.ps1" -Server example.test -OutputFolder $temp
    $paths = @(Import-Csv (Join-Path $temp '02-MembershipPaths.csv') -Delimiter ';')
    $review = @(Import-Csv (Join-Path $temp '02-PrivilegedUserReview.csv') -Delimiter ';')
    $csv01 = @(Import-Csv (Join-Path $temp '01-PrivilegedUsers.csv') -Delimiter ';')
    Assert-PathTest ($paths.Count -eq 5) 'All five paths, including alternative paths to shared group and primary-group user'
    Assert-PathTest (@($paths | Where-Object SamAccountName -eq 'alice').Count -eq 3) 'Alice has direct and two indirect paths'
    Assert-PathTest (@($paths | Where-Object MembershipType -eq 'NestedPrimaryGroup').Count -eq 2) 'Both primary-group routes retained'
    Assert-PathTest ($review.Count -eq 2 -and $csv01.Count -eq 2) 'One review row per SID and one CSV01 row per user/root'
    $alice = $review | Where-Object SamAccountName -eq 'alice'
    Assert-PathTest ($alice.AccountStatus -eq 'Disabled' -and $alice.LoginActivity -eq 'Active') 'Disabled status independent of recent replicated login'
    Assert-PathTest ($alice.IndirectPaths -like '*Team A*' -and $alice.IndirectPaths -like '*Team B*') 'Review includes both alternate routes'
    Assert-PathTest ($alice.DirectAdministrativeGroups -like '*Domain Admins*' -and !$alice.OwnerDecision -and !$alice.Notes) 'Direct group and blank editable review fields'
    Assert-PathTest (($csv01 | Where-Object SamAccountName -eq 'alice').MembershipType -eq 'Direct') 'CSV01 prefers direct membership'
    Assert-PathTest (($csv01[0].PSObject.Properties.Name -join ',') -eq 'SID,DirectoryServer,DomainNetBIOS,SamAccountName,UserPrincipalName,DisplayName,Enabled,ActivityStatus,LastLogonDate,PasswordLastSet,PrivilegedGroup,GroupSID,MembershipType') 'Exact CSV01 header contract'
    $issues = @(Import-Csv (Join-Path $temp 'DiscoveryStatus.csv') -Delimiter ';')
    Assert-PathTest (@($issues | Where-Object Status -eq 'CycleDetected').Count -ge 2) 'Self and multi-group cycles logged'
    $run = Import-Csv (Join-Path $temp 'DiscoveryRun.csv') -Delimiter ';'
    Assert-PathTest ($run.CollectionStatus -eq 'Complete' -and $run.WorkbookStatus -eq 'Success') 'Cycle handling preserves complete simple-path enumeration'
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $temp '02-PrivilegedUserReview.xlsx'))
    try {
        foreach ($entry in $zip.Entries) {
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try { $text = $reader.ReadToEnd(); $document = [xml]$text } finally { $reader.Dispose() }
            Assert-PathTest ($null -ne $document.DocumentElement) "Valid XML part $($entry.FullName)"
            if ($entry.FullName -eq 'xl/worksheets/sheet1.xml') {
                Assert-PathTest ($document.worksheet.sheetData.row.Count -eq 3) 'Workbook one row per user plus header'
                Assert-PathTest ($text -match 's="4"' -and $text -notmatch '<f>') 'Typed dates and no executable formulas'
                Assert-PathTest ($text -match 'state="frozen"' -and $text -match '<autoFilter') 'Frozen header and filter'
            }
        }
    }
    finally { $zip.Dispose() }
    if ($KeepOutput) {
        New-Item -ItemType Directory -Path $KeepOutput -Force | Out-Null
        foreach ($file in (Get-ChildItem -LiteralPath $temp -File)) { Copy-Item -LiteralPath $file.FullName -Destination $KeepOutput }
    }
    & "$root/Scripts/Get-PrivilegedUsers.ps1" -Server example.test -AdditionalGroup "$domainSid-1201" -OutputFolder $temp
    Assert-PathTest (@(Import-Csv (Join-Path $temp '02-PrivilegedUserReview.csv') -Delimiter ';').Count -eq 2) 'Review consolidates users across administrative roots'
    Assert-PathTest (@(Import-Csv (Join-Path $temp '01-PrivilegedUsers.csv') -Delimiter ';').Count -eq 4) 'CSV01 preserves one row per user and administrative root'
    Assert-PathTest (@(Import-Csv (Join-Path $temp '02-MembershipPaths.csv') -Delimiter ';').Count -eq 7) 'All paths from additional administrative root retained'
    foreach ($mode in @('BranchFailure','PrimaryFailure','UserFailure')) {
        $fixtureMode = $mode
        & "$root/Scripts/Get-PrivilegedUsers.ps1" -Server example.test -OutputFolder $temp
        $run = Import-Csv (Join-Path $temp 'DiscoveryRun.csv') -Delimiter ';'
        Assert-PathTest ($run.CollectionStatus -eq 'Partial') "$mode marks global coverage partial"
        $partial = @(Import-Csv (Join-Path $temp '02-PrivilegedUserReview.csv') -Delimiter ';')
        Assert-PathTest (@($partial | Where-Object CollectionStatus -ne 'Partial').Count -eq 0) "$mode never labels review complete"
        Assert-PathTest (@(Import-Csv (Join-Path $temp '02-MembershipPaths.csv') -Delimiter ';').Count -gt 0) "$mode preserves other membership evidence"
        if ($mode -eq 'UserFailure') {
            $bob = $partial | Where-Object SamAccountName -eq 'bob'
            Assert-PathTest ($bob.AccountStatus -eq 'Unknown' -and $bob.UserDetailsStatus -eq 'Failed') 'Unreadable user remains visible as Unknown'
            Assert-PathTest (@(Import-Csv (Join-Path $temp '01-PrivilegedUsers.csv') -Delimiter ';').Count -eq 1) 'Unreadable user excluded from CSV01 as before'
        }
    }
    $fixtureMode = 'Empty'
    & "$root/Scripts/Get-PrivilegedUsers.ps1" -Server example.test -OutputFolder $temp
    Assert-PathTest (@(Import-Csv (Join-Path $temp '02-PrivilegedUserReview.csv') -Delimiter ';').Count -eq 0) 'Empty review is valid header-only CSV'
    Assert-PathTest ((Import-Csv (Join-Path $temp 'DiscoveryRun.csv') -Delimiter ';').WorkbookStatus -eq 'Success') 'Empty workbook exports successfully'
    . "$root/Scripts/Export-AuditWorkbook.ps1"
    $literal = '=SUM(1,2) & <test> ' + [char]0x00E7 + "`nline two"
    Export-AuditWorkbook -Rows @([pscustomobject]@{ Value = $literal }) -Columns Value -Notes @() -Path (Join-Path $temp 'literal.xlsx')
    $literalZip = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $temp 'literal.xlsx'))
    try {
        $reader = [System.IO.StreamReader]::new($literalZip.GetEntry('xl/worksheets/sheet1.xml').Open())
        try { $literalXml = [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
        Assert-PathTest ($literalXml.worksheet.sheetData.row[1].c.is.t.InnerText -eq $literal) 'Formula-like strings, XML characters, Unicode and newlines remain literal text'
    }
    finally { $literalZip.Dispose() }
    $large = [pscustomobject]@{ Value = ('x' * 32768) }
    $rejected = $false
    try { Export-AuditWorkbook -Rows @($large) -Columns Value -Notes @() -Path (Join-Path $temp '02-PrivilegedUserReview.xlsx') } catch { $rejected = $true }
    Assert-PathTest $rejected 'Oversized cells rejected without silent truncation'
    Assert-PathTest (!(Test-Path (Join-Path $temp '02-PrivilegedUserReview.xlsx'))) 'Failed export does not leave a stale workbook'
    Write-Output "PASS: $checks membership-path and workbook checks. No live AD calls were made."
}
finally {
    if (Test-Path -LiteralPath $temp) {
        Get-ChildItem -LiteralPath $temp -File -Recurse | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
        Get-ChildItem -LiteralPath $temp -Directory -Recurse | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
        Remove-Item -LiteralPath $temp
    }
}
