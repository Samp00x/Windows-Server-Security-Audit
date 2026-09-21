# Windows Server / Active Directory Security Audit

A read-only PowerShell toolkit for reviewing privileged AD users, locating server dependencies, and flagging account settings for human review. It does not remove memberships, disable users, rotate passwords, or change server configuration.

## What it does

| Script | Purpose |
| --- | --- |
| `Scripts/Get-PrivilegedUsers.ps1` | Discover users through direct, nested and primary-group membership; export a compact user report and group coverage summary. |
| `Scripts/Get-PrivilegedAccountDependencies.ps1` | Inspect Services, Scheduled Tasks, IIS app pools, direct local Administrators, and optional running processes on an explicit server list. |
| `Scripts/Get-PrivilegedAccountRisks.ps1` | Re-query users by SID and flag disabled/stale accounts, password settings, Kerberos pre-authentication, delegation, SPNs and SID history. |

Default groups: Domain Admins, Group Policy Creator Owners, Builtin Administrators, Account/Server/Print/Backup Operators, DnsAdmins, and forest-root Schema/Enterprise Admins. Add custom groups with `-AdditionalGroup`. Missing groups are reported as coverage gaps, including DnsAdmins when DNS is not deployed.

## Requirements

- Run in **64-bit Windows PowerShell 5.1** on Windows Server 2016 or newer, or an administrative workstation with RSAT. PowerShell 7 is not the supported audit host.
- Discovery and risk scripts require the `ActiveDirectory` module, DNS/DC connectivity and permission to read the requested directory objects. They use your current Windows identity.
- Server scans require an authorized account with access to the target Windows PowerShell remoting endpoint and the underlying collectors (typically local administrator), WinRM connectivity, and the standard `Microsoft.PowerShell` endpoint. `-Credential (Get-Credential)` is optional for server scans only.
- Targets need CIM, ScheduledTasks and Microsoft.PowerShell.LocalAccounts capabilities. IIS targets also need WebAdministration. Missing modules or denied reads appear as failures.
- Run only within an approved audit scope. Choose an access-controlled report directory. No software is installed or remoting enabled by these scripts.

## Quick start

Clone or download this repository. Open Windows PowerShell at its root. Replace these fictitious names with your approved targets:

```powershell
$run = Join-Path $PWD ('Output/' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
.\Scripts\Get-PrivilegedUsers.ps1 -Server 'dc01.example.test' -OutputFolder $run

# Review DiscoveryStatus.csv and 04-PrivilegedGroupSummary.csv before proceeding.
$accounts = Join-Path $run '01-PrivilegedUsers.csv'
.\Scripts\Get-PrivilegedAccountDependencies.ps1 -PrivilegedCsv $accounts `
    -ComputerName 'app01.example.test','web01.example.test' -OutputFolder $run
.\Scripts\Get-PrivilegedAccountRisks.ps1 -PrivilegedCsv $accounts -OutputFolder $run
```

Add `-ScanProcesses` for a potentially expensive point-in-time process-owner scan. Use `-InactiveDays 90` and `-PasswordAgeDays 180` to tune review thresholds; password age is an organizational review signal, not a universal rotation requirement. Use a fresh folder for each run; matching report names are overwritten.

## Reports and interpretation

All CSVs use UTF-8, semicolon delimiters, stable headers (even with zero results) and ISO 8601 date values where exported. Import with `Import-Csv -Delimiter ';'`.

| Report | Meaning |
| --- | --- |
| `01-PrivilegedUsers.csv` | One row per user SID and privileged root group; includes domain-qualified identity for matching. |
| `04-PrivilegedGroupSummary.csv` | Users found, groups visited and coverage per requested group. Counts are lower bounds when partial. |
| `DiscoveryStatus.csv` | Missing groups, unsupported objects and failed directory reads. |
| `05-PrivilegedAccountDependencies.csv` | Exact SID, UPN or NetBIOS-qualified matches to discovered accounts. |
| `06-ServerScanStatus.csv` | Per-server, per-collector Success, Partial, Failed, Skipped or NotApplicable. |
| `DependencyInventory.csv` | All observed configured identities, including unmatched accounts and group principals for manual follow-up. |
| `07-PrivilegedAccountRisks.csv` | One row per successfully queried SID, with individual review indicators. |
| `RiskQueryStatus.csv` | Success or failure for every requested account query. |

**No matches is not proof that an account is unused.** Review coverage and inventory before making changes. A stopped service or disabled task can still depend on a configured identity. Risk indicators do not establish that access is unnecessary; obtain an owner decision.

## Scope and limitations

- Discovery covers selected groups, not all possible privilege paths. AD ACL delegation, GPO rights, AD CS, trusts, resource ACLs and application permissions need separate assessment. Historical `adminCount` and delegation exports are intentionally outside this compact workflow.
- Run discovery separately for each domain you intend to audit, using separate output folders. Forest-root groups are included, but this is not an automatic forest-wide audit. Foreign security principals and non-user objects are recorded for manual review, not silently treated as users.
- Local Administrators and task group principals are inventoried directly; group members are **not expanded** by the dependency scanner. A privileged user may therefore have indirect local access without appearing in the matched report. Domain controllers have no local SAM Administrators group; review their domain Builtin group.
- Matching never strips domain qualifiers. Bare usernames, aliases not present in the AD report, renamed accounts and unresolved identities require manual validation. `NotMatched` does not mean non-privileged.
- Replicated `LastLogonDate` is approximate and can lag. No recorded logon is not proof of no use. Check all relevant DCs and workload/security logs before concluding inactivity.
- Dependencies outside the listed collectors (scripts, SQL Agent, application credentials, clusters, stored credentials and offline servers) are not covered. Processes are only a snapshot.
- Coverage means the configured query completed; it does not guarantee the querying identity can see every protected resource. Test in a representative lab before production use.

## Repository layout

```text
Scripts/       Audit scripts and shared helpers
Docs/          Audit workflow and troubleshooting
Examples/      Fictitious example CSVs only (EXAMPLE / example.test)
Tests/         Offline regression checks and Windows CI
Output/        Ignored runtime reports; only .gitkeep is tracked
```

See [Audit workflow](Docs/Audit-Workflow.md) and [Troubleshooting](Docs/Troubleshooting.md). Run offline checks with `powershell.exe -NoProfile -File .\Tests\Test-Toolkit.ps1`, then `powershell.exe -NoProfile -File .\Tests\Test-Workflow.ps1`. These check syntax, key logic and simulated workflows; they do not replace a live AD/WinRM test.

## Data handling

No client data is included. Examples are fabricated and are not evidence of a real scan. Runtime output contains sensitive identity and infrastructure information. Keep it in an approved restricted location, apply your retention policy, and review staged changes before committing. `.gitignore` is a convenience, not an access-control or data-loss prevention boundary. Treat CSV values as untrusted text when opening in spreadsheets; use text import to avoid formula interpretation.

## Microsoft references

- [Get-ADGroupMember](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember)
- [Get-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask)
- [Process ownership through Win32_Process](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process)

## Contributing

Keep collectors read-only, preserve identity qualifiers, expose query failures, and add regression coverage for changed behavior. Use fabricated fixtures only. Describe the Windows/AD environment used for live validation in your pull request; do not attach real reports.
