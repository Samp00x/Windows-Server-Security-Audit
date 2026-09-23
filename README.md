# Windows Server / Active Directory Security Audit

**English** | [Português (Brasil)](README.pt-BR.md) | [Guia rápido em português](Docs/Guia-Rapido.pt-BR.md)

A read-only PowerShell toolkit for reviewing privileged AD users, locating server dependencies, and flagging account settings for human review. It does not remove memberships, disable users, rotate passwords, or change server configuration.

## What it does

| Script | Purpose |
| --- | --- |
| `Scripts/Get-PrivilegedUsers.ps1` | Discover users through direct, nested and primary-group membership; export a compact user report and group coverage summary. |
| `Scripts/Get-PrivilegedAccountDependencies.ps1` | Inspect Services, Scheduled Tasks, IIS app pools, direct local Administrators, and optional running processes on servers discovered through AD or optionally supplied. |
| `Scripts/Get-PrivilegedAccountRisks.ps1` | Re-query users by SID and flag disabled/stale accounts, password settings, Kerberos pre-authentication, delegation, SPNs and SID history. |

Default groups: Domain Admins, Group Policy Creator Owners, Builtin Administrators, Account/Server/Print/Backup Operators, DnsAdmins, and forest-root Schema/Enterprise Admins. Add custom groups with `-AdditionalGroup`. Missing groups are reported as coverage gaps, including DnsAdmins when DNS is not deployed.

## Requirements

- Run in **64-bit Windows PowerShell 5.1** on Windows Server 2016 or newer, or an administrative workstation with RSAT. PowerShell 7 is not the supported audit host.
- Discovery and risk scripts require the `ActiveDirectory` module, DNS/DC connectivity and permission to read the requested directory objects. They use your current Windows identity.
- Server scans require an authorized account with access to the target Windows PowerShell remoting endpoint and the underlying collectors (typically local administrator), WinRM connectivity, and the standard `Microsoft.PowerShell` endpoint. `-Credential (Get-Credential)` is optional for server scans only.
- Targets need CIM, ScheduledTasks and Microsoft.PowerShell.LocalAccounts capabilities. IIS targets also need WebAdministration. Missing modules or denied reads appear as failures.
- Run only within an approved audit scope. Choose an access-controlled report directory. No software is installed or remoting enabled by these scripts.

## Quick start

Download and extract the repository. On a domain-joined computer, open **64-bit Windows PowerShell 5.1 as administrator**, enter the extracted folder and run:

```powershell
.\Start-Audit.ps1
```

No DC, server list or output path is required. The entry point detects the computer's domain, discovers enabled Windows Server computer objects and domain controllers through AD, and runs all three stages. Reports are written directly to **`C:\scriptsDC`**, created automatically. Previous reports are archived under `C:\scriptsDC\History\<run identifier>`.

Use `.\Start-Audit.ps1 -ScanProcesses` to include process owners. Discovery covers the current AD domain, not IP ranges: machines outside AD or without a Windows Server OS attribute may be missed. DCs are enumerated separately and included. Missing DNS names and inaccessible targets remain visible in coverage reports.

Individual scripts also default to `C:\scriptsDC`; dependencies and risks read the discovery CSV there. Run discovery first. Optional advanced overrides remain available: `-Server`, `-ComputerName` (dependencies), `-OutputFolder`, and `-PrivilegedCsv` (dependencies/risks). Individual scripts regenerate CSV reports; discovery preserves the previous review workbook in History.

## Reports and interpretation

### Membership paths and owner review

Discovery now also generates:

- **02-MembershipPaths.csv**: every distinct simple path from a selected administrative group to a user, including alternative routes and primary-group membership. Direction: root group → nested groups → user. `Depth` counts membership edges (1 = direct). Group DNs/SIDs distinguish same-named groups. Cycles stop only the current branch and are logged as `CycleDetected`; alternate routes remain eligible. Paths repeating a group would be infinite and are not enumerated.
- **02-PrivilegedUserReview.xlsx** and **02-PrivilegedUserReview.csv**: one row per user SID across all roots. Columns include UPN, `AccountStatus`, `LastLogonDate`, `PasswordLastSet`, `LoginActivity`, `DirectAdministrativeGroups`, `IndirectPaths`, blank `OwnerDecision`/`Notes`, and coverage. Direct administrative groups are the selected roots to which the user belongs directly, including primary membership. XLSX includes filters, frozen headers, wrapped paths, highlighted editable fields and a Collection sheet. No Excel installation or downloaded module is required.
- **DiscoveryRun.csv**: overall coverage, workbook export status, timestamp and counts, including empty runs. Read this before treating the review as complete.

`AccountStatus` (Enabled/Disabled/Unknown) is separate from `LoginActivity`. A disabled account can have recent logon evidence. `Active` means a replicated timestamp within `InactiveDays`, not a current session. **LastLogonDate derives from replicated, approximate lastLogonTimestamp** and can lag; an empty value does not prove the account has never logged on. XLSX stores typed dates in the collection host's local time; CSV dates use ISO 8601. See [Microsoft's attribute reference](https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp).

Failed group/member/primary-group/user reads go to `DiscoveryStatus.csv`; other branches continue. Affected roots and their path rows are Partial. **All review rows** are Partial if any selected scope is incomplete, because missing evidence could affect any user. Unreadable user details remain visible as Unknown with Failed `UserDetailsStatus`, but are omitted from CSV 01 as before. Unresolved objects without a user SID appear in the status report rather than an invented user row. Foreign principals still need manual review.

CSV 01 retains its **column names, order and one-row-per-user/root contract** for dependencies and risks. `Enabled` carries account state; `ActivityStatus` now represents only login evidence, even for disabled users. With both direct and indirect routes, CSV 01 prefers direct membership while CSV 02 preserves every route. Start-Audit marks Discovery as Partial for collection/export gaps and continues downstream stages with the known user subset.

The default command and `C:\scriptsDC` destination are unchanged. Start-Audit archives the new reports. Individual discovery reruns preserve the previous XLSX under `History/workbook-*` to protect owner edits; CSVs are regenerated. Save your reviewed copy separately. The workbook is never silently truncated: Excel's 32,767-character cell limit or row limit produces an export failure while the full CSV remains available. Many paths can consume substantial time/memory; no arbitrary path/depth cutoff is applied. Excel's maximum row height can limit visible text; use the formula bar or path CSV for long routes.

Run `powershell.exe -NoProfile -File .\Tests\Test-MembershipPaths.ps1` in addition to the existing tests. It covers alternate paths, cycles, primary groups, partial collection, CSV 01 compatibility, empty reports and XLSX integrity.

All CSVs use UTF-8, semicolon delimiters, stable headers (even with zero results) and ISO 8601 date values where exported. Import with `Import-Csv -Delimiter ';'`.

| Report | Meaning |
| --- | --- |
| `RunStatus.csv` | Entry-point stage outcomes; Completed still requires reviewing detailed coverage. |
| `ServerDiscovery.csv` | Discovered servers/DCs and missing DNS names. |
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
Output/        Optional legacy folder; default reports go to C:\scriptsDC
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
