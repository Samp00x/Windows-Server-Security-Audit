# Reading dependency evidence

[Português (Brasil)](Dependency-Reports.pt-BR.md)

The numbered reports are now sequential. This is a filename/schema change: update saved imports and use a fresh output folder so reports from older versions are not mistaken for current results.

| Order | File | Read it for |
| --- | --- | --- |
| 01 | `01-Privileged-Users.csv` | Privileged user SIDs and root groups |
| 02 | `02-Privileged-Groups-Summary.csv` | Discovery coverage by group |
| 03 | `03-Privileged-Service-Dependencies.csv` | All observed Windows services, including unmatched and unresolved identities |
| 04 | `04-Scheduled-Task-Dependencies.csv` | Scheduled tasks, with profile artifacts separated by classification |
| 05 | `05-Server-Scan-Status.csv` | Coverage, observed row counts and unresolved identity counts per collector |
| 06 | `06-Privileged-Account-Risks.csv` | Account configuration findings |

Supplementary reports remain unnumbered: `DiscoveryStatus.csv`, `RiskQueryStatus.csv`, `DependencyInventory.csv` (all collectors, including resolution failures) and `Other-Privileged-Dependencies.csv` (SID matches for IIS, direct local Administrators and optional processes). These other findings are not Windows service dependencies.

## Start with coverage, then services

Read report 05 first. `Success` with `ObservedCount=0` means an empty completed query. `Failed` means the query did not complete, even if some rows were already received. `Partial` includes identity-resolution gaps; `UnresolvedIdentityCount` measures those gaps, not missing resources. `Skipped` and `NotApplicable` are explicit. If remoting fails, each missing collector receives a failure row. Successfully collected rows are retained when another collector fails.

Report 03 contains `Server`, `ServiceName`, `DisplayName`, `State`, `StartMode`, `StartNameRaw`, `ResolvedAccountType`, `ResolvedDomain`, `ResolvedSamAccountName`, `AccountSID`, `IsPrivileged`, `PrivilegedGroups`, `DependencySeverity`, `WhyItMatters`, `ResolutionStatus` and `ResolutionError`. It includes all services so an unmatched identity never silently disappears. Filter `IsPrivileged=True` for confirmed SID matches, and review every `Review` severity and unresolved identity.

`State` is the observed service state, and `StartMode` is the configured CIM mode (`Auto`, `Manual`, `Disabled`). The report does not infer business criticality from a product name. `Critical` expresses privilege exposure and workload dependency, not a confirmed business outage.

| Evidence | Severity |
| --- | --- |
| Running automatic service with a discovered privileged domain SID | Critical |
| Other running service with a discovered privileged SID | High |
| Stopped automatic service (any identity), or another non-running privileged service | Review |
| Unresolved service identity or unknown privilege match | Review |
| Other resolved service identity absent from supplied privileged SIDs | Informational |

`IsPrivileged=True` means the SID occurs in the supplied discovery report. `False` means a resolved identity has no match **within that inventory**, not that it lacks all privileges. `Unknown` means resolution is incomplete without a confirmed SID match. Local administrator rights, built-in system privileges, group task principals, managed service accounts absent from user discovery and unselected domain groups need separate assessment. Group memberships are not expanded by the scanner. An orphaned raw SID is retained and may match discovery, but its unresolved scope still requires review.

## How identity resolution works

Translation runs inside each target's Windows PowerShell remoting session, cached by configured identity for that target. The toolkit translates the configured name to a SID, then the SID back to its canonical qualified name. Privilege matching uses only the SID; name-only fallback never creates a confirmed match. DNS domain aliases, UPNs, case variations and renamed accounts therefore depend on the target's Windows resolver, not custom name stripping.

Fictitious examples on `APP01`:

| Configured identity | Meaning when Windows resolves it |
| --- | --- |
| `EXAMPLE\Administrator` or `example.test\Administrator` | Domain account; same SID if the names identify the same account |
| `.\Administrator` or `APP01\Administrator` | Account local to APP01; a different SID from the domain account |
| `Administrator` | Unqualified and ambiguous; Unresolved, never guessed |
| `LocalSystem`, `NT AUTHORITY\LOCAL SERVICE`, `NT SERVICE\Demo` | BuiltIn or virtual identity after successful resolution |

Both local and domain Administrator SIDs can end in RID 500; the **complete SID** determines the match. Machine scope is evaluated using the target's actual computer name, not the FQDN/alias used to connect. Domain controllers are not treated as having a local SAM. Translation failures, deleted accounts, unsupported namespaces or unavailable target context preserve the raw value and error, and mark coverage Partial. Correct DNS/trust/read-access problems and rerun; a CSV cannot guarantee visibility into inaccessible systems.

## Scheduled tasks and profile artifacts

Report 04 retains every observed task, its full path/name, raw principal, logon type, resolved identity, privilege match, classification and explanation. Known task-name families `OneDrive Startup`, `OneDrive Reporting`, `CreateExplorerShellUnelevatedTask`, `User_Feed_Synchronization` and `GoogleUserPEH` are `UserProfileArtifact` / `Informational` **when their logon type is interactive**. Such tasks use a logged-on user context and do not establish an unattended Windows service dependency, even when that user's SID is privileged. Identity errors still appear in report 04 and coverage 05.

A profile-like name with Password, S4U, group or unknown logon type stays `Review`; names alone are not a security trust decision. Other privileged tasks are High, or Review when disabled. Task state `Ready` is not proof that a task is currently running. Inspect the task's actions and application ownership if its configuration is unexpected.

For final analysis, keep confirmed privileged services, unattended tasks, profile artifacts and collection gaps distinct. Confirm the workload owner, minimum required permissions, replacement identity, restart validation and rollback before remediation. Reports prove observed configuration, not that stored credentials are valid or that a workload will survive a password or membership change.

## Validation

Run all three offline test scripts in `Tests/`. They cover the real collector body with mocked Windows responses plus SID aliases/collisions, built-ins, unresolved accounts, severity rules and task profile heuristics. Before production use, validate a disposable domain/member-server pair with same-named local/domain accounts, DNS and NetBIOS names, running/stopped automatic services, interactive and unattended tasks, denied collectors and an unreachable server. No live AD/WinRM validation is implied by offline tests.

Microsoft references: [NTAccount.Translate](https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.ntaccount.translate), [Task logon types](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type).
