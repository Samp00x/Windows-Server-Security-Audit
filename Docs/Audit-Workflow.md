# Audit workflow

[Português (Brasil)](Audit-Workflow.pt-BR.md)

1. **Define scope.** Record the approved domains, server list, account owner contacts, maintenance constraints and review thresholds outside this repository. Use a dedicated report folder per domain and run. Confirm read access and remoting with one lab target first.
2. **Discover privileges.** Run `Get-PrivilegedUsers.ps1`. Include custom administrative groups with `-AdditionalGroup`. Review every partial/failed group and every unsupported principal in the status report. Resolve coverage gaps or explicitly document exclusions before using the user list.
3. **Locate dependencies.** Supply the discovery CSV and an explicit list of approved server FQDNs to `Get-PrivilegedAccountDependencies.ps1`. Start with a small batch. Add process collection only when needed. Inspect the scan status before the matched report, then review unmatched inventory, local administrative groups and task group principals manually.
4. **Assess risk.** Run `Get-PrivilegedAccountRisks.ps1`. Review RiskQueryStatus for missing accounts. Findings include disabled privileged users, stale or missing replicated logons, missing/old password timestamps, password policy flags, disabled pre-authentication, delegation flags, missing AccountNotDelegated, SPNs and SID history. Validate each indicator against the account's intended use and compensating controls. SPNs and SID history may be legitimate; the toolkit does not calculate exploitability or an automatic risk score.
5. **Confirm business need.** Ask the service/application owner to validate each dependency and privileged membership. Check tasks that run monthly, stopped services, disaster-recovery systems and external applications. Absence from a snapshot is insufficient evidence for removal.
6. **Plan remediation separately.** Record approval, replacement identity, rollback and validation steps. Consider supported managed service identities for workloads, separate human administrative accounts and least-privilege group access. This toolkit performs no remediation. Do not disable an account or rotate its password solely because of a report flag.
7. **Validate and retain.** After approved changes, repeat the audit into a new folder and test affected applications. Compare by SID and root group SID, not display name. Retain original coverage reports alongside results and delete according to your organization's retention policy.

## Practical execution

Use the [dependency report guide](Dependency-Reports.md) to separate confirmed service dependencies, unattended tasks, interactive profile artifacts and coverage gaps. Prioritize report 03 by severity after reviewing report 05. Compare local and domain identities by full SID; matching the name Administrator or RID 500 is insufficient.

Use `Get-Help .\Scripts\Get-PrivilegedUsers.ps1 -Full` for script help. For server batches, a locally maintained text file can be read with `Get-Content` and passed to `-ComputerName`; do not commit that target list. Windows integrated authentication is used by default. Optional server credentials remain in memory and are never exported.

The scanner uses one remoting session per target, processes targets sequentially and closes sessions in `finally`. `-OperationTimeoutSeconds` controls the remoting operation timeout, not a guaranteed total wall-clock deadline for every collector. Avoid oversized server batches.

## Acceptance before production

- On a disposable domain, create direct and nested group memberships, a cycle and a primary-group membership. Verify one user row per privileged root, expected membership classification, and counts.
- Validate forest-root and cross-domain member reads; confirm unsupported foreign principals produce a coverage gap.
- Configure a lab service, task and IIS SpecificUser pool with a fictitious privileged test identity. Include stopped/disabled resources. Verify exact matches and a same-named local user does not match.
- Test a direct local administrator and an AD group added to local Administrators. Confirm the latter remains in inventory for expansion outside the scanner.
- Deny a collector, use an unreachable server and remove an IIS module on an IIS target. Verify failures remain distinct from empty successful scans and NotApplicable.
- Exercise process-owner denial and process exit races; expect Partial coverage. Verify skipped process collection is explicit.

No live environment validation is implied by the offline test suite.
