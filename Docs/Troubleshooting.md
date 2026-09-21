# Troubleshooting

[Português (Brasil)](Troubleshooting.pt-BR.md)

| Symptom | Check and action |
| --- | --- |
| ActiveDirectory module missing | Use Windows PowerShell 5.1 and install approved RSAT AD tools through your normal administration process. |
| DC lookup or AD query fails | Check the `-Server` value, DNS, AD Web Services connectivity, current identity and trust relationships. Inspect DiscoveryStatus or RiskQueryStatus. |
| Forest-root groups fail | Verify root-domain connectivity and read permissions. Run each domain separately; a selected-domain run is not forest-wide coverage. |
| DnsAdmins missing | It may not exist in this domain. Document applicability; the script deliberately reports the missing lookup. |
| Missing/partial group members | Check ADWS limits, cross-domain permissions and unsupported foreign security principals. Counts are lower bounds until gaps are resolved. |
| CSV rejected | Use this toolkit's semicolon-delimited discovery output with SID, DirectoryServer, DomainNetBIOS, SamAccountName, UserPrincipalName and PrivilegedGroup. Do not feed a legacy username-only spreadsheet. Empty discovery must be reviewed before scanning. |
| Every server collector fails | Verify the standard Microsoft.PowerShell WinRM endpoint, firewall policy, name resolution and authorization. The script does not change TrustedHosts or authentication configuration. |
| Access denied in one collector | Check the delegated collector permissions and remote elevation policy. Do not weaken security policy globally; test with an approved administrative identity. |
| Local Administrators query fails | Confirm a 64-bit Windows PowerShell endpoint and LocalAccounts module. Orphaned/unresolvable members may make the cmdlet fail; inspect the target manually. |
| Local Administrators NotApplicable | Expected on domain controllers; audit the domain Builtin Administrators group instead. |
| IIS Failed versus NotApplicable | Missing IIS configuration yields NotApplicable. Existing configuration with module/access/query problems yields Failed. An installed IIS instance with zero pools is a successful empty query. |
| Processes Partial | Some processes exited or owner access was denied. This is incomplete visibility, not a clean result. |
| No matched dependencies | Review all collector statuses and DependencyInventory. Check group-based access, aliases, unqualified identities and workload types outside scope. |
| Long scan | Use smaller explicit batches and omit processes. Remoting operation timeout is not a hard overall scan deadline. |
| Risk report misses a user | Review RiskQueryStatus; the account may have been deleted, moved across domains or become unreadable since discovery. |
| Spreadsheet displays one column | Import as UTF-8 with semicolon separator and identity/date columns as text. Avoid evaluating formula-like content. |
| Script blocked by execution policy | Follow your organization's signing/unblocking process after source review. Do not disable execution policy globally. |

## Escalating a defect

Provide the script name, Windows/PowerShell versions, collector status, expected behavior and a minimal **fictitious** reproduction. Redact domains, usernames, SIDs, server names and exception paths. Never attach production CSVs, credentials or client files to a public issue.
