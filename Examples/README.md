# Fictitious examples

[Português (Brasil)](README.pt-BR.md)

Every value in these CSVs is fabricated. EXAMPLE, example.test and the sample SIDs do not identify a client. These illustrate the report schemas, not a successful audit. Do not run the risk scanner against these identities expecting real directory objects.

The example has one privileged service identity, one stopped-service dependency and one password review indicator. A successful collector status describes query completion only. Runtime output must remain outside Examples.

The two `02-*.csv` files are a separate fabricated fixture: Domain Admins reaches alice directly and through Team A/Team B → Shared. Bob is a primary-group member of Shared. Two different paths reach each nested user even though Shared is visited twice. Both accounts are disabled, but alice has recent replicated logon evidence; account state and login activity are separate. The generated review workbook uses the same columns as the review CSV. `Tests/Test-MembershipPaths.ps1` builds and validates the XLSX without any live AD data.
