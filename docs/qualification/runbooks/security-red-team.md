# Runbook — Q3 security campaign and red team

Use `qa/qualification/matrices/attack-matrix.json` to scope the campaign.
Provide the red team with the candidate binary digest, supported protocols,
threat model, tenant model and explicit rules of engagement. Do not provide
private customer data or production credentials.

Every finding needs a stable ID, severity, reproduction evidence, affected
digest, owner and disposition. Fixed vulnerabilities should gain a regression
test whenever technically possible. Risk acceptance must name an authority,
expiry and compensating controls.

Q3 also includes malformed protocols, authentication and authorization
boundaries, tenant isolation, configuration abuse and resource exhaustion.
Fuzzing alone is not a red team. For MissionCritical, the assessment and
evidence verification must be independent.

Open critical findings block GovernmentProduction. High findings require the
formal policy disposition defined in the qualification plan; hiding or deleting
a historical failure is forbidden.
