# Rapid7 InsightVM to Freshservice Sync

This project reads active Critical and Severe findings from the Rapid7 InsightVM
Security Console API v3, resolves remediation details, writes a CSV for audit, and
can create Freshservice tickets for remediation groups. Ticket creation is
opt-in when running locally.

## Requirements

- Python 3.10+
- Rapid7 Security Console HTTPS URL, username, and password
- Freshservice domain, API key, and requester email when creating tickets
- Network access from the runner to the Security Console and Freshservice

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
cd "patch automation"
python -m pip install -e ".[dev]"
```

Set the Rapid7 credentials in your shell or secret manager:

```bash
export RAPID7_CONSOLE_URL="https://your-console:3780"
export RAPID7_CONSOLE_USERNAME="your-api-user"
export RAPID7_CONSOLE_PASSWORD="..."
```

To create Freshservice tickets, also configure:

```bash
export FRESHSERVICE_DOMAIN="https://your-domain.freshservice.com"
export FRESHSERVICE_API_KEY="..."
export FRESHSERVICE_REQUESTER_EMAIL="security@example.com"
```

The API key is sent using Freshservice's documented HTTP Basic authentication
format (`api_key:X`). The integration uses the
[Freshservice Create a Ticket endpoint](https://api.freshservice.com/#create_ticket).
Ticket priority defaults to High and status to Open.

## Run

Export the CSV without creating tickets:

```bash
rapid7-freshservice-sync --output rapid7-freshservice-findings.csv
```

Export and create tickets:

```bash
rapid7-freshservice-sync \
  --output rapid7-freshservice-findings.csv \
  --create-tickets
```

Ticket creation checks Freshservice for an existing Open or Pending ticket with
the same deterministic remediation tag before creating a ticket. A separate
ticket is created for each Rapid7 remediation solution; the tag includes its
solution ID so distinct solutions remain separate. Repeated scheduled runs do
not create duplicate active tickets for the same solution. Resolved or Closed
tickets do not prevent a new ticket if the finding returns.

Tickets use the configured requester, the remediation solution name as the
subject, Medium urgency/impact/priority, the `IT, Banking Support & Marketing`
workspace, the `Service Desk` group, and the `Digital Security` /
`Vulnerability Management` category and subcategory. Workspace and group IDs
are resolved by exact name through Freshservice before the first ticket is
created; missing or ambiguous matches stop ticket creation.
The ticket description separates a per-asset remediation details table from a
proof table; the proof section is included only when the solution affects five
or fewer distinct vulnerabilities.

CSV files contain vulnerability, asset, and proof data and are written with
owner-only permissions. Store exports only in protected locations and follow
your retention policy.

## Azure Pipelines

The scheduled pipeline runs the tests and sync weekly. Configure these variables
in the existing `New version for automation` variable group and Key Vault:

- `Rapid7-Console-URL`
- `Rapid7-Console-Username`
- `Rapid7-Console-Password`
- `Freshservice-Domain`
- `Freshservice-API-Key`
- `Freshservice-Requester-Email`

The Azure service connection and Key Vault names are configured in
[`azure-pipelines.yml`](./azure-pipelines.yml).

The self-hosted `Security-Agent-Pool` agent must provide Python 3.11 through
the Azure Pipelines tool cache. The pipeline selects that version with
`UsePythonVersion@0`, verifies it is at least Python 3.10, installs the project
with its test dependencies, compiles the application modules, and runs the full
test suite before the sync job runs.

## Rapid7 selection and export

The client uses HTTPS and Basic authentication with the Security Console API v3.
It resolves the configured asset group, selects assets scanned in the last
seven days, and includes only active (`vulnerable`) Critical and Severe findings.
Microsoft Patch-category vulnerabilities are excluded. Rapid7 `Severe` is
retained as `high` in the internal catalog. Remediation lookups use
`GET /api/3/vulnerabilities/{id}/solutions` and
`GET /api/3/solutions/{id}`; API failures stop the export.

For each remediation solution affecting at most five distinct vulnerabilities,
the exporter also calls
`GET /api/3/assets/{assetId}/vulnerabilities/{vulnerabilityId}` and includes
Rapid7 proof results per asset in the CSV and Freshservice ticket. Proof is not
retrieved for solutions affecting more than five vulnerabilities; the export
and ticket state that the threshold was exceeded.

Findings are grouped by solution ID, solution, and fix details, with affected
hosts listed in the CSV and Freshservice ticket. If a software family has one
"latest version" remediation, version-pinned updates for that same normalized
family are consolidated into the rollup finding; the rollup retains all
affected CVEs and assets. Ambiguous families or families with multiple rollups
remain separate. Missing hostnames are skipped by default; use
`--hostname-fallback ip` to use an asset IP instead.

## Azure Key Vault

Install the optional Azure support:

```bash
python -m pip install -e ".[dev,azure]"
```

Set `SECRET_SOURCE=azure-keyvault` and `AZURE_KEY_VAULT_URL`, then authenticate
with Azure. The default secret names are:

- `rapid7-console-username`
- `rapid7-console-password`
- `freshservice-api-key`
- `freshservice-requester-email`

Secret names can be overridden with the corresponding `*_SECRET` environment
variables or CLI options. The Rapid7 console URL and Freshservice domain are
non-secret configuration values.

## Tests

```bash
cd "patch automation"
python -m pytest
```
