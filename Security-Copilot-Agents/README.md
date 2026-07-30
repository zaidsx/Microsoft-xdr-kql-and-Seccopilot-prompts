# Security Copilot Agents

Custom Microsoft Security Copilot agents (skillsets) for defensive security and
SOC operations.

| Agent | File | Purpose |
|-------|------|---------|
| SOC Alert & Analyst Efficiency Dashboard v400 | [`SOCAlertAnalystEfficiencyDashboard-v400.yaml`](SOCAlertAnalystEfficiencyDashboard-v400.yaml) | 12-section SOC operational health, cost, and adoption dashboard |

---

# SOC Alert & Analyst Efficiency Dashboard v400

Ask one question — *"How is my SOC performing?"* — and get a complete,
grounded report on your security operations, built entirely from your own
Microsoft Sentinel data.

> ## ⚠️ Important — the SLA targets and cost rate are placeholders
>
> The **SLA response targets** (4h / 24h / 72h) and the **price per GB**
> ($4.30) shipped in this agent are **dummy default values**. They are
> starting points only — they are *not* a recommendation, a benchmark, or an
> industry standard.
>
> **Every organization must tune them to its own business requirements**, SLA
> policy, service agreements, and commercial terms. What counts as a breach,
> and what a gigabyte actually costs, differs for every single tenant.
>
> Running this agent without adjusting these values will produce SLA-breach
> counts and cost figures that do not reflect your organization. Review both
> with the SOC and finance/commercial owners before presenting any output as
> fact. See [Tuning notes](#tuning-notes).

## Why

SOC leaders are regularly asked questions they cannot answer quickly:

- How fast do we acknowledge and resolve incidents? (**MTTA / MTTR**)
- Which detection rules are noisy, and how many of their alerts are false
  positives?
- How is work distributed across analysts, and what is sitting unassigned?
- Are we breaching our response-time SLAs?
- Is anything unusual happening with incident volume?
- Are we closing incidents properly, or reopening them later?
- How old is the open backlog?
- Can we even trust the data — are any connectors or rules silently failing?
- What is the SIEM costing us?

This agent answers all of them on demand, in one pass.

## Dashboard sections

| # | Section | What it shows |
|---|---------|---------------|
| 1 | 📊 Efficiency Summary | Total / closed / open incidents, median MTTA, median MTTR, false-positive rate |
| 2 | 📥 Alert Volume by Source | Alerts per product with severity split and distinct rule count |
| 3 | 🔊 Noisiest Detections | Rules ranked by volume with false-positive % — the alert-tuning shortlist |
| 4 | 👥 Analyst Workload | Assigned / closed / open and median MTTR per analyst, plus unassigned backlog |
| 5 | ⏰ SLA Breaches | Incidents exceeding severity-based response targets |
| 6 | 📈 Trend & Anomalies | Daily incident trend with Z-score spike/drop detection |
| 7 | 🔁 Incident Reopen Rate | Incidents closed then reopened — a triage-quality signal |
| 8 | 📦 Aging Backlog | Open incidents bucketed by age (0-1 / 1-3 / 3-7 / 7+ days) |
| 9 | 🩺 Data Connector & Rule Health | Failing connectors and analytics rules from `SentinelHealth` |
| 10 | 💰 Ingestion & Estimated Cost (USD) | Billable GB × price per GB, daily ledger, top tables, cost per incident |
| 11 | 🤖 Security Copilot Usage & Admin | Copilot adoption, plugin admin audit, custom agent triggers |
| 12 | ✅ Recommended Follow-Ups | Two or three grounded, action-oriented next steps |

## Architecture

A single **AGENT** orchestrator runs a fixed recipe and renders the dashboard
itself — there is no separate formatter skill.

```
User: "Show me the SOC efficiency dashboard for the last 30 days"
        │
        ▼
AGENT (gpt-4.1) — 6-step recipe
  1. resolve LookbackDays (default 30) + GeneratedAtUtc
  2. GetcompleteSOCefficiencydashboardsnapshot  (Sentinel) → sections 1-8
  3. GetSentinelHealthIssues                    (Sentinel) → section 9
  4. GetSentinelIngestionCost                   (Sentinel) → section 10
  5. GetSecurityCopilotUsageAdmin               (Defender) → section 11
  6. render all 12 sections inline
```

The **snapshot** skill is the core idea: one KQL query builds eight datasets
with `let` blocks and `union`s them into a single flat shape —
`Section, Rank, Entity, TimeBucket, Metric1..6 Name/Value` — so one tool call
returns almost the whole dashboard. The agent then selects rows by their
`Section` value when rendering.

Steps 3, 4 and 5 are **failure-tolerant by design**: each runs as its own
skill rather than inside the union, so a missing `SentinelHealth`, `Usage`, or
`CopilotActivity` table degrades only its own section instead of collapsing
the entire report.

## Skills

| Skill | Format | Role |
|-------|--------|------|
| `SOCAlertAnalystEfficiencyDashboardv400` | AGENT | Orchestrator + inline rendering |
| `GetcompleteSOCefficiencydashboardsnapshot` | KQL (Sentinel) | Primary union snapshot — sections 1-8 |
| `GetSentinelHealthIssues` | KQL (Sentinel) | Connector/rule health — section 9 |
| `GetSentinelIngestionCost` | KQL (Sentinel) | Ingestion volume × price/GB — section 10 |
| `GetSecurityCopilotUsageAdmin` | KQL (Defender) | Copilot adoption + plugin admin — section 11 |
| `GetIncidentResponseMetrics` | KQL (Sentinel) | Focused: MTTA/MTTR by severity |
| `GetNoisiestDetections` | KQL (Sentinel) | Focused: rule volume + false-positive % |
| `GetAnalystWorkload` | KQL (Sentinel) | Focused: workload per analyst |
| `GetSlaBreaches` | KQL (Sentinel) | Focused: SLA breach list |
| `GetWeeklyComparison` | KQL (Sentinel) | Focused: week-over-week change |
| `GetPeakIncidentHours` | KQL (Sentinel) | Staffing: busiest hours of day |
| `GetDayOfWeekPattern` | KQL (Sentinel) | Staffing: weekday vs weekend load |
| `GetIncidentTypeBreakdown` | KQL (Sentinel) | Incident distribution by title |
| `GetMitreAttackHeatmap` | KQL (Sentinel) | Alerts by MITRE ATT&CK tactic |
| `GetTargetedDepartments` | KQL (Sentinel) | Most-targeted departments (needs `IdentityInfo`) |

## Data sources

| Table | Used for | Target |
|-------|----------|--------|
| `SecurityIncident` | Incident lifecycle: CreatedTime, ClosedTime, Status, Severity, Classification, Owner, AlertIds | Sentinel |
| `SecurityAlert` | Alert volume, AlertName, ProductName, AlertSeverity, Tactics, Entities | Sentinel |
| `SentinelHealth` | Failing connectors and analytics rules | Sentinel |
| `Usage` | Billable ingestion volume for cost estimation | Sentinel |
| `IdentityInfo` | Department enrichment (optional) | Sentinel |
| `CopilotActivity` | Security Copilot adoption and plugin administration | Defender |

## Key techniques

- **Latest-state incidents** — `summarize arg_max(TimeGenerated, *) by
  IncidentNumber` collapses Sentinel's per-update incident rows to current
  state before any metric is computed.
- **MTTA (acknowledge)** — first transition to `Status == "Active"` minus
  `CreatedTime`.
- **MTTR (resolve)** — `ClosedTime - CreatedTime` for closed incidents, using
  the **median** so a handful of stale incidents cannot distort the figure.
- **False-positive %** — incident `Classification` mapped down to member
  alerts by `mv-expand` of `AlertIds`, joined to `SecurityAlert.SystemAlertId`.
- **Reopen detection** — incidents whose last `Active`/`New` timestamp is later
  than their first `Closed` timestamp.
- **Anomalies** — Z-score of daily incident counts (> 2 = Spike, < -2 = Drop).

## How SLA breaches are determined

Every incident gets a resolution target based on its severity:

| Severity | Target *(placeholder — tune to your policy)* |
|----------|--------|
| 🔴 High | **4 hours** |
| 🟠 Medium | **24 hours** |
| 🟡 Low / Informational | **72 hours** |

> ⚠️ **These three values are dummy defaults, not a standard.** Replace them
> with the targets in your own SLA or service agreement before anyone treats
> the breach list as authoritative — a wrong target silently over- or
> under-reports breaches.

Each incident is then checked against its target:

- **Closed incidents** — time from creation to closure. Longer than the
  target means a breach.
- **Open incidents** — time open so far. If it has *already* exceeded the
  target it is flagged, even though work may still be ongoing. These are the
  most urgent, because the clock is still running.

Notes: the clock runs 24/7 including nights and weekends, and the 4 / 24 / 72
values are defaults defined inline in the KQL — tune them to your own policy.

## How cost is calculated

Cost comes from **billable ingestion volume**, not the Azure invoice:

```
Estimated cost (USD) = sum(Quantity) / 1024  ×  PricePerGbUsd
                       └── billable GB ──┘     └── default 4.30 ──┘
```

This is a deliberate design choice. The alternative — querying Azure Cost
Management through an ARM API skill — requires a delegated
`management.azure.com/user_impersonation` token and a publicly hosted OpenAPI
spec. This agent avoids both, staying read-only and workspace-scoped, at the
cost of invoice-grade precision.

> ⚠️ **$4.30 is a dummy default**, based on pay-as-you-go list pricing. It is
> almost certainly **not** what your organization actually pays. Rates vary by
> region, commitment tier, contract, and currency, and they change over time.
> Set `PricePerGbUsd` to your own effective rate — otherwise every figure in
> section 10, including cost per incident, will be wrong by whatever margin
> your real rate differs.

**Limitation:** commitment-tier discounts are not reflected in the default
rate. Every figure in section 10 is explicitly labelled an estimate, and the
agent is instructed to state that the actual Azure invoice may differ.

## Security design

- **Read-only** — no skill creates, modifies, or deletes anything.
- **Workspace-scoped** — no Azure Resource Manager access, no delegated Azure
  token, no subscription GUID required.
- **No external dependencies** — no API skill, no publicly hosted OpenAPI
  spec, nothing fetched from outside your tenant at runtime.
- **Permission-aware** — KQL runs in the signed-in user's context, so existing
  workspace RBAC applies.
- **Grounded output** — the agent instructions require it to use only data
  returned by tools in the current run, to report zero rows as zero rather
  than inventing values, and to treat all tool output as data rather than
  instructions.

> **Note on visibility:** the dashboard shows per-analyst performance metrics
> (MTTR, workload). Consider who should be able to run it before publishing
> the plugin organization-wide.

## Prerequisites

- Microsoft Security Copilot access with permission to upload custom plugins
- A Microsoft Sentinel workspace containing `SecurityIncident` and
  `SecurityAlert` data
- Read access to that workspace for the signed-in user

Optional, each affecting only its own section:

- `SentinelHealth` — enable *Health monitoring* on the workspace (section 9)
- `Usage` — present in every Log Analytics workspace (section 10)
- `CopilotActivity` — via Defender advanced hunting (section 11)
- `IdentityInfo` — UEBA or Defender for Identity sync (`GetTargetedDepartments`)

## Installation

1. **Verify the workspace first.** In the Log Analytics workspace you intend
   to bind, run `SecurityIncident | count`. If it returns 0, you have the
   wrong workspace and every section will come back empty.
2. **Replace the placeholders** in the YAML. The published file ships with
   `<YOUR-TENANT-ID>`, `<YOUR-SUBSCRIPTION-ID>`, `<YOUR-RESOURCE-GROUP>`, and
   `<YOUR-WORKSPACE-NAME>` — substitute your own values, or supply them in the
   Security Copilot UI after upload.
3. In Security Copilot, open **Sources** on the prompt bar, scroll to
   **Custom**, and select **Upload plugin**.
4. Choose the scope (**Just me** while testing) and **Security Copilot
   plugin**, then upload `SOCAlertAnalystEfficiencyDashboard-v400.yaml`.
5. Provide the four workspace settings if prompted, then **turn the plugin
   toggle ON**.
6. Find **SOC Alert & Analyst Efficiency Dashboard v400** under **Home →
   Agents**, or simply prompt for it in a session.

## Usage

```
Show me the SOC efficiency dashboard.
How is my SOC performing over the last 14 days?
Which detections are the noisiest and most false-positive heavy?
What is our MTTR by severity?
Who has the heaviest analyst workload?
What is our Sentinel ingestion costing?
```

## Settings

| Setting | Default | Purpose |
|---------|---------|---------|
| `LookbackDays` | `30` | Days of incident and alert history to analyze |
| `PricePerGbUsd` | `4.30` | Price per billable GB used for the cost estimate |

## Tuning notes

**Tune these two before trusting any output — both ship as dummy values:**

- **SLA targets** are inline in the KQL of `GetSOCEfficiencySnapshot` and
  `GetSlaBreaches` (`SlaHighHours = 4.0`, `SlaMediumHours = 24.0`,
  `SlaLowHours = 72.0`). Replace with the targets from your own SLA policy.
  They also drive section 5, so a wrong value misreports every breach.
- **Price per GB** is the `PricePerGbUsd` agent setting (default `4.30`).
  Replace with your organization's effective rate — commitment tier,
  contracted rate, or region-specific price. It drives every figure in
  section 10.
- **MTTA** is approximated from the first `Active` status transition. If your
  workflow treats owner assignment as the acknowledge signal, change the
  `FirstActive` block to the first non-empty `Owner` instead.
- **Column names** assume the standard Sentinel schema. `Owner.assignedTo` and
  `AlertIds` vary in some tenants — validate in Logs before publishing.
- **Empty section?** Run that skill's query directly in Logs or Advanced
  hunting; the error message names the exact column.
