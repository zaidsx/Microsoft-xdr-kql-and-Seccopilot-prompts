# AI Agent Unbounded Consumption (LLM10) — AgentsInfo

> **Verified against the live `AgentsInfo` schema.** Join key is the confirmed column **`EntraAgentID`** (capital ID). Joins to `EntraIdSpnSignInEvents` (needs Entra ID P2).

## Overview
Detects AI agent identities whose **sign-in / invocation volume spikes far above their own baseline** — a signal of runaway automation, abuse of a broadly shared agent, denial-of-wallet (cost) attacks, or a compromised identity being driven hard.

**OWASP LLM Top 10:** LLM10 — Unbounded Consumption
**MITRE ATT&CK:** TA0040 — Impact | T1496 — Resource Hijacking
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo` + `EntraIdSpnSignInEvents`)

## In Plain English
Every time an agent works it "signs in." One that usually signs in 10 times a day but suddenly signs in 2,000 times in an hour is being driven hard — a runaway loop, a cost attack, or a stolen identity. This learns each agent's normal rate and flags sudden explosions.

## KQL Query

```kql
let Lookback     = 14d;
let RecentWindow = 1d;
let BaselineDays = 13.0;
// Agent service-principal IDs as a scalar list — used as a semi-join filter.
// NOTE: a direct cross-table JOIN between AgentsInfo and EntraIdSpnSignInEvents
// throws "An unexpected error occurred" (the two tables are served from different
// data sources). The `in (list)` filter avoids the join entirely.
let AgentSpnIds = toscalar(
    AgentsInfo
    | where LifecycleStatus !in ("Deleted", "Uninstalled")
    | where isnotempty(EntraAgentID)
    | summarize make_set(tostring(EntraAgentID)));
EntraIdSpnSignInEvents
| where Timestamp > ago(Lookback)
| where ServicePrincipalId in (AgentSpnIds)
| summarize
    RecentCount   = countif(Timestamp >= ago(RecentWindow)),
    BaselineCount = countif(Timestamp <  ago(RecentWindow)),
    AgentName     = take_any(ServicePrincipalName)   // name comes from the sign-in table (no join needed)
    by ServicePrincipalId
| extend BaselineDailyAvg = round(BaselineCount / BaselineDays, 2)
| extend SpikeRatio = round(iff(BaselineDailyAvg > 0, RecentCount / BaselineDailyAvg, todouble(RecentCount)), 1)
| where RecentCount >= 50 and (SpikeRatio >= 5 or BaselineDailyAvg == 0)
| extend RiskLevel = case(
        SpikeRatio >= 20 or (BaselineDailyAvg == 0 and RecentCount >= 200), "Critical – Runaway agent activity (possible abuse / cost / DoS)",
        SpikeRatio >= 10,                                                    "High – Activity 10x+ over baseline",
        "Medium – Elevated activity vs baseline")
| project RiskLevel, AgentName, ServicePrincipalId, RecentCount, BaselineDailyAvg, SpikeRatio
| sort by RiskLevel asc, SpikeRatio desc
```

## Risk Tiers
- 🔴 **Critical** — 20x+ over baseline, or a brand-new burst of 200+ with no prior history
- 🟠 **High** — 10x+ over baseline
- 🟡 **Medium** — 5x+ over baseline with meaningful volume

## Response Actions
1. Confirm with the owner whether a legitimate batch job explains the spike.
2. If unexplained: throttle/disable the agent, review what it accessed.
3. Apply consumption limits / rate controls to prevent denial-of-wallet.

## Notes
- **No cross-table join.** A direct `join` between `AgentsInfo` and `EntraIdSpnSignInEvents` throws *"An unexpected error occurred during query execution"* — the two tables are served from different data sources and can't be joined at runtime. This version instead builds a scalar list of agent SPN IDs (`toscalar(... make_set ...)`) and filters sign-ins with `where ServicePrincipalId in (list)`, which is a semi-join, not a join.
- The agent display name comes from **`ServicePrincipalName`** in the sign-in table, so no enrichment from `AgentsInfo` is needed.
- Only agents with `EntraAgentID` populated *and* matching sign-in activity will appear; `LocalAgents` (IDE extensions) won't produce SPN sign-ins.
- Agents with `Platform == "LocalAgents"` (e.g., VS Code extensions) may not produce Entra service-principal sign-ins.
