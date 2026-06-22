# AI Agent Unbounded Consumption (LLM10) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic unchanged; only the agent-inventory side and the join key changed (`EntraObjectId` → `EntraAgentId`). The activity table (`EntraIdSpnSignInEvents`) is the same.

## Overview
Detects AI agent identities whose **sign-in / invocation volume spikes far above their own baseline** — a signal of runaway automation, abuse of an exposed agent, denial-of-wallet (cost) attacks, or a compromised identity being driven hard.

**OWASP LLM Top 10:** LLM10 — Unbounded Consumption
**MITRE ATT&CK:** TA0040 — Impact | T1496 — Resource Hijacking
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo` + `EntraIdSpnSignInEvents`)

---

## In Plain English

Every time an agent does work it "signs in." A normal agent does this a steady number of times a day. An agent that usually signs in 10 times a day but suddenly signs in 2,000 times in an hour is being driven hard — a runaway loop, an attacker running up your cloud bill, or a stolen identity bulk-pulling data. This query learns each agent's normal daily rate and flags sudden explosions past it.

**In one sentence:** *It spots agents suddenly working far harder than normal — a sign of runaway loops, cost attacks, or a hijacked identity.*

---

## Prerequisites
> - `AgentsInfo` (agent inventory) and `EntraIdSpnSignInEvents` (needs Microsoft Entra ID P2).
> - Join key: `AgentsInfo.EntraAgentId` ↔ `EntraIdSpnSignInEvents.ServicePrincipalId` (cast to string).

## KQL Query

```kql
let Lookback     = 14d;
let RecentWindow = 1d;
let BaselineDays = 13.0;
let Agents =
    AgentsInfo
    | summarize arg_max(Timestamp, *) by AgentId
    | where LifecycleStatus != "Deleted"
    | extend EntraAgentId = tostring(EntraAgentId)
    | where isnotempty(EntraAgentId)
    | distinct EntraAgentId, AgentName, Owners;
EntraIdSpnSignInEvents
| where Timestamp > ago(Lookback)
| where isnotempty(ServicePrincipalId)
| join kind=inner Agents on $left.ServicePrincipalId == $right.EntraAgentId
| extend Period = iff(Timestamp >= ago(RecentWindow), "Recent", "Baseline")
| summarize
    RecentCount   = countif(Period == "Recent"),
    BaselineCount = countif(Period == "Baseline")
    by AgentName, EntraAgentId, Owners
| extend BaselineDailyAvg = round(BaselineCount / BaselineDays, 2)
| extend SpikeRatio = round(iff(BaselineDailyAvg > 0, RecentCount / BaselineDailyAvg, todouble(RecentCount)), 1)
| where RecentCount >= 50 and (SpikeRatio >= 5 or BaselineDailyAvg == 0)
| extend RiskLevel = case(
        SpikeRatio >= 20 or (BaselineDailyAvg == 0 and RecentCount >= 200), "Critical – Runaway agent activity (possible abuse / cost / DoS)",
        SpikeRatio >= 10,                                                    "High – Activity 10x+ over baseline",
        "Medium – Elevated activity vs baseline")
| project
    RiskLevel, AgentName, EntraAgentId, RecentCount, BaselineDailyAvg, SpikeRatio, Owners
| sort by RiskLevel asc, SpikeRatio desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| `RecentCount` | Sign-ins in the last day |
| `BaselineDailyAvg` | Normal sign-ins per day over the prior 13 days |
| `SpikeRatio` | How many times above normal the recent activity is |
| `RiskLevel` | Severity from spike size and absolute volume |

## Risk Tiers
- 🔴 **Critical** — 20x+ over baseline, or a brand-new burst of 200+ with no prior history
- 🟠 **High** — 10x+ over baseline
- 🟡 **Medium** — 5x+ over baseline with meaningful volume

## Response Actions
1. Confirm with the owner whether a legitimate batch job explains the spike.
2. If unexplained: throttle/disable the agent, check for an exposed config, review what it accessed.
3. Apply consumption limits / rate controls to prevent denial-of-wallet.

## Migration Notes (vs AIAgentsInfo version)
- Agent inventory side: `AIAgentsInfo` → `AgentsInfo`; join key `EntraObjectId` → `EntraAgentId`; `OwnerAccountUpns` → `Owners`.
- `EntraIdSpnSignInEvents` (activity) is unchanged — this detection was already on the current sign-in table.
