# AI Agent Unbounded Consumption (LLM10)

## Overview
Detects AI agent identities whose **sign-in / invocation volume spikes far above their own baseline** — a signal of runaway automation, abuse of an exposed agent, denial-of-wallet (cost) attacks, or a compromised identity being driven hard. Without consumption limits, an agent can be looped to exhaust resources, rack up model costs, or bulk-extract data. This compares each agent's recent activity to its historical norm using `EntraIdSpnSignInEvents`.

**OWASP LLM Top 10:** LLM10 — Unbounded Consumption
**MITRE ATT&CK:** TA0040 — Impact | T1496 — Resource Hijacking
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

Every time an AI agent does work, it "signs in" to get its job done. A normal agent does this a fairly steady number of times a day.

Now imagine an agent that usually signs in 10 times a day suddenly signs in **2,000 times in an hour**. Something is driving it hard — maybe a runaway loop, maybe an attacker hammering an exposed agent to run up your cloud bill (a "denial-of-wallet" attack), maybe a stolen identity being used to bulk-pull data.

This query learns each agent's **normal daily rate**, then flags any agent whose recent activity **suddenly explodes past it**.

**In one sentence:** *It spots agents suddenly working far harder than normal — a sign of runaway loops, cost attacks, or a hijacked identity.*

---

## Prerequisites
> - `AIAgentsInfo` (agent inventory) and `EntraIdSpnSignInEvents` (needs Microsoft Entra ID P2).
> - Join key: `AIAgentsInfo.EntraObjectId` (cast guid → string) ↔ `EntraIdSpnSignInEvents.ServicePrincipalId`.

## KQL Query

```kql
let Lookback     = 14d;   // total window
let RecentWindow = 1d;    // "now"
let BaselineDays = 13.0;  // Lookback - RecentWindow
// Agent identities only
let Agents =
    AIAgentsInfo
    | summarize arg_max(Timestamp, *) by AIAgentId
    | where AgentStatus != "Deleted"
    | extend EntraObjectId = tostring(EntraObjectId)
    | where isnotempty(EntraObjectId)
    | distinct EntraObjectId, AIAgentName, OwnerAccountUpns;
EntraIdSpnSignInEvents
| where Timestamp > ago(Lookback)
| where isnotempty(ServicePrincipalId)
| join kind=inner Agents on $left.ServicePrincipalId == $right.EntraObjectId
| extend Period = iff(Timestamp >= ago(RecentWindow), "Recent", "Baseline")
| summarize
    RecentCount   = countif(Period == "Recent"),
    BaselineCount = countif(Period == "Baseline")
    by AIAgentName, EntraObjectId, OwnerAccountUpns
| extend BaselineDailyAvg = round(BaselineCount / BaselineDays, 2)
| extend SpikeRatio = round(iff(BaselineDailyAvg > 0, RecentCount / BaselineDailyAvg, todouble(RecentCount)), 1)
// Only meaningful spikes: enough absolute volume AND a big jump (or no prior history)
| where RecentCount >= 50 and (SpikeRatio >= 5 or BaselineDailyAvg == 0)
| extend RiskLevel = case(
        SpikeRatio >= 20 or (BaselineDailyAvg == 0 and RecentCount >= 200), "Critical – Runaway agent activity (possible abuse / cost / DoS)",
        SpikeRatio >= 10,                                                    "High – Activity 10x+ over baseline",
        "Medium – Elevated activity vs baseline")
| project
    RiskLevel, AIAgentName, EntraObjectId, RecentCount, BaselineDailyAvg, SpikeRatio, OwnerAccountUpns
| sort by RiskLevel asc, SpikeRatio desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| `RecentCount` | Sign-ins in the last day |
| `BaselineDailyAvg` | The agent's normal sign-ins per day over the prior 13 days |
| `SpikeRatio` | How many times above normal the recent activity is |
| `RiskLevel` | Severity from the size of the spike and absolute volume |

## Risk Tiers
- 🔴 **Critical** — 20x+ over baseline, or a brand-new burst of 200+ with no prior history
- 🟠 **High** — 10x+ over baseline
- 🟡 **Medium** — 5x+ over baseline with meaningful volume

## Response Actions
1. Confirm with the owner whether a legitimate batch job or new workload explains the spike.
2. If unexplained: throttle or disable the agent, check for an exposed/no-auth configuration, and review what it accessed during the burst.
3. Apply consumption limits / rate controls to prevent denial-of-wallet.

## Tuning Notes
- Adjust `RecentWindow`, the `RecentCount >= 50` floor, and the spike thresholds to your environment's normal agent cadence.
- For agents with naturally spiky workloads (scheduled bursts), allowlist by `EntraObjectId` or compare same-day-of-week instead.

## Related Detections
- AI Agent Dormant Reactivation — the opposite signal: quiet agents waking up
- AI Agent Excessive Tool Surface — what a hard-driven agent could be doing
