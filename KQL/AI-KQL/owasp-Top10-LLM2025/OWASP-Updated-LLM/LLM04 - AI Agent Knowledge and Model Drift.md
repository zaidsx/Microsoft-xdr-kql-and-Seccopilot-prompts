# AI Agent Knowledge & Model Drift (Data & Model Poisoning) (LLM04) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic unchanged; columns mapped per [`../updated-tables.md`](../updated-tables.md).

## Overview
Detects two poisoning vectors by comparing each agent's configuration over time: a **new or external knowledge source** added to an agent, and the agent's **underlying AI model being changed**. Knowledge sources are the agent's facts — swap in a poisoned source and you control its answers. A silent model swap can downgrade safety or route data to an unapproved model.

**OWASP LLM Top 10:** LLM04 — Data & Model Poisoning
**MITRE ATT&CK:** TA0042 — Resource Development | T1584 — Compromise Infrastructure
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

An agent answers based on its **knowledge** (documents it reads) and its **brain** (the AI model). Poisoning means quietly tampering with either: adding a malicious knowledge source so the agent repeats lies, or swapping the model for a weaker/unsafe one. Both are small config changes that are easy to miss. This query takes a **"before" and "after" snapshot** and flags when knowledge or model changed.

**In one sentence:** *It catches someone quietly swapping an agent's information sources or its AI brain.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365. Relies on multiple snapshots over time; best run on a recurring (daily) schedule.

## KQL Query

```kql
let Lookback = 30d;
let RecentWindow = 7d;
let ExternalMarkers = dynamic(["http", "www.", "public", "external", "web", "url", "internet"]);
let Baseline =
    AgentsInfo
    | where Timestamp between (ago(Lookback) .. ago(RecentWindow))
    | summarize arg_max(Timestamp, *) by AgentId
    | project AgentId,
              OldKnowledge = tostring(DeclaredDataSources),
              OldModel     = Model,
              OldTime      = Timestamp;
let Current =
    AgentsInfo
    | where Timestamp > ago(RecentWindow)
    | summarize arg_max(Timestamp, *) by AgentId
    | project AgentId, AgentName, Owners, LifecycleStatus,
              NewKnowledge = tostring(DeclaredDataSources),
              NewModel     = Model,
              NewTime      = Timestamp;
Baseline
| join kind=inner Current on AgentId
| extend KnowledgeChanged = OldKnowledge != NewKnowledge
| extend ModelChanged     = OldModel != NewModel
| extend NewExternalKnowledge =
        KnowledgeChanged and tolower(NewKnowledge) has_any (ExternalMarkers)
| where KnowledgeChanged or ModelChanged
| extend RiskLevel = case(
        NewExternalKnowledge and ModelChanged, "Critical – External knowledge added and model changed",
        NewExternalKnowledge,                  "High – New external knowledge source added (poisoning vector)",
        ModelChanged,                          "High – Underlying AI model changed",
        KnowledgeChanged,                      "Medium – Knowledge source modified",
        "Low")
| project
    RiskLevel, AgentName, AgentId,
    ModelChanged, OldModel, NewModel,
    KnowledgeChanged, NewExternalKnowledge,
    OldTime, NewTime, Owners, LifecycleStatus
| sort by RiskLevel asc, NewTime desc
```

## Risk Tiers
- 🔴 **Critical** — external knowledge source added *and* model changed in the same window
- 🟠 **High** — new external knowledge source, or any model swap
- 🟡 **Medium** — knowledge sources changed (internal-only)

## Response Actions
1. Check `Owners` and the change window — was this legitimate maintenance?
2. For new knowledge sources: verify the source is trusted and untampered.
3. For model changes: confirm `NewModel` is an approved model; revert if not.

## Migration Notes (vs AIAgentsInfo version)
- `KnowledgeDetails` → `DeclaredDataSources`; `AIModel` → `Model`.
- `LastModifiedByUpn` has **no direct column** in `AgentsInfo` — "who changed it" is not available here; `Owners` is projected as the closest accountability lead. If `RawAgentInfo` carries a modifier UPN in your tenant, add it.
