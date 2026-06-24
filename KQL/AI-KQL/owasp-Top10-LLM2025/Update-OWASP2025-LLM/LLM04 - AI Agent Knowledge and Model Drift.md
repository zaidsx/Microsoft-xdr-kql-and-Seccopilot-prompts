# AI Agent Knowledge & Model Drift (Data & Model Poisoning) (LLM04) — AgentsInfo

> **Verified against the live `AgentsInfo` schema** (`Name`, `Model`, `DeclaredDataSources`, `LifecycleStatus` all confirmed). No uncertain columns used.

## Overview
Detects two poisoning vectors by comparing each agent's config over time: a **new/external knowledge source** added (`DeclaredDataSources`), and the **AI model changed** (`Model`).

**OWASP LLM Top 10:** LLM04 — Data & Model Poisoning
**MITRE ATT&CK:** TA0042 — Resource Development | T1584 — Compromise Infrastructure
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
An agent answers based on its knowledge (documents) and its brain (the model). Poisoning means quietly adding a malicious source or swapping the model. This compares each agent's **first-seen vs last-seen** snapshot and flags either change.

> **Why this version (not fixed before/after windows):** `AgentsInfo` is newly populating and may have only days of history, so a fixed "30→7 days ago" baseline is often empty and returns nothing. Comparing each agent's earliest vs latest snapshot within the lookback works with whatever history exists — even multiple snapshots on the same day.

## KQL Query

```kql
let Lookback = 30d;   // compares each agent's first vs last snapshot within this window
let ExternalMarkers = dynamic(["http","https","www","public","external","web","internet","url"]);
AgentsInfo
| where Timestamp > ago(Lookback)
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| extend Knowledge = tostring(DeclaredDataSources)
| summarize
    (OldTime, OldKnowledge, OldModel) = arg_min(Timestamp, Knowledge, Model),
    (NewTime, NewKnowledge, NewModel, Name, Owners, LifecycleStatus) = arg_max(Timestamp, Knowledge, Model, Name, Owners, LifecycleStatus)
    by AgentId
| where OldTime != NewTime          // need at least two snapshots at different times
| extend KnowledgeChanged = OldKnowledge != NewKnowledge
| extend ModelChanged     = OldModel != NewModel
| extend NewExternalKnowledge = KnowledgeChanged and NewKnowledge has_any (ExternalMarkers)
| where KnowledgeChanged or ModelChanged
| extend RiskLevel = case(
        NewExternalKnowledge and ModelChanged, "Critical – External knowledge added and model changed",
        NewExternalKnowledge,                  "High – New external knowledge source added (poisoning vector)",
        ModelChanged,                          "High – Underlying AI model changed",
        KnowledgeChanged,                      "Medium – Knowledge source modified",
        "Low")
| project RiskLevel, Name, AgentId, ModelChanged, OldModel, NewModel,
          KnowledgeChanged, NewExternalKnowledge, OldTime, NewTime, Owners, LifecycleStatus
| sort by RiskLevel asc, NewTime desc
```

## Risk Tiers
- 🔴 **Critical** — external knowledge added *and* model changed in the same window
- 🟠 **High** — new external knowledge source, or any model swap
- 🟡 **Medium** — knowledge sources changed (internal-only)

## Response Actions
1. Check `Owners` and the change window — legitimate maintenance or not?
2. Verify any new knowledge source is trusted and untampered.
3. Confirm `NewModel` is an approved model; revert if not.

## Notes
- `LastModifiedByUpn` doesn't exist in `AgentsInfo`; `Owners` (GUIDs — resolve via `IdentityInfo`) is the accountability lead.
- In the sample tenant `Model` was often empty, so the model-change branch fires only where agents specify a model.
