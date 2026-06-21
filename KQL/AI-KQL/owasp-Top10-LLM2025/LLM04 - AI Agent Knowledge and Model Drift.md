# AI Agent Knowledge & Model Drift (Data & Model Poisoning)

## Overview
Detects two poisoning vectors by comparing each agent's configuration over time: a **new or external knowledge source** being added to an agent, and the agent's **underlying AI model being changed**. Knowledge sources are the agent's "facts" — swap in a poisoned or attacker-controlled source and you control its answers and behavior. A silent model swap can downgrade safety, route data to an unapproved model, or alter outputs. Both are quiet configuration changes that legitimate monitoring usually misses.

**OWASP LLM Top 10:** LLM04 — Data & Model Poisoning
**MITRE ATT&CK:** TA0042 — Resource Development | T1584 — Compromise Infrastructure
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

An AI agent answers questions based on two things: **its knowledge** (the documents and sources it's allowed to read) and **its brain** (the AI model running it).

Poisoning means quietly tampering with either one:

- **Knowledge poisoning** — someone adds a new source full of false or malicious information. Now the agent confidently repeats lies, or follows hidden instructions, because it "learned" them from a source it trusts. Especially dangerous if the new source points to the **open internet** instead of your vetted internal docs.
- **Model swapping** — someone changes which AI brain the agent uses. Maybe to a weaker model with fewer safety checks, or one that sends your data somewhere it shouldn't go.

Both are small config changes that are easy to miss. This query takes a **"before" and "after" snapshot** of each agent and flags when its knowledge or its model changed — and crucially, **who changed it**.

**In one sentence:** *It catches someone quietly swapping an agent's information sources or its AI brain — the two ways to poison what an agent knows and how it behaves.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.
> - Relies on multiple snapshots per agent over time. Best run on a recurring (e.g., daily) schedule.

## KQL Query

```kql
let Lookback = 30d;     // how far back the "before" snapshot can come from
let RecentWindow = 7d;  // what counts as "current"
let ExternalMarkers = dynamic(["http", "www.", "public", "external", "web", "url", "internet"]);
// "Before" snapshot per agent
let Baseline =
    AIAgentsInfo
    | where Timestamp between (ago(Lookback) .. ago(RecentWindow))
    | summarize arg_max(Timestamp, *) by AIAgentId
    | project AIAgentId,
              OldKnowledge = tostring(KnowledgeDetails),
              OldModel     = AIModel,
              OldTime      = Timestamp;
// "Current" snapshot per agent
let Current =
    AIAgentsInfo
    | where Timestamp > ago(RecentWindow)
    | summarize arg_max(Timestamp, *) by AIAgentId
    | project AIAgentId, AIAgentName, OwnerAccountUpns, LastModifiedByUpn, AgentStatus,
              NewKnowledge = tostring(KnowledgeDetails),
              NewModel     = AIModel,
              NewTime      = Timestamp;
Baseline
| join kind=inner Current on AIAgentId
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
    RiskLevel, AIAgentName, AIAgentId, LastModifiedByUpn,
    ModelChanged, OldModel, NewModel,
    KnowledgeChanged, NewExternalKnowledge,
    OldTime, NewTime, OwnerAccountUpns, AgentStatus
| sort by RiskLevel asc, NewTime desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| `KnowledgeChanged` | The agent's knowledge sources were modified between snapshots |
| `NewExternalKnowledge` | The change introduced an external/web source — the poisoning vector |
| `ModelChanged` | The agent's AI model was swapped |
| `OldModel` → `NewModel` | The before/after model — check the new one is approved |
| `LastModifiedByUpn` | **Who** made the change — your investigation lead |
| `OldTime` → `NewTime` | The window the change happened in |

## Risk Tiers
- 🔴 **Critical** — external knowledge source added *and* model changed in the same window
- 🟠 **High** — new external knowledge source, or any model swap
- 🟡 **Medium** — knowledge sources changed (internal-only)

## Response Actions
1. Check `LastModifiedByUpn` — was this the owner doing legitimate maintenance, or an unexpected account?
2. For new knowledge sources: verify the source is trusted and the content hasn't been tampered with.
3. For model changes: confirm `NewModel` is an approved, sanctioned model — revert if not.
4. If unexplained, restore the prior configuration and investigate the account that made the change.

## Production Note
This compares the **earliest snapshot in the window** to the **latest**, so a change that was made and reverted inside the window can be missed. Run daily for true change-by-change coverage.

## Related Detections
- AI Agent Guardrail Drift Detection — the same snapshot-diff technique for protective settings
- AI Agent XPIA Exposure Map — agents whose knowledge sources are externally reachable
- AI Agent Untrusted Tool Supply Chain — poisoned tools rather than poisoned knowledge
