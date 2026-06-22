# AI Agent Misinformation Risk (LLM09) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic unchanged; columns mapped per [`../updated-tables.md`](../updated-tables.md).

## Overview
Detects AI agents configured to produce **confident-but-unreliable output**: a generative agent with **no grounding knowledge source** and often **no system prompt** constraining accuracy. Such agents answer freely from the model's parametric memory with no source of truth, and tend to fabricate — operational misinformation once published to users.

**OWASP LLM Top 10:** LLM09 — Misinformation
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

Ask someone a detailed question with no reference material and they'll often give a confident answer that isn't right. An AI agent that **generates freely but has nothing factual to ground its answers in** does the same — and if it's **published** with **no instructions** to stick to facts, the misinformation risk is high. This query finds those ungrounded, free-generating agents, especially the live ones.

**In one sentence:** *It finds agents that answer confidently with no factual source behind them — the ones most likely to make things up.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365.

## KQL Query

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| extend IsGenAI =
        tostring(Capabilities) has_any (dynamic(["generative", "orchestration", "autonomous"]))
        or tostring(RawAgentInfo) has '"GenerativeActionsEnabled": true'
| extend NoKnowledge =
        isempty(tostring(DeclaredDataSources)) or tostring(DeclaredDataSources) in ("[]", "{}", "")
| extend NoInstructions = isempty(Instructions) or Instructions == "N/A"
| extend Published = PublishedStatus == "Published"
// Generates freely with no grounded source of truth
| where IsGenAI and NoKnowledge
| extend RiskLevel = case(
        Published and NoInstructions, "High – Published autonomous agent: no grounding and no guardrails",
        Published,                    "High – Published agent generating without grounded knowledge",
        NoInstructions,               "Medium – Ungrounded agent with no behavioral guidance",
        "Medium – Agent generates without grounded knowledge")
| project
    RiskLevel, AgentName, AgentId, Published, NoKnowledge, NoInstructions,
    PublishedStatus, LifecycleStatus, Availability, Model, Owners, AgentDescription, Platform
| sort by RiskLevel asc, AgentName asc
```

## Risk Tiers
- 🟠 **High** — published, generating, with no grounding (worse if no guardrails)
- 🟡 **Medium** — ungrounded generative agent not yet broadly published

## Response Actions
1. Attach an authoritative knowledge source so answers are grounded.
2. Add a system prompt instructing the agent to cite sources and say "I don't know" when unsure.
3. For high-stakes use cases, require human review of output.

## Migration Notes (vs AIAgentsInfo version)
- `KnowledgeDetails` → `DeclaredDataSources`; `AgentStatus == "Published"` → `PublishedStatus == "Published"`; `AIModel` → `Model`.
- `IsGenerativeOrchestrationEnabled` approximated via `Capabilities` + `RawAgentInfo`.
