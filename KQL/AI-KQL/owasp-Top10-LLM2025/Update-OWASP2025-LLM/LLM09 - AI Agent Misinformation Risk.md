# AI Agent Misinformation Risk (LLM09) — AgentsInfo

> **Verified against the live `AgentsInfo` schema** (`Description`, `Model`, `PublishedStatus`, `DeclaredDataSources` confirmed).

## Overview
Detects AI agents likely to produce **confident-but-unreliable output**: a generative agent with **no grounding knowledge source** (`DeclaredDataSources` empty), often with **no system prompt** constraining accuracy. With no source of truth, such agents fabricate.

**OWASP LLM Top 10:** LLM09 — Misinformation
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
Ask someone a detailed question with no reference material and they'll answer confidently but often wrongly. An agent that generates freely with nothing factual to ground it does the same — especially risky once published.

## KQL Query

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| extend NoKnowledge = isempty(DeclaredDataSources) or tostring(DeclaredDataSources) in ("[]", "{}", "null", "")
| extend NoInstructions = isempty(Instructions) or Instructions == "N/A"
| extend Published = PublishedStatus == "Published"
// Context only (NOT a hard filter): every AgentsInfo row is already a generative agent.
| extend GenerativeSignal =
        (isnotempty(Capabilities) and tostring(Capabilities) !in ("[]", "{}", "null"))
        or isnotempty(Model)
        or tostring(RawAgentInfo) has "GenerativeActionsEnabled"
// Core signal: an agent with NO grounded knowledge source can fabricate answers.
| where NoKnowledge
| extend RiskLevel = case(
        Published and NoInstructions, "High – Published agent: no grounding and no guardrails",
        Published,                    "High – Published agent generating without grounded knowledge",
        NoInstructions,               "Medium – Ungrounded agent with no behavioral guidance",
        "Medium – Agent generates without grounded knowledge")
| project RiskLevel, Name, AgentId, Published, NoKnowledge, NoInstructions, GenerativeSignal,
          PublishedStatus, LifecycleStatus, Model, Capabilities, Owners, Description, Platform
| sort by RiskLevel asc, Name asc
```

## Risk Tiers
- 🟠 **High** — published, generating, with no grounding (worse if no guardrails)
- 🟡 **Medium** — ungrounded generative agent not yet broadly published

## Response Actions
1. Attach an authoritative knowledge source so answers are grounded.
2. Add a system prompt instructing the agent to cite sources and say "I don't know" when unsure.
3. For high-stakes use, require human review of output.

## Notes
- **Why no `IsGenAI` gate:** the original `AIAgentsInfo` version gated on the boolean `IsGenerativeOrchestrationEnabled`. `AgentsInfo` has no equivalent, and a keyword proxy (`Capabilities has "Copilot"…`) only matched *grounded* Copilot agents — so `IsGenAI AND NoKnowledge` returned zero. Since **every `AgentsInfo` row is already a generative agent**, the gate is dropped; `GenerativeSignal` is kept only as an informational column.
- **Tuning:** this now returns every ungrounded agent. To reduce noise, add `| where GenerativeSignal` (require a model/capabilities), `| where Published`, or `| where Platform != "LocalAgents"` to exclude IDE extensions.
- Maps `AgentStatus == "Published"` → `PublishedStatus == "Published"`.
