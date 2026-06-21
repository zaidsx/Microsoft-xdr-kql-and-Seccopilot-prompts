# AI Agent Misinformation Risk (LLM09)

## Overview
Detects AI agents configured in a way that makes **confident-but-unreliable output** likely: a generative agent with **no grounding knowledge source** (nothing authoritative to draw on) and often **no system prompt** constraining its accuracy. Such agents answer freely from the model's parametric memory, with no source of truth, and tend to fabricate. When that agent is published to real users, its made-up answers become operational misinformation.

**OWASP LLM Top 10:** LLM09 — Misinformation
**MITRE ATT&CK:** (no direct mapping — governance/safety risk)
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

If you ask someone a detailed question and they have **no reference material**, no notes, no rulebook — just their memory — they'll often give you an answer that *sounds* right but isn't. Now imagine that person is wearing a company badge and customers believe everything they say.

That's an AI agent that **generates freely but has nothing factual to ground its answers in**. It will confidently make things up. If it's also **published** and has **no instructions** telling it to stick to facts or say "I don't know," the misinformation risk is high.

This query finds those ungrounded, free-generating agents — especially the ones already live in front of users.

**In one sentence:** *It finds agents that answer confidently with no factual source behind them — the ones most likely to make things up.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.

## KQL Query

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| extend IsGenAI =
        IsGenerativeOrchestrationEnabled == true
        or tostring(todynamic(RawAgentInfo).Bot.Attributes.configuration) has '"GenerativeActionsEnabled": true'
| extend NoKnowledge =
        isempty(tostring(KnowledgeDetails))
        or tostring(KnowledgeDetails) in ("[]", "{}", "")
| extend NoInstructions = isempty(Instructions) or Instructions == "N/A"
| extend Published = AgentStatus == "Published"
// Generates freely with no grounded source of truth
| where IsGenAI and NoKnowledge
| extend RiskLevel = case(
        Published and NoInstructions, "High – Published autonomous agent: no grounding and no guardrails",
        Published,                    "High – Published agent generating without grounded knowledge",
        NoInstructions,               "Medium – Ungrounded agent with no behavioral guidance",
        "Medium – Agent generates without grounded knowledge")
| project
    RiskLevel, AIAgentName, AIAgentId, Published, NoKnowledge, NoInstructions,
    AgentStatus, AccessControlPolicy, AIModel, OwnerAccountUpns, AgentDescription
| sort by RiskLevel asc, AIAgentName asc
```

## Risk Tiers
- 🟠 **High** — published, generating, with no grounding (and worse if no guardrails)
- 🟡 **Medium** — ungrounded generative agent not yet broadly published

## Response Actions
1. Attach an authoritative knowledge source so answers are grounded, not invented.
2. Add a system prompt instructing the agent to cite sources and say "I don't know" when unsure.
3. For high-stakes use cases, require human review of agent output before it's acted on.

## Tuning Notes
- This is a **configuration/governance** signal, not an attack signal — treat findings as quality/risk debt to remediate, not incidents to investigate.
- Some agents are legitimately ungrounded (creative/brainstorming assistants) — allowlist those by `AIAgentId`.

## Related Detections
- AI Agent Knowledge & Model Drift — when grounding sources change
- AI Agent Autonomy Trifecta — ungrounded *and* able to act is worse still
