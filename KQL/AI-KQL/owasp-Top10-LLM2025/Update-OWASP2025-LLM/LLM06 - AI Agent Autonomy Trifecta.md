# AI Agent Autonomy Trifecta (Excessive Autonomy) (LLM06) — AgentsInfo

> **Verified against the live `AgentsInfo` schema.** `Guardrails` (not present in every tenant) is wrapped in `column_ifexists()`; the no-guardrails pillar falls back to empty `Instructions`.

## Overview
Detects the most dangerous configuration: an agent that **decides for itself** (generative orchestration), **can take destructive actions** (send/HTTP/delete/MCP), and **has no guardrails** (empty `Instructions`/`Guardrails`).

**OWASP LLM Top 10:** LLM06 — Excessive Agency (excessive autonomy)
**MITRE ATT&CK:** TA0002 — Execution | T1648 — Automated Execution
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
An intern who improvises freely, holds dangerous keys, and was never told the rules. This finds agents that are autonomous, hold destructive tools, and have no guardrails — all at once.

## KQL Query

```kql
// Human-readable tool-name tokens (real DeclaredTools names look like "Office 365 Outlook Send an email (V2)")
let DestructiveOps = dynamic(["email","Outlook","Send","Post","HTTP","Http","webhook","Teams","Delete","Create","Update","SharePoint","OneDrive","Dataverse","SQL","CodeInterpreter"]);
let BroadShare = dynamic(["everyone","all","organization","tenant","AllUsers","anyone","public"]);
AgentsInfo
| extend
    Guardrails   = column_ifexists("Guardrails", dynamic([])),
    Availability = column_ifexists("Availability", "")
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| extend HasMcp = isnotempty(McpServers) and tostring(McpServers) !in ("[]", "{}", "null")
| extend HasGenOrchestration =
        tostring(Capabilities) has_any (dynamic(["generative","orchestration","autonomous"]))
        or tostring(RawAgentInfo) has "GenerativeActionsEnabled"
| extend NoGuardrails =
        (isempty(Instructions) or Instructions == "N/A")
        and (isempty(Guardrails) or tostring(Guardrails) in ("[]", "{}", "null"))
| extend HasDestructiveTool =
        tostring(DeclaredTools) has_any (DestructiveOps)
        or tostring(Capabilities) has_any (DestructiveOps)
        or HasMcp
| extend Pillars = toint(HasGenOrchestration) + toint(NoGuardrails) + toint(HasDestructiveTool)
| extend Exposed = strcat(tostring(Availability), " ", tostring(SharedWith)) has_any (BroadShare)
| where HasDestructiveTool and Pillars >= 2
| extend RiskLevel = case(
        Pillars == 3 and Exposed, "Critical – Full autonomy trifecta on a broadly shared agent",
        Pillars == 3,             "Critical – Autonomous, destructive, no guardrails",
        Pillars == 2 and Exposed, "High – Two pillars on a broadly shared agent",
        Pillars == 2,             "High – Two of three autonomy pillars present",
        "Medium")
| extend MissingControls = trim(", ", strcat(
        iff(NoGuardrails,        "no system prompt/guardrails, ", ""),
        iff(HasGenOrchestration, "generative orchestration on, ", ""),
        iff(HasDestructiveTool,  "destructive tools present, ", ""),
        iff(Exposed,             "broadly shared, ", "")))
| project RiskLevel, Name, AgentId, MissingControls,
          HasGenOrchestration, NoGuardrails, HasDestructiveTool, Exposed,
          SharedWith, Model, Owners, LifecycleStatus, Platform
| sort by RiskLevel asc, Name asc
```

## Risk Tiers
- 🔴 **Critical** — all three pillars (optionally + broadly shared)
- 🟠 **High** — two pillars (destructive capability + one more)
- 🟡 **Medium** — destructive capability with a single additional weakness

## Response Actions
1. Add a constraining system prompt; confirm destructive tools are required.
2. Disable generative orchestration if not needed.
3. Narrow `SharedWith`.
