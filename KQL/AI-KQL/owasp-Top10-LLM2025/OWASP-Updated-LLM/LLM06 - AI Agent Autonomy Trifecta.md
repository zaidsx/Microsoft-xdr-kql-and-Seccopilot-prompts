# AI Agent Autonomy Trifecta (Excessive Autonomy) (LLM06) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic unchanged; columns mapped per [`../updated-tables.md`](../updated-tables.md). Dynamic-column matching is best-effort — validate against live data.

## Overview
Detects the single most dangerous AI-agent configuration: an agent that **decides for itself what to do** (generative orchestration), **can take destructive real-world actions** (send email, HTTP, delete), and **has no behavioral guardrails** (empty system prompt). Any one alone is manageable; all three together is excessive agency.

**OWASP LLM Top 10:** LLM06 — Excessive Agency (excessive autonomy)
**MITRE ATT&CK:** TA0002 — Execution | T1648 — Serverless/Automated Execution
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

Think of an AI agent like an intern. **Generative orchestration** = the intern improvises instead of following a checklist. **Destructive tools** = they hold keys to send emails, call services, delete files. **No system prompt** = nobody gave them rules. Each is fine alone — but an intern who improvises freely, holds dangerous keys, and was never told the rules is an accident waiting to happen. This finds agents where all three are true.

**In one sentence:** *It finds AI agents that can freely decide to do dangerous things with no rules holding them back.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365. Tune `DestructiveOps` to your tenant's tool names.

## KQL Query

```kql
let DestructiveOps = dynamic([
    "SendEmail", "SendEmailV2", "ForwardEmail",
    "HttpRequestAction", "RemoteMCPServer", "Mcp",
    "DeleteItem", "DeleteFile", "CreateItem", "UpdateItem",
    "PostMessage", "CreateEvent"
]);
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| extend
    ToolsStr = tostring(DeclaredTools),
    CapStr   = tostring(Capabilities),
    AuthStr  = tolower(tostring(ToolsAuthenticationType)),
    AvailStr = tolower(tostring(Availability))
// 1) Decides its own actions?
| extend HasGenOrchestration =
        CapStr has_any (dynamic(["generative", "orchestration", "autonomous"]))
        or tostring(RawAgentInfo) has '"GenerativeActionsEnabled": true'
// 2) No behavioral guardrails? (no system prompt AND no attached Guardrails)
| extend NoInstructions =
        (isempty(Instructions) or Instructions == "N/A")
        and (isempty(McpServers) or true) // instructions-only; Guardrails handled below
| extend NoGuardrails = isempty(tostring(Guardrails)) or tostring(Guardrails) in ("[]", "{}")
| extend NoGuardrailsCombined = (isempty(Instructions) or Instructions == "N/A") and NoGuardrails
// 3) Can take a destructive action?
| extend HasDestructiveTool =
        ToolsStr has_any (DestructiveOps) or CapStr has_any (DestructiveOps) or isnotempty(McpServers)
| extend Pillars =
        toint(HasGenOrchestration) + toint(NoGuardrailsCombined) + toint(HasDestructiveTool)
| extend Exposed =
        AuthStr has "none" or AuthStr has "anonymous"
        or AvailStr has_any (dynamic(["all", "everyone", "tenant", "organization", "any"]))
| where HasDestructiveTool and Pillars >= 2
| extend RiskLevel = case(
        Pillars == 3 and Exposed, "Critical – Full autonomy trifecta on an exposed agent",
        Pillars == 3,             "Critical – Autonomous, destructive, no guardrails",
        Pillars == 2 and Exposed, "High – Two pillars on an exposed agent",
        Pillars == 2,             "High – Two of three autonomy pillars present",
        "Medium")
| extend MissingControls = trim(", ", strcat(
        iff(NoGuardrailsCombined, "no system prompt/guardrails, ", ""),
        iff(HasGenOrchestration,  "generative orchestration on, ", ""),
        iff(HasDestructiveTool,   "destructive tools present, ", ""),
        iff(Exposed,              "weak access control, ", "")))
| project
    RiskLevel, AgentName, AgentId, MissingControls,
    HasGenOrchestration, NoGuardrailsCombined, HasDestructiveTool, Exposed,
    ToolsAuthenticationType, Availability, Model, Owners, LifecycleStatus, Platform
| sort by RiskLevel asc, AgentName asc
```

## Risk Tiers
- 🔴 **Critical** — all three pillars (optionally + weak access control)
- 🟠 **High** — two pillars (destructive capability + one more)
- 🟡 **Medium** — destructive capability with a single additional weakness

## Response Actions
1. For Critical agents: add a constraining system prompt / `Guardrails` and confirm destructive tools are required.
2. If orchestration isn't needed, disable it and pin the agent to a fixed flow.
3. Tighten `ToolsAuthenticationType` / `Availability`.

## Migration Notes (vs AIAgentsInfo version)
- **Improved:** the "no guardrails" pillar now also checks the first-class `Guardrails` column, not just empty `Instructions`.
- `AgentToolsDetails` → `DeclaredTools` (+ `McpServers`); `IsGenerativeOrchestrationEnabled` approximated via `Capabilities` + `RawAgentInfo`.
- The intermediate `NoInstructions` line is retained for readability; `NoGuardrailsCombined` is the value actually scored.
