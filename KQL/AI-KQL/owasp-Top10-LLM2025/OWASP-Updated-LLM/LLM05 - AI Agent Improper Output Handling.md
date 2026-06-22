# AI Agent Improper Output Handling (LLM05) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic unchanged; columns mapped per [`../updated-tables.md`](../updated-tables.md). `DeclaredTools` sub-field paths are best-effort — validate against live data.

## Overview
Detects AI agents where the **generative orchestrator populates the inputs of an outbound action** — sending email, making HTTP calls, posting messages — with no hard-coded, validated values. The agent's *output* feeds straight into a system that acts on it, with nothing to sanitize it. A successful prompt injection can redirect the recipient, URL, or payload to an attacker.

**OWASP LLM Top 10:** LLM05 — Improper Output Handling
**MITRE ATT&CK:** TA0010 — Exfiltration | T1567 — Exfiltration Over Web Service
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

Picture a mailroom where the AI writes both the letter **and** the address, and the mailroom sends it without checking. Fine — until someone slips a fake instruction into what the AI reads and tricks it into addressing your confidential letter to a stranger. The safe version hard-codes the recipient; the risky version lets the AI decide it on the fly. This query finds agents that let the AI fill in the **"send to," URL, or payload** itself.

**In one sentence:** *It finds agents that let the AI freely decide who to email or what URL to call — so a hijacked agent can send your data anywhere.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365.

## KQL Query

```kql
let OutboundOps = dynamic([
    "SendEmailV2", "SendEmail", "ForwardEmail",
    "HttpRequestAction", "PostMessage", "CreateItem"
]);
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
// Agent decides its own actions (generative orchestration)
| extend IsGenAI =
        tostring(Capabilities) has_any (dynamic(["generative", "orchestration", "autonomous"]))
        or tostring(RawAgentInfo) has '"GenerativeActionsEnabled": true'
| where IsGenAI
| where isnotempty(DeclaredTools)
| mv-expand Tool = todynamic(DeclaredTools)
| extend
    OperationId = tostring(coalesce(Tool.action.operationId, Tool.operationId, Tool["$kind"])),
    ActionName  = tostring(coalesce(Tool.modelDisplayName, Tool.displayName, Tool.name)),
    ToolInputs  = tostring(coalesce(Tool.inputs, Tool.action.inputs, Tool.parameters))
| where OperationId in (OutboundOps)
// Inputs empty/absent => populated at runtime by the orchestrator (not hard-coded)
| where isempty(ToolInputs) or ToolInputs in ("{}", "[]", "null")
| extend RiskLevel = case(
        OperationId in ("SendEmailV2", "SendEmail", "ForwardEmail"), "High – AI-decided email recipient/content (exfiltration path)",
        OperationId == "HttpRequestAction",                          "High – AI-decided outbound HTTP target/payload",
        "Medium – AI-populated outbound action input")
| project
    RiskLevel, AgentName, AgentId, ActionName, OperationId,
    Owners, Availability, Platform
| sort by RiskLevel asc, AgentName asc
```

## Risk Tiers
- 🟠 **High** — AI-decided email recipient/content, or AI-decided HTTP target/payload
- 🟡 **Medium** — other AI-populated outbound action inputs

## Response Actions
1. Hard-code the recipient/URL where possible.
2. Where dynamic values are required, add validation or human approval before the action runs.
3. Cross-reference the XPIA Exposure Map — read-untrusted + AI-populated outbound = highest exfil risk.

## Migration Notes (vs AIAgentsInfo version)
- `AgentToolsDetails` → `DeclaredTools`; the `Action.inputs` emptiness check now uses `coalesce` across likely sub-fields.
- `IsGenerativeOrchestrationEnabled` has no direct column — approximated via `Capabilities` + `RawAgentInfo`. Validate against live data.
