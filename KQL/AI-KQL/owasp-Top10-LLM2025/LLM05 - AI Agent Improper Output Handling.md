# AI Agent Improper Output Handling (LLM05)

## Overview
Detects AI agents where the **generative orchestrator populates the inputs of an outbound action** — sending email, making HTTP calls, posting messages — with no hard-coded, validated values. The agent's *output* is fed straight into a system that acts on it, with nothing in between to sanitize or constrain it. This is the classic improper-output-handling weakness: a successful prompt injection can redirect the email recipient, the URL, or the payload to an attacker.

**OWASP LLM Top 10:** LLM05 — Improper Output Handling
**MITRE ATT&CK:** TA0010 — Exfiltration | T1567 — Exfiltration Over Web Service
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

Picture an office mailroom where the AI writes both the letter **and** the address on the envelope, and the mailroom sends it without anyone checking. Normally fine. But if someone slips a fake instruction into what the AI reads, the AI can be tricked into addressing your confidential letter to a stranger — and the mailroom sends it anyway, because it trusts whatever the AI wrote.

The safe version hard-codes the address ("always send to the manager"). The risky version lets the AI decide the recipient on the fly.

This query finds agents where the AI fills in the **"send to," the URL, or the payload** of an action itself, instead of those being fixed and checked. Those are the agents a prompt injection can turn into an exfiltration tool.

**In one sentence:** *It finds agents that let the AI freely decide who to email or what URL to call — so a hijacked agent can send your data anywhere.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.
> - Mirrors Microsoft's published sample pattern for AI-populated action inputs.

## KQL Query

```kql
let OutboundOps = dynamic([
    "SendEmailV2", "SendEmail", "ForwardEmail",
    "HttpRequestAction", "PostMessage", "CreateItem"
]);
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| extend IsGenAI =
        IsGenerativeOrchestrationEnabled == true
        or tostring(todynamic(RawAgentInfo).Bot.Attributes.configuration) has '"GenerativeActionsEnabled": true'
| where IsGenAI
| where isnotempty(AgentToolsDetails)
| mv-expand Action = AgentToolsDetails
| extend
    OperationId = tostring(Action.action.operationId),
    ActionName  = tostring(Action.modelDisplayName)
| where OperationId in (OutboundOps)
// Inputs empty => populated at runtime by the generative orchestrator (not hard-coded)
| where isempty(tostring(Action.inputs)) or tostring(Action.inputs) == "{}" or tostring(Action.inputs) == "[]"
| extend RiskLevel = case(
        OperationId in ("SendEmailV2", "SendEmail", "ForwardEmail"), "High – AI-decided email recipient/content (exfiltration path)",
        OperationId == "HttpRequestAction",                          "High – AI-decided outbound HTTP target/payload",
        "Medium – AI-populated outbound action input")
| project
    RiskLevel, AIAgentName, AIAgentId, ActionName, OperationId,
    OwnerAccountUpns, CreatorAccountUpn, AccessControlPolicy, RegistrySource
| sort by RiskLevel asc, AIAgentName asc
```

## Risk Tiers
- 🟠 **High** — AI-decided email recipient/content, or AI-decided HTTP target/payload
- 🟡 **Medium** — other AI-populated outbound action inputs

## Response Actions
1. Hard-code the recipient/URL where possible (e.g., always send to a fixed mailbox).
2. Where dynamic values are required, add validation or human approval before the action runs.
3. Combine with the XPIA Exposure Map — agents that read untrusted content *and* have AI-populated outbound actions are the highest exfiltration risk.

## Tuning Notes
- The `Action.inputs` emptiness check follows Microsoft's sample; confirm the exact shape in your tenant and adjust the path if your tool objects nest inputs differently.

## Related Detections
- AI Agent XPIA Exposure Map — the input side of the same attack
- AI Agent Autonomy Trifecta — broader autonomous-action risk
