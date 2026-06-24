# AI Agent Improper Output Handling (LLM05) — AgentsInfo

> **Verified against the live `AgentsInfo` schema.** Uses confirmed columns only; orchestration is inferred from `Capabilities` + `RawAgentInfo`.

## Overview
Detects agents that are **autonomous and hold outbound actions** (send email, HTTP, post) where the agent's output drives the action. When output flows into an action without validation, a prompt injection can redirect the recipient/URL/payload.

**OWASP LLM Top 10:** LLM05 — Improper Output Handling
**MITRE ATT&CK:** TA0010 — Exfiltration | T1567 — Exfiltration Over Web Service
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
A mailroom where the AI writes both the letter and the address, sent unchecked — until someone tricks it into mailing your secrets to a stranger. This finds autonomous agents holding outbound "send/call" actions.

## KQL Query

```kql
// Human-readable tool-name tokens (real DeclaredTools names look like "Office 365 Outlook Send an email (V2)")
let OutboundOps = dynamic(["email","Outlook","Send","Post","HTTP","Http","webhook","Teams"]);
let BroadShare = dynamic(["everyone","all","organization","tenant","AllUsers","anyone","public"]);
AgentsInfo
| extend Availability = column_ifexists("Availability", "")
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
// Core signal: the agent HOLDS an outbound action (email / HTTP / post)
| extend HasOutbound =
        tostring(DeclaredTools) has_any (OutboundOps)
        or tostring(Capabilities) has_any (OutboundOps)
| where HasOutbound
| extend EmailSend = tostring(DeclaredTools) has_any (dynamic(["email","Outlook"]))
| extend HttpCall  = tostring(DeclaredTools) has_any (dynamic(["HTTP","Http","webhook"]))
// Autonomy is an ESCALATOR, not a hard filter (AgentsInfo exposes no reliable orchestration flag).
| extend Autonomous =
        tostring(Capabilities) has_any (dynamic(["generative","orchestration","autonomous","CodeInterpreter","Copilot"]))
        or tostring(RawAgentInfo) has "GenerativeActionsEnabled"
| extend Exposed = strcat(tostring(Availability), " ", tostring(SharedWith)) has_any (BroadShare)
| extend RiskLevel = case(
        EmailSend and (Exposed or Autonomous), "Critical – Outbound email send on an exposed/autonomous agent",
        EmailSend,                             "High – Agent can send email (data exfiltration path)",
        HttpCall,                              "High – Agent can make outbound HTTP (output injection path)",
        "Medium – Agent holds an outbound action")
| project RiskLevel, Name, AgentId, EmailSend, HttpCall, Autonomous, Exposed, DeclaredTools, SharedWith, Owners, Platform
| sort by RiskLevel asc, Name asc
```

## Risk Tiers
- 🔴 **Critical** — email-send tool on an exposed **or** autonomous agent
- 🟠 **High** — agent can send email, or make outbound HTTP
- 🟡 **Medium** — agent holds any outbound action

## Response Actions
1. Hard-code the recipient/URL where possible.
2. Where dynamic values are required, add validation or human approval.
3. Cross-reference the XPIA Exposure Map.

## Notes
- **Autonomy is an escalator, not a gate.** Earlier versions hard-filtered on `IsGenerativeOrchestrationEnabled` / generative-keyword detection, but `AgentsInfo` exposes no reliable orchestration flag and real `Capabilities` look like `["CodeInterpreter","Copilot"]` — so that gate dropped every row. This version flags any agent holding an outbound action and escalates the autonomous/exposed ones.
- Results appear only for agents that declare an outbound tool (e.g., "Office 365 Outlook Send an email (V2)").
