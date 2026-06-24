# AI Agent XPIA Exposure Map (Indirect Prompt Injection) — AgentsInfo

> **Built and verified against the live `AgentsInfo` schema** (confirmed column names: `Name`, `Description`, `EntraAgentID`, etc.). Columns not present in every tenant (`ToolsAuthenticationType`, `Availability`) are wrapped in `column_ifexists()` so the query never errors. Access exposure is inferred from `SharedWith`.

## Overview
Maps every AI agent meeting the **structural precondition for indirect prompt injection (XPIA)**: it *reads untrusted external content* AND *can take an outbound/destructive action*. The combination is what an attacker weaponizes by planting instructions in content the agent ingests.

**OWASP LLM Top 10:** LLM01 — Prompt Injection (indirect / XPIA)
**MITRE ATT&CK:** TA0001 — Initial Access | T1566 — Phishing
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
For indirect injection to do damage, an agent must both **read untrusted content** (poison gets in) and **be able to act** (damage gets out). This lists every agent where both are true.

## KQL Query

```kql
let UntrustedSources = dynamic(["http","https","www","public","external","web","website","internet","url","rss","feed"]);
// Human-readable tool-name tokens (real DeclaredTools names look like "Office 365 Outlook Send an email (V2)")
let ActOps = dynamic(["email","Outlook","Send","Post","HTTP","Http","webhook","Teams","SharePoint","OneDrive","Dataverse","SQL","Delete","Create","Update","CodeInterpreter"]);
let BroadShare = dynamic(["everyone","all","organization","tenant","AllUsers","anyone","public"]);
AgentsInfo
| extend
    Availability            = column_ifexists("Availability", ""),
    ToolsAuthenticationType = column_ifexists("ToolsAuthenticationType", "")
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| extend HasMcp = isnotempty(McpServers) and tostring(McpServers) !in ("[]", "{}", "null")
| extend ReadsUntrusted =
        tostring(DeclaredDataSources) has_any (UntrustedSources)
        or tostring(DeclaredTools) has_any (dynamic(["HTTP","Http","web","url"]))
        or HasMcp
        or tostring(RawAgentInfo) has_any (dynamic(["http","web","url"]))
| extend CanAct =
        tostring(DeclaredTools) has_any (ActOps)
        or tostring(Capabilities) has_any (ActOps)
        or HasMcp
| where ReadsUntrusted and CanAct
| extend Autonomous =
        tostring(Capabilities) has_any (dynamic(["generative","orchestration","autonomous"]))
        or tostring(RawAgentInfo) has "GenerativeActionsEnabled"
| extend Exposed =
        strcat(tostring(Availability), " ", tostring(SharedWith), " ", tostring(ToolsAuthenticationType))
            has_any (array_concat(BroadShare, dynamic(["None","Anonymous"])))
| extend RiskLevel = case(
        Autonomous and Exposed, "Critical – Injectable, autonomous, and broadly shared",
        Autonomous,             "High – Reads untrusted content and can autonomously act",
        Exposed,                "High – Injectable and broadly shared",
        "Medium – Reads untrusted content and can act")
| project
    RiskLevel, Name, AgentId, ReadsUntrusted, CanAct, Autonomous, Exposed,
    SharedWith, DeclaredDataSources, DeclaredTools, McpServers, Model, Owners, Platform
| sort by RiskLevel asc, Name asc
```

## Risk Tiers
- 🔴 **Critical** — reads untrusted + can act + autonomous + broadly shared
- 🟠 **High** — autonomous, or broadly shared, on top of read+act
- 🟡 **Medium** — base read-untrusted + can-act precondition

## Response Actions
1. Restrict `DeclaredDataSources` to trusted internal sources where possible.
2. Constrain the actions an agent can take where it reads external content.
3. Add a system prompt telling the agent to ignore instructions embedded in retrieved content.
4. Resolve `Owners` GUIDs via `IdentityInfo` to reach the agent owner.
