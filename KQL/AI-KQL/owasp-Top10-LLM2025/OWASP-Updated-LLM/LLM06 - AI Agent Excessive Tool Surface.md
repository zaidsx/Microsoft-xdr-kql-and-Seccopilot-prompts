# AI Agent Excessive Tool Surface (Excessive Functionality) (LLM06) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic unchanged; columns mapped per [`../updated-tables.md`](../updated-tables.md). `DeclaredTools` sub-field paths are best-effort — validate against live data.

## Overview
Detects AI agents wired up with **far more tools and actions than they need** — a broad surface of HTTP calls, email senders, connectors, MCP servers, and create/delete operations. The more functionality an agent carries, the more an attacker can do if they hijack it.

**OWASP LLM Top 10:** LLM06 — Excessive Agency (excessive functionality)
**MITRE ATT&CK:** TA0040 — Impact | T1565 — Data Manipulation
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

A good tool does one job. A Swiss-army knife does twenty — handy until the wrong person holds it. An agent built for one task should carry only the one or two tools it needs, but agents often get loaded with everything "just in case." Every extra tool is one more thing an attacker can abuse. This query counts each agent's **high-impact tools** and flags the over-equipped ones — especially the openly accessible ones.

**In one sentence:** *It finds agents loaded with far more powerful tools than they need — extra weapons for an attacker who hijacks them.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365.

## KQL Query

```kql
let HighImpactActions = dynamic([
    "HttpRequestAction", "RemoteMCPServer", "Mcp", "ModelContextProtocol",
    "SendEmail", "SendEmailV2", "ForwardEmail",
    "DeleteItem", "DeleteFile", "CreateItem", "UpdateItem",
    "PostMessage", "CreateEvent", "ConnectorAction"
]);
let ToolCountThreshold = 5;
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(DeclaredTools)
| mv-expand Tool = todynamic(DeclaredTools)
| extend ActionName = tostring(coalesce(
        Tool.action.operationId, Tool.operationId, Tool.modelDisplayName,
        Tool.displayName, Tool.name, Tool["$kind"]))
| extend IsHighImpact =
        ActionName has_any (HighImpactActions) or tostring(Tool) has_any (HighImpactActions)
| summarize
    TotalTools      = dcount(ActionName),
    HighImpactTools = dcountif(ActionName, IsHighImpact),
    ToolList        = make_set(ActionName, 50),
    HighImpactList  = make_set_if(ActionName, IsHighImpact, 50),
    McpPresent      = take_anyif(McpServers, isnotempty(McpServers)),
    CapStr          = take_any(Capabilities),
    AuthType        = take_any(ToolsAuthenticationType),
    Avail           = take_any(Availability),
    Owners          = take_any(Owners)
    by AgentId, AgentName, Platform
| extend Exposed =
        tolower(tostring(AuthType)) has "none"
        or tolower(tostring(Avail)) has_any (dynamic(["all", "everyone", "tenant", "organization", "any"]))
| extend Autonomous = tostring(CapStr) has_any (dynamic(["generative", "orchestration", "autonomous"]))
| where TotalTools >= ToolCountThreshold or HighImpactTools >= 3
| extend RiskLevel = case(
        HighImpactTools >= 3 and Exposed,    "Critical – Broad high-impact toolset on an exposed agent",
        HighImpactTools >= 3 and Autonomous, "Critical – Broad high-impact toolset with autonomous orchestration",
        HighImpactTools >= 3,                "High – Broad high-impact toolset",
        TotalTools >= ToolCountThreshold and HighImpactTools >= 1, "High – Large toolset including high-impact actions",
        "Medium – Large toolset")
| project
    RiskLevel, AgentName, AgentId, TotalTools, HighImpactTools,
    HighImpactList, ToolList, Exposed, Autonomous,
    ToolsAuthenticationType = AuthType, Availability = Avail, Owners, Platform
| sort by RiskLevel asc, HighImpactTools desc, TotalTools desc
```

## Risk Tiers
- 🔴 **Critical** — 3+ high-impact tools *and* (exposed **or** autonomous)
- 🟠 **High** — 3+ high-impact tools, or a large toolset containing high-impact actions
- 🟡 **Medium** — large toolset overall

## Response Actions
1. Review `HighImpactList` with the owner — remove tools the workflow doesn't need.
2. Prioritize exposed/autonomous agents.
3. Re-scope to least functionality; prefer fixed flows over broad connector access.

## Migration Notes (vs AIAgentsInfo version)
- `AgentToolsDetails` → `DeclaredTools`; MCP tools also surface via the first-class `McpServers` column.
- `IsGenerativeOrchestrationEnabled` approximated via `Capabilities`. The `ActionName` `coalesce` paths are best-effort; the `tostring(Tool) has_any` fallback catches the rest.
