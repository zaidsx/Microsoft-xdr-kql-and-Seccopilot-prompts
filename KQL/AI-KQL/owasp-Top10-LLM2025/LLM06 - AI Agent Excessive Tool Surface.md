# AI Agent Excessive Tool Surface (Excessive Functionality)

## Overview
Detects AI agents that have been wired up with **far more tools and actions than they need** — a broad surface of HTTP calls, email senders, connectors, MCP servers, and create/delete operations. The more functionality an agent carries, the more an attacker can do if they hijack it through prompt injection or a stolen token. A focused agent with two tools is low risk; an agent with a dozen high-impact tools is a Swiss-army knife in the wrong hands. This is the *excessive functionality* facet of excessive agency.

**OWASP LLM Top 10:** LLM06 — Excessive Agency (excessive functionality)
**MITRE ATT&CK:** TA0040 — Impact | T1565 — Data Manipulation
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

A good tool does one job well. A Swiss-army knife does twenty jobs — handy, until the wrong person is holding it.

An AI agent built for **one narrow task** should only have the **one or two tools** that task needs. But agents often get loaded up with everything "just in case" — send email, call websites, run connectors, delete records. Every extra tool is one more thing an attacker can abuse if they ever take control of the agent.

This query counts how many **high-impact tools** each agent carries and flags the over-equipped ones — especially the ones that are *also* openly accessible. The fix is simple: take away the tools the agent doesn't actually use.

**In one sentence:** *It finds agents loaded with far more powerful tools than they need — extra weapons for an attacker who hijacks them.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.
> - Inspects `AgentToolsDetails` — adjust extraction to your tenant's tool object shape if needed.

## KQL Query

```kql
// High-impact action types that meaningfully expand attack surface
let HighImpactActions = dynamic([
    "HttpRequestAction", "RemoteMCPServer", "ModelContextProtocolMetadata",
    "SendEmail", "SendEmailV2", "ForwardEmail",
    "DeleteItem", "DeleteFile", "CreateItem", "UpdateItem",
    "PostMessage", "CreateEvent", "ConnectorAction"
]);
let ToolCountThreshold = 5;   // total distinct tools considered "broad"
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where isnotempty(AgentToolsDetails)
| mv-expand Tool = AgentToolsDetails
// Best-effort extraction of an action identifier across tool shapes
| extend ActionName = tostring(coalesce(
        Tool.action.operationId,
        Tool.action.operationDetails.operationId,
        Tool.modelDisplayName,
        Tool["$kind"]))
| extend IsHighImpact =
        ActionName has_any (HighImpactActions)
        or tostring(Tool) has_any (HighImpactActions)
| summarize
    TotalTools       = dcount(ActionName),
    HighImpactTools  = dcountif(ActionName, IsHighImpact),
    ToolList         = make_set(ActionName, 50),
    HighImpactList   = make_set_if(ActionName, IsHighImpact, 50)
    by AIAgentId, AIAgentName, AccessControlPolicy, UserAuthenticationType,
       IsGenerativeOrchestrationEnabled, OwnerAccountUpns, AIModel
| extend Exposed = UserAuthenticationType == "None" or AccessControlPolicy == "Any"
| where TotalTools >= ToolCountThreshold or HighImpactTools >= 3
| extend RiskLevel = case(
        HighImpactTools >= 3 and Exposed,                          "Critical – Broad high-impact toolset on an exposed agent",
        HighImpactTools >= 3 and IsGenerativeOrchestrationEnabled, "Critical – Broad high-impact toolset with autonomous orchestration",
        HighImpactTools >= 3,                                      "High – Broad high-impact toolset",
        TotalTools >= ToolCountThreshold and HighImpactTools >= 1, "High – Large toolset including high-impact actions",
        "Medium – Large toolset")
| project
    RiskLevel, AIAgentName, AIAgentId, TotalTools, HighImpactTools,
    HighImpactList, ToolList, Exposed, IsGenerativeOrchestrationEnabled,
    UserAuthenticationType, AccessControlPolicy, AIModel, OwnerAccountUpns
| sort by RiskLevel asc, HighImpactTools desc, TotalTools desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| `TotalTools` | Distinct tools/actions the agent can invoke |
| `HighImpactTools` | How many of those are high-impact (send, HTTP, MCP, delete) |
| `HighImpactList` | The actual high-impact actions — your reduction target |
| `Exposed` | True if the agent is anonymously reachable |
| `IsGenerativeOrchestrationEnabled` | Autonomy multiplier — broad tools + self-direction = worst case |
| `RiskLevel` | Severity from toolset breadth × exposure × autonomy |

## Risk Tiers
- 🔴 **Critical** — 3+ high-impact tools *and* (exposed **or** autonomous)
- 🟠 **High** — 3+ high-impact tools, or a large toolset containing high-impact actions
- 🟡 **Medium** — large toolset overall

## Response Actions
1. Review `HighImpactList` with the owner — remove every tool the agent's actual workflow doesn't require.
2. Prioritize agents that are **exposed** or **autonomous** — they convert excess tools into real risk fastest.
3. Re-scope the agent to least functionality; prefer fixed flows over broad connector access.

## Tuning Notes
- `HighImpactActions` and `ToolCountThreshold` are the tuning levers — set the threshold to your environment's norm.
- The `ActionName` extraction uses `coalesce` across known shapes; if your tools nest differently, add the path. The `tostring(Tool) has_any` fallback catches the rest.

## Related Detections
- AI Agent Autonomy Trifecta — the autonomy facet of excessive agency
- AI Agent Over-Privileged Permissions — the permission facet of excessive agency
- AI Agent Graph API Sensitive Access — what the tools actually do at runtime
