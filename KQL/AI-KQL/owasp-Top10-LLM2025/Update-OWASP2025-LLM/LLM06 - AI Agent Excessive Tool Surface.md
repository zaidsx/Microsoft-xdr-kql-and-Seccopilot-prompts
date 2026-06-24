# AI Agent Excessive Tool Surface (Excessive Functionality) (LLM06) — AgentsInfo

> **Verified against the live `AgentsInfo` schema.** Counts tools via `array_length` on `DeclaredTools`/`McpServers` and classifies high-impact ones by content matching.

## Overview
Detects AI agents wired with **far more tools than they need**. The more functionality an agent carries, the more an attacker can do if they hijack it.

**OWASP LLM Top 10:** LLM06 — Excessive Agency (excessive functionality)
**MITRE ATT&CK:** TA0040 — Impact | T1565 — Data Manipulation
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
A good tool does one job; a Swiss-army knife does twenty — handy until the wrong person holds it. This counts each agent's tools and flags the over-equipped ones.

## KQL Query

```kql
// Human-readable tool-name tokens (real DeclaredTools names look like "Office 365 Outlook Send an email (V2)")
let HighImpactActions = dynamic(["email","Outlook","HTTP","Http","webhook","Teams","Delete","Create","Update","SharePoint","OneDrive","Dataverse","SQL","Send","CodeInterpreter"]);
let ToolCountThreshold = 5;
let BroadShare = dynamic(["everyone","all","organization","tenant","AllUsers","anyone","public"]);
AgentsInfo
| extend Availability = column_ifexists("Availability", "")
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| extend ToolsArr = todynamic(DeclaredTools), McpArr = todynamic(McpServers)
| extend TotalTools = coalesce(array_length(ToolsArr), 0) + coalesce(array_length(McpArr), 0)
| extend HighImpactPresent = set_intersect(extract_all(@"([A-Za-z]+)", tostring(DeclaredTools)), HighImpactActions)
| extend HighImpactTools = array_length(HighImpactPresent)
        + iff(isnotempty(McpServers) and tostring(McpServers) !in ("[]", "{}"), 1, 0)
| extend Exposed = strcat(tostring(Availability), " ", tostring(SharedWith)) has_any (BroadShare)
| extend Autonomous = tostring(Capabilities) has_any (dynamic(["generative","orchestration","autonomous"]))
| where TotalTools >= ToolCountThreshold or HighImpactTools >= 3
| extend RiskLevel = case(
        HighImpactTools >= 3 and Exposed,    "Critical – Broad high-impact toolset on a broadly shared agent",
        HighImpactTools >= 3 and Autonomous, "Critical – Broad high-impact toolset with autonomous orchestration",
        HighImpactTools >= 3,                "High – Broad high-impact toolset",
        TotalTools >= ToolCountThreshold and HighImpactTools >= 1, "High – Large toolset including high-impact actions",
        "Medium – Large toolset")
| project RiskLevel, Name, AgentId, TotalTools, HighImpactTools, HighImpactPresent,
          Exposed, Autonomous, SharedWith, Owners, Platform
| sort by RiskLevel asc, HighImpactTools desc, TotalTools desc
```

## Risk Tiers
- 🔴 **Critical** — 3+ high-impact tools *and* (broadly shared **or** autonomous)
- 🟠 **High** — 3+ high-impact tools, or a large toolset with high-impact actions
- 🟡 **Medium** — large toolset overall

## Response Actions
1. Review `HighImpactPresent` with the owner — remove tools not needed.
2. Prioritize broadly shared / autonomous agents.

## Notes
- In the sample tenant `DeclaredTools` was often empty, so expect results only where agents declare multiple tools.
