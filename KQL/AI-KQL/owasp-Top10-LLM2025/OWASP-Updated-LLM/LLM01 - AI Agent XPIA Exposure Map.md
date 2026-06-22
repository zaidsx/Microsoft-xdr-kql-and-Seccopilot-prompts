# AI Agent XPIA Exposure Map (Indirect Prompt Injection) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic is unchanged; columns are mapped per [`../updated-tables.md`](../updated-tables.md). Dynamic-column paths (`DeclaredDataSources`, `DeclaredTools`, `Capabilities`) are **best-effort** — validate against live data before production.

## Overview
Maps every AI agent that meets the **structural precondition for indirect prompt injection (XPIA)**: it *reads untrusted external content* AND *can take an outbound or destructive action*. You can't easily detect the injection payload itself — but you can inventory every agent an attacker could weaponize by planting instructions in a document, web page, or email the agent ingests.

**OWASP LLM Top 10:** LLM01 — Prompt Injection (indirect / XPIA)
**MITRE ATT&CK:** TA0001 — Initial Access | T1566 — Phishing (content-borne instructions)
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

Indirect prompt injection hides secret instructions inside something the agent will *read* — a web page, a shared document, an incoming email. The agent reads it, mistakes the hidden text for a command, and obeys. For that to do damage two things must both be true: the agent **reads untrusted content** (how the poison gets in) and **can act** (how the damage gets out). This query lists every agent where both are true.

**In one sentence:** *It finds agents that both read untrusted content and can take action — the ones an attacker can hijack by hiding commands in a document.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365 (unified successor to `AIAgentsInfo`).
> - Tune `UntrustedSources` and `ActOps` to your tenant's data sources and tool names.

## KQL Query

```kql
let UntrustedSources = dynamic([
    "http", "www.", "public", "external", "web search",
    "website", "url", "internet", "rss", "feed"
]);
let ActOps = dynamic([
    "SendEmail", "SendEmailV2", "ForwardEmail", "HttpRequestAction",
    "PostMessage", "CreateItem", "UpdateItem", "DeleteItem", "Mcp", "RemoteMCPServer"
]);
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| extend
    KnowledgeStr = tolower(tostring(DeclaredDataSources)),
    ToolsStr     = tostring(DeclaredTools),
    CapStr       = tostring(Capabilities),
    McpStr       = tostring(McpServers),
    AuthStr      = tolower(tostring(ToolsAuthenticationType)),
    AvailStr     = tolower(tostring(Availability))
// 1) Reads untrusted / external content?
| extend ReadsUntrusted =
        KnowledgeStr has_any (UntrustedSources)
        or ToolsStr has "Http" or CapStr has "Http"
// 2) Can take an outbound / destructive action?
| extend CanAct =
        ToolsStr has_any (ActOps) or CapStr has_any (ActOps) or isnotempty(McpServers)
| where ReadsUntrusted and CanAct
| extend Autonomous =
        CapStr has_any (dynamic(["generative", "orchestration", "autonomous"]))
        or tostring(RawAgentInfo) has '"GenerativeActionsEnabled": true'
| extend Exposed =
        AuthStr has "none" or AuthStr has "anonymous"
        or AvailStr has_any (dynamic(["all", "everyone", "tenant", "organization", "any"]))
| extend RiskLevel = case(
        Autonomous and Exposed, "Critical – Injectable, autonomous, and openly reachable",
        Autonomous,             "High – Reads untrusted content and can autonomously act",
        Exposed,                "High – Injectable and openly reachable",
        "Medium – Reads untrusted content and can act")
| project
    RiskLevel, AgentName, AgentId, ReadsUntrusted, CanAct, Autonomous, Exposed,
    ToolsAuthenticationType, Availability, DeclaredDataSources,
    Model, Owners, Platform
| sort by RiskLevel asc, AgentName asc
```

## Risk Tiers
- 🔴 **Critical** — reads untrusted + can act + autonomous + openly reachable
- 🟠 **High** — autonomous, or openly reachable, on top of the read+act combo
- 🟡 **Medium** — the base read-untrusted + can-act precondition

## Response Actions
1. Review `DeclaredDataSources` — restrict to trusted, internal sources where possible.
2. Where external content is required, constrain the actions the agent can take (remove send/HTTP/delete or require approval).
3. Add a system prompt instructing the agent to ignore instructions embedded in retrieved content.
4. Tighten `ToolsAuthenticationType` / `Availability` so untrusted users can't feed it directly.

## Migration Notes (vs AIAgentsInfo version)
- `KnowledgeDetails` → `DeclaredDataSources`; `AgentToolsDetails` → `DeclaredTools` (+ `McpServers`, now first-class).
- `IsGenerativeOrchestrationEnabled` has **no direct column** — approximated via `Capabilities` keywords + `RawAgentInfo`. Confirm the real location once you can inspect live `AgentsInfo` rows.
- `UserAuthenticationType`/`AccessControlPolicy` → `ToolsAuthenticationType`/`Availability` (now structured) — matched via string contains.
