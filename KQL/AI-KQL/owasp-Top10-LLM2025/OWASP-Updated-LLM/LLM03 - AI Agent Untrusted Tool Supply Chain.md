# AI Agent Untrusted Tool Supply Chain (MCP & External Endpoints) (LLM03) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). This detection gets **cleaner** in the new schema: `McpServers` and `Endpoints` are now first-class columns instead of being parsed out of `AgentActionTriggers`. Dynamic sub-field paths are best-effort — validate against live data.

## Overview
Detects AI agents wired to **untrusted external tool endpoints** — Model Context Protocol (MCP) servers and runtime endpoints that use non-HTTPS schemes, raw IP addresses, or external servers. Every external endpoint an agent calls is a link in its supply chain: a malicious or insecure server can feed it poisoned data, steal what it sends, or run attacker-controlled operations.

**OWASP LLM Top 10:** LLM03 — Supply Chain
**MITRE ATT&CK:** TA0011 — Command and Control | T1071 — Application Layer Protocol
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

An AI agent reaches out to other services — APIs, databases, MCP "tool servers" — to get work done. Each is a supplier it trusts. This query flags sketchy suppliers: connections **not using HTTPS** (unencrypted, tamperable), endpoints that are a **raw IP address** (no name, no accountability), and **external MCP servers** (a powerful new plugin type that needs vetting).

**In one sentence:** *It finds agents connected to sketchy outside services — unencrypted links, anonymous IPs, and external tool servers that could feed them poison or steal their data.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365.
> - Reads the first-class `McpServers` and `Endpoints` columns.

## KQL Query

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(McpServers) or isnotempty(Endpoints)
// Normalize MCP servers and runtime endpoints into one stream of (Url, Source)
| extend McpList = todynamic(McpServers), EndpointList = todynamic(Endpoints)
| mv-expand Item = array_concat(
        iff(isnull(McpList), dynamic([]), McpList),
        iff(isnull(EndpointList), dynamic([]), EndpointList))
| extend Url = tostring(coalesce(
        Item.url, Item.serverUrl, Item.serverUrls, Item.endpoint, Item.endpointUrl, Item.uri))
| extend Transport = tostring(coalesce(Item.transportType, Item.transport, Item.protocol))
| extend ExternalFlag = tostring(coalesce(Item.externalConnectivity, Item.isExternal, Item.external))
| where isnotempty(Url)
| extend Parsed = parse_url(Url)
| extend Scheme = tostring(Parsed["Scheme"]), Host = tostring(Parsed["Host"])
| extend IsRawIp    = Host matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
| extend IsInsecure = isnotempty(Scheme) and Scheme != "https"
| extend IsExternal = tolower(ExternalFlag) == "true"
| where IsInsecure or IsRawIp or IsExternal
| extend RiskLevel = case(
        IsExternal and (IsInsecure or IsRawIp), "Critical – External endpoint over insecure or raw-IP connection",
        IsInsecure and IsRawIp,                 "High – Insecure connection to a raw IP",
        IsInsecure,                             "High – Tool endpoint not using HTTPS",
        IsRawIp,                                "High – Tool endpoint is a raw IP address",
        IsExternal,                             "Medium – Externally connected endpoint",
        "Low")
| project
    RiskLevel, AgentName, AgentId, Url, Scheme, Host, Transport,
    IsExternal, IsInsecure, IsRawIp, Owners, Platform
| sort by RiskLevel asc, AgentName asc
```

> ⚠️ The `coalesce(...)` field names (`url`, `serverUrl`, `transportType`, `externalConnectivity`, etc.) are best-effort guesses at the `McpServers`/`Endpoints` sub-fields. Once you can see live rows, replace them with the real sub-field names — the query is structured so only those names need adjusting.

## Risk Tiers
- 🔴 **Critical** — external endpoint over an insecure or raw-IP connection
- 🟠 **High** — any non-HTTPS or raw-IP endpoint
- 🟡 **Medium** — externally connected endpoint (vet even if HTTPS)

## Response Actions
1. Confirm with the owner whether each external endpoint / MCP server is required.
2. Force HTTPS and a named, verifiable domain; remove raw-IP targets.
3. For MCP servers: verify identity, review credential configuration, apply least privilege, remove unused ones.

## Migration Notes (vs AIAgentsInfo version)
- Old version parsed `AgentActionTriggers` → `serverUrls`. New version reads the dedicated **`McpServers`** and **`Endpoints`** columns — more reliable and complete.
- `Endpoints` is documented to include "URL, transport type, and external connectivity flag," so the intended sub-fields exist; exact names are confirmed against live data.
