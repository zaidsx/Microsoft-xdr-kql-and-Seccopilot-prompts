# AI Agent Untrusted Tool Supply Chain (MCP & External Endpoints) (LLM03) — AgentsInfo

> **Verified against the live `AgentsInfo` schema.** Uses `McpServers` (confirmed) and wraps `Endpoints` in `column_ifexists()` (not present in every tenant). URLs are pulled by regex over the raw column text, so it works regardless of internal field names.

## Overview
Detects AI agents wired to **untrusted external tool endpoints** — MCP servers / endpoints using non-HTTPS schemes, raw IP addresses, or external servers. Each external endpoint is a supply-chain link that can feed the agent poison or steal what it sends.

**OWASP LLM Top 10:** LLM03 — Supply Chain
**MITRE ATT&CK:** TA0011 — Command and Control | T1071 — Application Layer Protocol
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
An agent reaches out to other services to get work done — each is a supplier it trusts. This flags sketchy suppliers: unencrypted (non-HTTPS) links, raw-IP endpoints, and external MCP servers.

## KQL Query

```kql
AgentsInfo
| extend Endpoints = column_ifexists("Endpoints", dynamic([]))
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| extend McpStr = tostring(McpServers), EndpointStr = tostring(Endpoints)
| where (isnotempty(McpServers) and McpStr !in ("[]", "{}")) or (EndpointStr !in ("[]", "{}", "", "null"))
| extend AllUrls = extract_all(@"(https?://[^\s""'\]\},]+)", strcat(McpStr, " ", EndpointStr))
| mv-expand Url = AllUrls to typeof(string)
| extend Parsed = parse_url(Url)
| extend Scheme = tostring(Parsed["Scheme"]), Host = tostring(Parsed["Host"])
| extend IsRawIp    = Host matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
| extend IsInsecure = isnotempty(Scheme) and Scheme != "https"
| extend FromMcp    = McpStr contains Url
| where IsInsecure or IsRawIp or FromMcp
| extend RiskLevel = case(
        FromMcp and (IsInsecure or IsRawIp), "Critical – MCP server over insecure or raw-IP endpoint",
        IsInsecure and IsRawIp,              "High – Insecure connection to a raw IP",
        IsInsecure,                          "High – Tool endpoint not using HTTPS",
        IsRawIp,                             "High – Tool endpoint is a raw IP address",
        FromMcp,                             "Medium – External MCP server configured",
        "Medium – Externally connected endpoint")
| project RiskLevel, Name, AgentId, Url, Scheme, Host, FromMcp, IsInsecure, IsRawIp, Owners, Platform
| sort by RiskLevel asc, Name asc
```

## Risk Tiers
- 🔴 **Critical** — MCP server over an insecure or raw-IP endpoint
- 🟠 **High** — any non-HTTPS or raw-IP endpoint
- 🟡 **Medium** — external MCP server or externally connected endpoint

## Response Actions
1. Confirm each external endpoint / MCP server is required.
2. Force HTTPS and a named domain; remove raw-IP targets.
3. For MCP servers: verify identity, review credential config, least privilege.

## Notes
- In the sample tenant `McpServers` was empty for most agents, so expect few/no results until agents declare MCP servers. URL detection is regex-based over raw text — shape-agnostic.
