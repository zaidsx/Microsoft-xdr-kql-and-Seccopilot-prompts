# AI Agent Untrusted Tool Supply Chain (MCP & External Endpoints)

## Overview
Detects AI agents wired to **untrusted external tool endpoints** — Model Context Protocol (MCP) servers and HTTP actions that point to non-HTTPS schemes, raw IP addresses, or external servers. Every external endpoint an agent calls is a link in its supply chain: if that server is malicious, compromised, or simply insecure, it can feed the agent poisoned data, steal whatever the agent sends it, or execute attacker-controlled operations. MCP in particular is the newest and least-governed agent integration surface.

**OWASP LLM Top 10:** LLM03 — Supply Chain
**MITRE ATT&CK:** TA0011 — Command and Control | T1071 — Application Layer Protocol
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

An AI agent rarely works alone — it reaches out to **other services** to get things done: a weather API, a database, an MCP "tool server." Each of those is a supplier the agent trusts.

But what if a supplier is shady? Picture a chef who buys ingredients from a stranger in an alley with no label, no receipt, paying in an unmarked envelope. Even if the chef is honest, the food is now a gamble.

This query flags agents whose "suppliers" look risky:

- **Not using HTTPS** — the connection is unencrypted, so anyone can listen in or tamper with it.
- **A raw IP address instead of a real domain** — no name, no accountability, often a sign of something hand-rolled or hostile.
- **An external MCP tool server** — a powerful new kind of plugin that can run advanced operations and needs careful vetting.

**In one sentence:** *It finds agents connected to sketchy outside services — unencrypted links, anonymous IP addresses, and external tool servers that could feed them poison or steal their data.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.
> - Parses `AgentActionTriggers` for `serverUrls` (matches Microsoft's published sample structure for MCP/HTTP triggers).

## KQL Query

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where isnotempty(AgentActionTriggers)
| extend Triggers = parse_json(AgentActionTriggers)
| mv-expand Trigger = Triggers
| extend ActionType = tostring(Trigger.type)
| extend ServerUrls = Trigger.serverUrls
| mv-expand Url = ServerUrls
| extend Url = tostring(Url)
| where isnotempty(Url)
| extend Parsed = parse_url(Url)
| extend Scheme = tostring(Parsed["Scheme"]), Host = tostring(Parsed["Host"])
| extend IsRawIp     = Host matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
| extend IsInsecure  = isnotempty(Scheme) and Scheme != "https"
| extend IsExternalMcp = ActionType == "RemoteMCPServer"
| where IsInsecure or IsRawIp or IsExternalMcp
| extend RiskLevel = case(
        IsExternalMcp and (IsInsecure or IsRawIp), "Critical – External MCP over insecure or raw-IP endpoint",
        IsInsecure and IsRawIp,                    "High – Insecure connection to a raw IP",
        IsInsecure,                                "High – Tool endpoint not using HTTPS",
        IsRawIp,                                   "High – Tool endpoint is a raw IP address",
        IsExternalMcp,                             "Medium – External MCP server configured",
        "Low")
| project
    RiskLevel, AIAgentName, AIAgentId, ActionType, Url, Scheme, Host,
    IsExternalMcp, IsInsecure, IsRawIp,
    CreatorAccountUpn, OwnerAccountUpns, RegistrySource
| sort by RiskLevel asc, AIAgentName asc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| `ActionType` | The kind of trigger/tool (e.g., RemoteMCPServer, HTTP) |
| `Url` / `Host` / `Scheme` | The actual endpoint the agent talks to |
| `IsExternalMcp` | Endpoint is an MCP tool server (high-capability plugin surface) |
| `IsInsecure` | Connection isn't HTTPS — exposed to interception/tampering |
| `IsRawIp` | Endpoint is a bare IP, not a named domain |
| `RiskLevel` | Severity from endpoint type × insecurity |

## Risk Tiers
- 🔴 **Critical** — external MCP server reached over an insecure or raw-IP endpoint
- 🟠 **High** — any non-HTTPS or raw-IP tool endpoint
- 🟡 **Medium** — external MCP server (vet it even if HTTPS)

## Response Actions
1. Confirm with the owner whether each external endpoint / MCP server is required.
2. Force **HTTPS** and a named, verifiable domain for every tool endpoint; remove raw-IP targets.
3. For MCP servers: verify the server's identity, review its credential configuration, and apply least privilege. Remove unused ones.
4. Treat any endpoint outside your corporate domains as untrusted until proven otherwise.

## Tuning Notes
- Extend the logic to also scan `AgentToolsDetails` for `ModelContextProtocolMetadata` operations (the alternate place MCP tools surface).
- Add an allowlist of approved corporate domains and invert the `Host` check to flag anything not on it.

## Related Detections
- AI Agent XPIA Exposure Map — agents that read untrusted content
- AI Agent Excessive Tool Surface — agents with too many tools overall
- AI Agent Credential Abuse Detection — secrets embedded in those tool configs
