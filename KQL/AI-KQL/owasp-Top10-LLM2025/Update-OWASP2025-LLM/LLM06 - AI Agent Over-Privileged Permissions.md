# AI Agent Over-Privileged Permissions (LLM06) — AgentsInfo

> **Verified against the live `AgentsInfo` schema.** The documented `Permissions` column is **not present** in every tenant, so it's wrapped in `column_ifexists()` and the detection also scans `RawAgentInfo` for permission/scope content. If `Permissions` is absent and `RawAgentInfo` carries no scope data, prefer the original `AIAgentsInfo` + `OAuthAppInfo` version in the parent folder.

## Overview
Detects AI agents holding **high-privilege / write-capable permissions** — the excessive-permissions facet of excessive agency.

**OWASP LLM Top 10:** LLM06 — Excessive Agency (excessive permissions)
**MITRE ATT&CK:** TA0004 — Privilege Escalation | T1098 — Account Manipulation
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
Giving someone keys to every room when their job needs only the supply closet adds nothing but risk. This lists agents holding powerful write/admin permissions.

## KQL Query

```kql
let HighPrivMarkers = dynamic(["ReadWrite","Write",".All","FullControl","Manage","Delete","RoleManagement","Directory.","Application.","Mail.ReadWrite","Files.ReadWrite","Sites.FullControl"]);
AgentsInfo
| extend Permissions = column_ifexists("Permissions", dynamic([]))
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
// Search both Permissions (if present) and RawAgentInfo for high-privilege scope text
| extend PermBlob = strcat(tostring(Permissions), " ", tostring(RawAgentInfo))
| where PermBlob has_any (HighPrivMarkers)
| extend HighPrivHitCount = array_length(extract_all(@"(ReadWrite|FullControl|Manage|\.All|Delete|RoleManagement)", PermBlob))
| extend AdminConsented = PermBlob has_any (dynamic(["admin","allPrincipals","tenant"]))
| extend RiskLevel = case(
        HighPrivHitCount >= 3, "High – Broad high-privilege/write permission set",
        AdminConsented,        "High – Admin-consented high-privilege permission",
        "Medium – High-privilege permission held")
| project RiskLevel, Name, AgentId, HighPrivHitCount, AdminConsented,
          Permissions, SharedWith, Owners, Platform
| sort by RiskLevel asc, HighPrivHitCount desc
```

## Risk Tiers
- 🟠 **High** — broad high-privilege/write set, or admin-consented high-priv
- 🟡 **Medium** — a high-privilege permission held

## Response Actions
1. Review flagged agents' permissions with the owner; remove what isn't needed.
2. Revoke unused high-privilege and write scopes; apply least privilege.

## Notes
- This is content-based over `Permissions` + `RawAgentInfo`, since `Permissions` may be absent in your tenant. Once it's populated with a usage signal, add an "unused" filter for precision.
