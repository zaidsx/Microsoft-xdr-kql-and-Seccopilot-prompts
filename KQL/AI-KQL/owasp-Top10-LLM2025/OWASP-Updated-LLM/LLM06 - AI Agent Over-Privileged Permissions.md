# AI Agent Over-Privileged Permissions (Permission-vs-Usage Gap) (LLM06) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` + `OAuthAppInfo` version). This detection gets **simpler**: `AgentsInfo` now carries a first-class `Permissions` column, so the join to `OAuthAppInfo` is no longer required. Permission sub-field paths are best-effort — validate against live data.

## Overview
Detects AI agents granted **high-privilege permissions they don't use**. The `Permissions` column records requested/granted permissions, approval state, and consent. Unused high-privilege grants are pure standing risk — they expand the blast radius if the agent's identity is stolen, with zero operational value.

**OWASP LLM Top 10:** LLM06 — Excessive Agency (excessive permissions)
**MITRE ATT&CK:** TA0004 — Privilege Escalation | T1098 — Account Manipulation
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

Giving someone keys to every room when their job only needs the supply closet adds nothing but risk — if a thief steals the keyring, they own the building. This query lists the **powerful permissions an agent holds but never uses** — the keys to take back before they're stolen.

**In one sentence:** *It finds powerful permissions agents were given but never use — the keys worth taking back before they're stolen.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365, with the `Permissions` column populated.

## KQL Query

```kql
let WriteMarkers = dynamic(["Write", "ReadWrite", "All", "Manage", "FullControl", "Delete"]);
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(Permissions)
| mv-expand Perm = todynamic(Permissions)
| extend
    PermName  = tostring(coalesce(Perm.permissionName, Perm.name, Perm.scope, Perm.value)),
    PermPriv  = tolower(tostring(coalesce(Perm.privilegeLevel, Perm.priv, Perm.risk))),
    PermState = tolower(tostring(coalesce(Perm.approvalState, Perm.consentState, Perm.state, Perm.status))),
    PermUsage = tolower(tostring(coalesce(Perm.usageStatus, Perm.usage, Perm.lastUsed)))
| where isnotempty(PermName)
// Granted/approved but high/medium privilege and not used
| where PermState has_any (dynamic(["granted", "approved", "consented"])) or isempty(PermState)
| where PermPriv has_any (dynamic(["high", "medium"]))
| where PermUsage != "used" and PermUsage !has "used"
| summarize
    UnusedHighPrivCount = countif(PermPriv has "high"),
    UnusedPermCount     = count(),
    UnusedPermissions   = make_set(PermName, 30),
    UnusedWriteScopes   = make_set_if(PermName, PermName has_any (WriteMarkers), 30)
    by AgentId, AgentName, Owners, Availability, Platform
| extend RiskLevel = case(
        UnusedHighPrivCount >= 3,                                       "Critical – Many unused high-privilege grants",
        UnusedHighPrivCount >= 1 and array_length(UnusedWriteScopes) > 0, "High – Unused high-priv write access",
        UnusedHighPrivCount >= 1,                                       "High – Unused high-privilege grant",
        "Medium – Unused medium-privilege grants")
| project
    RiskLevel, AgentName, AgentId, UnusedHighPrivCount, UnusedPermCount,
    UnusedPermissions, UnusedWriteScopes, Availability, Owners, Platform
| sort by RiskLevel asc, UnusedHighPrivCount desc
```

## Risk Tiers
- 🔴 **Critical** — 3+ unused high-privilege permissions
- 🟠 **High** — any unused high-privilege permission, especially write/manage scopes
- 🟡 **Medium** — unused medium-privilege permissions only

## Response Actions
1. Review `UnusedPermissions` with the owner — confirm they're not needed.
2. Revoke unused high-privilege and write scopes; apply least privilege.
3. Re-run periodically — permission creep is continuous.

## Migration Notes (vs AIAgentsInfo version)
- **Simplified:** no longer joins `OAuthAppInfo`; reads the new first-class `Permissions` column directly.
- The sub-fields (`permissionName`, `privilegeLevel`, `usageStatus`, `approvalState`) are best-effort guesses via `coalesce` — the docs describe the column as carrying "requested and granted [permissions], their approval state, and consent enumeration," so these concepts exist; confirm exact names against live data.
- If `Permissions` doesn't carry a usage signal in your tenant, fall back to the `OAuthAppInfo`-join approach from the original detection.
