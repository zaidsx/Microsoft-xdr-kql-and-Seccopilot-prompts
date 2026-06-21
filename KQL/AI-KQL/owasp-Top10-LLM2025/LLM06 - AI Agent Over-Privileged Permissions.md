# AI Agent Over-Privileged Permissions (Permission-vs-Usage Gap)

## Overview
Detects AI agents that have been **granted high-privilege permissions they never actually use**. Defender for Cloud Apps app governance tracks a `UsageStatus` for every permission an app holds — so we can find the gap between what an agent *can* do and what it *does* do. Unused high-privilege scopes are pure standing risk: they expand the blast radius if the agent's identity is ever stolen, while delivering zero operational value. This is the *excessive permissions* facet of excessive agency.

**OWASP LLM Top 10:** LLM06 — Excessive Agency (excessive permissions)
**MITRE ATT&CK:** TA0004 — Privilege Escalation | T1098 — Account Manipulation
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

Imagine giving an employee keys to **every room in the building** — the server room, the vault, the CEO's office — when their job only ever needs the supply closet. They've never opened those other doors. So why do they have the keys?

If a thief ever steals that keyring, they now own the whole building. The unused keys added nothing but risk.

This query does exactly that audit for AI agents: it lists the **powerful permissions an agent was given but has never used**. Those are the keys to take away — they only help an attacker, never the agent.

**In one sentence:** *It finds powerful permissions that agents were given but never use — the keys worth taking back before they're stolen.*

---

## Prerequisites
> - `OAuthAppInfo` requires **app governance** turned on in Defender for Cloud Apps.
> - `AIAgentsInfo` is used to scope the results to agent identities only.
> - Join key: `OAuthAppInfo.ServicePrincipalId` ↔ `AIAgentsInfo.EntraObjectId` (cast guid → string).
> - **`UsageStatus` values vary** by tenant (commonly `Used` / `Unused`). Confirm yours and adjust the filter.

## KQL Query

```kql
// Agent identities only (cast guid EntraObjectId -> string for the join)
let Agents =
    AIAgentsInfo
    | summarize arg_max(Timestamp, *) by AIAgentId
    | where AgentStatus != "Deleted"
    | extend EntraObjectId = tostring(EntraObjectId)
    | where isnotempty(EntraObjectId)
    | distinct EntraObjectId, AIAgentName, OwnerAccountUpns;
OAuthAppInfo
| summarize arg_max(Timestamp, *) by OAuthAppId
| where AppStatus == "Enabled"
| join kind=inner Agents on $left.ServicePrincipalId == $right.EntraObjectId
| mv-expand Perm = Permissions
| extend
    PermName  = tostring(Perm.PermissionName),
    PermPriv  = tostring(Perm.PrivilegeLevel),
    PermType  = tostring(Perm.PermissionType),
    PermUsage = tostring(Perm.UsageStatus)
// Keep only sensitive grants that are NOT being used
| where PermPriv in ("High", "Medium")
| where PermUsage != "Used"          // adjust to your tenant's enum (e.g., == "Unused")
| summarize
    UnusedHighPrivCount = countif(PermPriv == "High"),
    UnusedPermCount     = count(),
    UnusedPermissions   = make_set(PermName, 30),
    HasWriteScope       = make_set_if(PermName, PermName has_any ("Write", "ReadWrite", "All", "Manage"), 30)
    by AIAgentName, OAuthAppId, ServicePrincipalId, AppName, OwnerAccountUpns,
       PrivilegeLevel, IsAdminConsented, AppOrigin
| extend RiskLevel = case(
        UnusedHighPrivCount >= 3,                              "Critical – Many unused high-privilege grants",
        UnusedHighPrivCount >= 1 and array_length(HasWriteScope) > 0, "High – Unused high-priv write access",
        UnusedHighPrivCount >= 1,                             "High – Unused high-privilege grant",
        "Medium – Unused medium-privilege grants")
| project
    RiskLevel, AIAgentName, AppName, UnusedHighPrivCount, UnusedPermCount,
    UnusedPermissions, HasWriteScope, PrivilegeLevel, IsAdminConsented,
    AppOrigin, OwnerAccountUpns, ServicePrincipalId, OAuthAppId
| sort by RiskLevel asc, UnusedHighPrivCount desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| `UnusedHighPrivCount` | How many **high**-privilege permissions are granted but never used |
| `UnusedPermissions` | The actual permission names to consider revoking |
| `HasWriteScope` | Unused permissions that allow writing/managing (the most dangerous to leave standing) |
| `IsAdminConsented` | Whether an admin granted these org-wide (broader exposure) |
| `AppOrigin` | Internal vs external-tenant app |
| `RiskLevel` | Severity from count and write-capability of unused grants |

## Risk Tiers
- 🔴 **Critical** — 3+ unused high-privilege permissions
- 🟠 **High** — any unused high-privilege permission, especially write/manage scopes
- 🟡 **Medium** — unused medium-privilege permissions only

## Response Actions
1. Review `UnusedPermissions` with the agent owner — confirm they're genuinely not needed.
2. **Revoke** unused high-privilege and write scopes; apply least privilege.
3. Re-run periodically — permission creep is continuous, so this is a recurring hygiene control.

## Tuning Notes
- Confirm your tenant's `UsageStatus` enum. If it uses `Unused`, change the filter to `PermUsage == "Unused"` for precision.
- To catch *recently granted but unused* (active over-provisioning) rather than legacy creep, join to `AIAgentsInfo.AgentCreationTime` and weight new agents higher.

## Related Detections
- AI Agent Autonomy Trifecta — the autonomy facet of excessive agency
- AI Agent Excessive Tool Surface — the functionality facet of excessive agency
- AI Agent Lifecycle Audit – Creation and Permission Grants — when/how permissions were granted
