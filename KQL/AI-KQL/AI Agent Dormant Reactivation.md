# AI Agent Dormant Reactivation

## Overview
Detects AI agents that sat **dormant** for an extended period and then **suddenly resumed signing in**. Stale, forgotten agents are some of the most dangerous attack surface in a tenant — they still hold valid credentials and granted permissions, but nobody is watching them. An attacker who discovers and reactivates one (via a leaked secret, an orphaned blueprint, or a compromised owner) inherits all of its access while flying under the radar of "new agent" detections.

This mirrors the classic *dormant account wakes up* signal, applied to agent identities. It joins agent inventory (`AIAgentsInfo`) to service-principal sign-in activity (`EntraIdSpnSignInEvents`) and flags any agent whose silence gap exceeds the dormancy threshold.

**MITRE ATT&CK:** TA0003 — Persistence | T1078.004 — Valid Accounts: Cloud Accounts
**OWASP LLM Top 10:** LLM06 — Excessive Agency / Identity Abuse
**Platform:** Microsoft Defender XDR — Advanced Hunting

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.
> - `EntraIdSpnSignInEvents` requires **Microsoft Entra ID P2**. (If your tenant still exposes the older `AADSpnSignInEventsBeta`, the columns are identical — just swap the table name.)
> - Join key: `AIAgentsInfo.EntraObjectId` ↔ `EntraIdSpnSignInEvents.ServicePrincipalId` — the agent's enterprise application (service principal) object in Entra.

## KQL Query

```kql
// ── Tunable windows ────────────────────────────────────────────────
let TotalLookback     = 90d;   // how far back we measure history
let RecentWindow      = 7d;    // what counts as "now" / reactivation
let DormancyThreshold = 30d;   // min silent gap to call an agent "dormant"
// ───────────────────────────────────────────────────────────────────
// Sensitive resources — a dormant agent reaching these should escalate
let SensitiveResources = dynamic([
    "Microsoft Graph", "Office 365 Exchange Online", "Office 365 SharePoint Online",
    "Microsoft Graph PowerShell", "Azure Key Vault", "Microsoft Azure Management",
    "Windows Azure Active Directory", "Microsoft Information Protection"
]);
// Latest config snapshot per agent (exclude deleted)
let Agents =
    AIAgentsInfo
    | summarize arg_max(Timestamp, *) by AIAgentId
    | where AgentStatus != "Deleted"
    | extend EntraObjectId = tostring(EntraObjectId)   // cast guid -> string for the join
    | where isnotempty(EntraObjectId)
    | project AIAgentId, AIAgentName, EntraObjectId, EntraBlueprintId,
              AIModel, OwnerAccountUpns, AgentStatus, AgentCreationTime, LastModifiedTime;
EntraIdSpnSignInEvents
| where Timestamp > ago(TotalLookback)
| where isnotempty(ServicePrincipalId)
| join kind=inner Agents on $left.ServicePrincipalId == $right.EntraObjectId
| extend Period = iff(Timestamp >= ago(RecentWindow), "Recent", "Historical")
| summarize
    RecentFirst       = minif(Timestamp, Period == "Recent"),
    RecentLast        = maxif(Timestamp, Period == "Recent"),
    RecentSignIns     = countif(Period == "Recent"),
    FailedRecent      = countif(Period == "Recent" and ErrorCode != 0),
    HistoricalLast    = maxif(Timestamp, Period == "Historical"),
    HistoricalSignIns = countif(Period == "Historical"),
    RecentResources   = make_set_if(ResourceDisplayName, Period == "Recent", 15),
    RecentIPs         = make_set_if(IPAddress, Period == "Recent", 10),
    RecentCountries   = make_set_if(Country,  Period == "Recent", 10)
    by AIAgentId, AIAgentName, EntraObjectId, AIModel, OwnerAccountUpns,
       AgentCreationTime, LastModifiedTime
| where RecentSignIns > 0                                  // must be active now
// Dormancy gap: silence between last historical sign-in and first recent sign-in.
// If there was no historical sign-in at all, fall back to time since last config change.
| extend DormancyGapDays = iff(
        isnotempty(HistoricalLast),
        datetime_diff('day', RecentFirst, HistoricalLast),
        datetime_diff('day', RecentFirst, LastModifiedTime))
| where DormancyGapDays >= toint(DormancyThreshold / 1d)
| extend SensitiveHit = tostring(RecentResources) has_any (SensitiveResources)
| extend RiskLevel = case(
        DormancyGapDays >= 60 and SensitiveHit, "Critical – Long-dormant agent now reaching sensitive resources",
        DormancyGapDays >= 60,                  "High – Agent reawakened after 60+ days",
        SensitiveHit,                           "High – Dormant agent now reaching sensitive resources",
        DormancyGapDays >= 30,                  "Medium – Agent reawakened after dormancy",
        "Low")
| project
    RiskLevel, AIAgentName, AIAgentId, EntraObjectId, AIModel, OwnerAccountUpns,
    DormancyGapDays, HistoricalLast, RecentFirst, RecentSignIns, FailedRecent,
    SensitiveHit, RecentResources, RecentCountries, RecentIPs,
    AgentCreationTime, LastModifiedTime
| sort by RiskLevel asc, DormancyGapDays desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| `AIAgentName` / `AIAgentId` | The reactivated AI agent identity |
| `EntraObjectId` | Agent's enterprise app (SPN) object — the join key to sign-in activity |
| `DormancyGapDays` | Days of silence before the agent resumed signing in |
| `HistoricalLast` | Last sign-in seen *before* the recent window (blank = no prior sign-in in lookback) |
| `RecentFirst` / `RecentSignIns` | When the agent woke up, and how many sign-ins since |
| `FailedRecent` | Failed sign-ins (`ErrorCode != 0`) in the recent window — token probing signal |
| `SensitiveHit` | True if any recent sign-in targeted a sensitive resource (Graph, Exchange, SharePoint, Key Vault, ARM) |
| `RecentCountries` / `RecentIPs` | Where the reawakened sign-ins came from |
| `RiskLevel` | Severity from dormancy length × resource sensitivity |

## Tuning Notes
- **New-agent false positives:** an agent created recently with no sign-in history trips the fallback branch. Tighten by adding `| where AgentCreationTime < ago(DormancyThreshold)` to require the agent itself to be old.
- **Scheduled/seasonal agents:** quarterly or monthly batch agents look dormant by design — maintain an allowlist of known periodic `AIAgentId`s.
- **Lengthen `TotalLookback`** to 180d to catch agents dormant longer than 90 days (retention permitting).
- Pair a non-zero `FailedRecent` with a new `RecentCountries` value to surface stolen-token reuse.

## Response Actions
1. Confirm with `OwnerAccountUpns` whether the reactivation was expected.
2. Pull the agent's full recent sign-ins from `EntraIdSpnSignInEvents` filtered on this `EntraObjectId`.
3. Review the agent's permissions/consent (`OAuthAppInfo` or the agent's `AgentToolsDetails`) to scope blast radius.
4. If unexplained: block the agent, rotate/revoke its credentials, and review the blueprint (`EntraBlueprintId`) for other instances spun from the same identity.

## Related Detections
- Risky AI Agent Service Principals — standing risk posture
- AI Agent T1-T2 Token Exchange Anomaly — token-level abuse during the reawakened sessions
- AI Agent Lifecycle Audit – Creation and Permission Grants — how the agent obtained its access
