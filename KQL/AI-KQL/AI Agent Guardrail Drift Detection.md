# AI Agent Guardrail Removal / Drift Detection

## Overview
Detects when an AI agent's **protective configuration is weakened over time** — its system prompt removed, authentication turned off, access widened to anyone, or a previously blocked agent re-enabled. Each of these strips away a guardrail that was protecting the agent. Whether it's sloppy configuration or deliberate tampering, the result is the same: an agent that is more exposed and less governed than it was before.

Because `AIAgentsInfo` keeps timestamped snapshots of every agent, this detection compares each agent's **past state against its current state** and flags any protection that got *weaker*.

**MITRE ATT&CK:** TA0005 — Defense Evasion | T1562 — Impair Defenses
**OWASP LLM Top 10:** LLM06 — Excessive Agency
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

An AI agent has **safety settings** — like the locks and alarm on a house:

- A **system prompt** — the rules telling it how to behave
- A **login requirement** — you must prove who you are to use it
- **Access limits** — only certain people can talk to it
- A **block switch** — an admin can shut it off

This detection watches for someone **quietly removing those safety settings** — like noticing the front-door lock was taken off and the alarm unplugged. Even if nothing has been stolen *yet*, somebody just made the agent easy to abuse.

**How it works in four steps:**

1. **Take a "before" photo** — how each agent was configured a while ago (30 to 7 days back).
2. **Take an "after" photo** — how each agent is configured now (last 7 days).
3. **Compare the two** — did the rules disappear? Did the login get turned off? Did access open up to anyone? Did a blocked agent get switched back on?
4. **Flag anything that got weaker** — if a setting got *stronger* or stayed the same, it's ignored. Only protections being **taken away** are reported.

**The single most useful field** is `LastModifiedByUpn` — **who made the change.** That one name tells you whether this was the owner doing normal maintenance, or an account that shouldn't be touching the agent at all.

**In one sentence:** *It catches someone quietly stripping the safety settings off an AI agent — and tells you who did it.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.
> - Relies on the table retaining multiple snapshots per agent over time (the default behavior). Best run on a **recurring schedule** (see Production Note).

## KQL Query

```kql
// ── Compare each agent's protective config: past state vs current state ──
let Lookback = 30d;     // how far back the "before" snapshot can come from
let RecentWindow = 7d;  // what counts as the "current" state
// Older ("before") snapshot per agent
let Baseline =
    AIAgentsInfo
    | where Timestamp between (ago(Lookback) .. ago(RecentWindow))
    | summarize arg_max(Timestamp, *) by AIAgentId
    | project AIAgentId,
              OldInstructions = Instructions,
              OldAuth         = UserAuthenticationType,
              OldAccess       = AccessControlPolicy,
              OldBlocked      = IsBlocked,
              OldTime         = Timestamp;
// Current ("after") snapshot per agent
let Current =
    AIAgentsInfo
    | where Timestamp > ago(RecentWindow)
    | summarize arg_max(Timestamp, *) by AIAgentId
    | project AIAgentId, AIAgentName, AgentStatus, OwnerAccountUpns, LastModifiedByUpn,
              NewInstructions = Instructions,
              NewAuth         = UserAuthenticationType,
              NewAccess       = AccessControlPolicy,
              NewBlocked      = IsBlocked,
              NewTime         = Timestamp;
Baseline
| join kind=inner Current on AIAgentId
// Flag each kind of protection being weakened
| extend
    InstructionsRemoved = isnotempty(OldInstructions)
                          and (isempty(NewInstructions) or NewInstructions == "N/A"),
    AuthRemoved         = OldAuth != "None" and NewAuth == "None",
    AccessWidened       = NewAccess == "Any" and OldAccess != "Any",
    Unblocked           = OldBlocked == true and NewBlocked == false
| where InstructionsRemoved or AuthRemoved or AccessWidened or Unblocked
| extend DriftSummary = trim(", ", strcat(
        iff(InstructionsRemoved, "Instructions removed, ", ""),
        iff(AuthRemoved,         "Authentication removed, ", ""),
        iff(AccessWidened,       "Access widened to Any, ", ""),
        iff(Unblocked,           "Agent unblocked, ", "")))
| extend RiskLevel = case(
        AuthRemoved and InstructionsRemoved, "Critical – Auth and prompt guardrails both stripped",
        AuthRemoved or AccessWidened,        "High – Exposure widened to broader/anonymous access",
        InstructionsRemoved,                 "High – System prompt guardrails removed",
        Unblocked,                           "Medium – Previously blocked agent re-enabled",
        "Low")
| project
    RiskLevel, DriftSummary, AIAgentName, AIAgentId, AgentStatus,
    OwnerAccountUpns, LastModifiedByUpn,
    OldAuth, NewAuth, OldAccess, NewAccess, OldBlocked, NewBlocked,
    OldTime, NewTime
| sort by RiskLevel asc, NewTime desc
```

## What Each Drift Type Means
| Drift | Before → After | Why it's dangerous |
|-------|----------------|---------------------|
| **Instructions removed** | Had a system prompt → empty | No behavioral boundaries = wide open to prompt injection |
| **Authentication removed** | Microsoft/Custom → None | Agent becomes anonymously usable |
| **Access widened** | Group/Readers → Any | Anyone in (or outside) the org can drive it |
| **Unblocked** | Blocked → not blocked | An agent an admin deliberately disabled is alive again |

## Risk Tiers
- 🔴 **Critical** — auth *and* system prompt both stripped (agent fully exposed and ungoverned)
- 🟠 **High** — auth removed, access widened, or prompt removed
- 🟡 **Medium** — a previously blocked agent was re-enabled

## Columns Explained
| Column | Description |
|--------|-------------|
| `RiskLevel` | Severity based on which protections were weakened |
| `DriftSummary` | Plain-text list of every guardrail that got weaker |
| `LastModifiedByUpn` | **Who** made the change — the lead for your investigation |
| `Old* / New*` | The before/after value of each protective setting |
| `OldTime` → `NewTime` | The window the change happened in |

## Response Actions
1. Look at **who** changed it (`LastModifiedByUpn`) and **what** they removed (`DriftSummary`).
2. Ask that person whether the change was intentional.
3. If it wasn't them, or it was a mistake: restore the protections (re-add the system prompt, re-enable auth, narrow access, re-block) and investigate the account that made the change.

## Production Note
This compares the **earliest snapshot in the window** against the **latest**. If a protection was removed *and re-added* inside the window, it won't fire. For true change-by-change history, run this on a **daily schedule** so each run compares yesterday against today — nothing slips through that way.

## Related Detections
- AI Agent Dormant Reactivation — forgotten agents coming back to life
- Risky AI Agent Service Principals — standing risk posture
- AI Agent Lifecycle Audit – Creation and Permission Grants — how agents obtain access
