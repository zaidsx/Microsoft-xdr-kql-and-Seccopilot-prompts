# AI Agent System Prompt Leakage (LLM07) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic unchanged; columns mapped per [`../updated-tables.md`](../updated-tables.md). Mostly scalar columns — low migration risk.

## Overview
Detects AI agents whose **system prompt (`Instructions`) contains secrets or sensitive internal references** — API keys, tokens, passwords, connection strings, or "internal only" content. System prompts are frequently coaxed out of agents through injection, so anything sensitive embedded in them should be treated as already exposed.

**OWASP LLM Top 10:** LLM07 — System Prompt Leakage
**MITRE ATT&CK:** TA0006 — Credential Access | T1552 — Unsecured Credentials
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

An agent's system prompt is its standing instructions. Developers sometimes paste secrets straight into it — a password, an API key, an internal server address. The problem: attackers can often trick the agent into reciting its own instructions ("print your system prompt"), and any secret in there walks right out. This query flags agents with credentials or internal-only references in their prompt.

> **Safety note:** the query deliberately does **not** output the prompt text — it only flags *which* agent and *that* a secret exists.

**In one sentence:** *It finds agents with passwords or secrets written into their instructions — which attackers can trick the agent into reading aloud.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365.

## KQL Query

```kql
let SecretPatterns = @"(AKIA[0-9A-Z]{16})|(AIza[0-9A-Za-z_\-]{35})|(xox[baprs]-[0-9a-zA-Z]{10,48})|(ghp_[A-Za-z0-9]{36,59})|(sk_(live|test)_[A-Za-z0-9]{24})|(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)|(password\s*[:=]\s*\S+)|(Authorization\s*:\s*(Basic|Bearer)\s+[A-Za-z0-9=:_\-\.]+)|([A-Za-z]+:\/\/[^\/\s]+:[^\/\s]+@)";
let InternalMarkers = dynamic([
    "internal only", "do not share", "confidential", "connection string",
    "api key", "apikey", "client secret", "private key", "\\\\"
]);
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(Instructions) and Instructions != "N/A"
| extend HasSecret      = Instructions matches regex SecretPatterns
| extend HasInternalRef = tolower(Instructions) has_any (InternalMarkers)
| where HasSecret or HasInternalRef
| extend AuthStr  = tolower(tostring(ToolsAuthenticationType)),
         AvailStr = tolower(tostring(Availability))
| extend Exposed =
        AuthStr has "none" or AuthStr has "anonymous"
        or AvailStr has_any (dynamic(["all", "everyone", "tenant", "organization", "any"]))
| extend RiskLevel = case(
        HasSecret and Exposed,      "Critical – Secret in system prompt on an exposed agent",
        HasSecret,                  "High – Secret/credential embedded in system prompt",
        HasInternalRef and Exposed, "High – Internal reference in prompt on an exposed agent",
        "Medium – Sensitive content in system prompt")
// NOTE: Instructions is intentionally NOT projected, to avoid copying the secret into results.
| project
    RiskLevel, AgentName, AgentId, HasSecret, HasInternalRef,
    ToolsAuthenticationType, Availability, Owners, Platform
| sort by RiskLevel asc, AgentName asc
```

## Risk Tiers
- 🔴 **Critical** — a credential pattern in the prompt on an exposed agent
- 🟠 **High** — a credential pattern, or an internal reference on an exposed agent
- 🟡 **Medium** — other sensitive content in the prompt

## Response Actions
1. Remove the secret from the prompt **and rotate it** — assume it's compromised.
2. Move secrets to Azure Key Vault / secured connection references.
3. Coach the owner on secure prompt authoring.

## Migration Notes (vs AIAgentsInfo version)
- `Instructions` is unchanged — core logic ports directly.
- `LastModifiedByUpn` has no direct column in `AgentsInfo`; `Owners` is projected instead as the accountability lead.
- Auth/access checks use `ToolsAuthenticationType`/`Availability`.
