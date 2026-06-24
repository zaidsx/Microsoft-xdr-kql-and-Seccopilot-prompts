# AI Agent System Prompt Leakage (LLM07) — AgentsInfo

> **Verified against the live `AgentsInfo` schema.** Uses the confirmed scalar `Instructions` column; access exposure inferred from `SharedWith`.

## Overview
Detects AI agents whose **system prompt (`Instructions`) contains secrets or sensitive internal references** — keys, tokens, passwords, connection strings, or "internal only" content. Prompts are frequently coaxed out of agents through injection.

**OWASP LLM Top 10:** LLM07 — System Prompt Leakage
**MITRE ATT&CK:** TA0006 — Credential Access | T1552 — Unsecured Credentials
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
Developers sometimes paste secrets into an agent's instructions; attackers can trick the agent into reciting them. This flags agents with credentials or internal-only references in their prompt. (The query never outputs the prompt text — only the flag.)

## KQL Query

```kql
let SecretPatterns = @"(AKIA[0-9A-Z]{16})|(AIza[0-9A-Za-z_\-]{35})|(xox[baprs]-[0-9a-zA-Z]{10,48})|(ghp_[A-Za-z0-9]{36,59})|(sk_(live|test)_[A-Za-z0-9]{24})|(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)|(password\s*[:=]\s*\S+)|(Authorization\s*:\s*(Basic|Bearer)\s+[A-Za-z0-9=:_\-\.]+)|([A-Za-z]+:\/\/[^\/\s]+:[^\/\s]+@)";
let InternalMarkers = dynamic(["internal only","do not share","confidential","connection string","api key","apikey","client secret","private key"]);
let BroadShare = dynamic(["everyone","all","organization","tenant","AllUsers","anyone","public"]);
AgentsInfo
| extend Availability = column_ifexists("Availability", "")
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| where isnotempty(Instructions) and Instructions != "N/A"
| extend HasSecret      = Instructions matches regex SecretPatterns
| extend HasInternalRef = tolower(Instructions) has_any (InternalMarkers)
| where HasSecret or HasInternalRef
| extend Exposed = strcat(tostring(Availability), " ", tostring(SharedWith)) has_any (BroadShare)
| extend RiskLevel = case(
        HasSecret and Exposed,      "Critical – Secret in system prompt on a broadly shared agent",
        HasSecret,                  "High – Secret/credential embedded in system prompt",
        HasInternalRef and Exposed, "High – Internal reference in prompt on a broadly shared agent",
        "Medium – Sensitive content in system prompt")
// NOTE: Instructions intentionally NOT projected, to avoid copying the secret into results.
| project RiskLevel, Name, AgentId, HasSecret, HasInternalRef, SharedWith, Owners, Platform
| sort by RiskLevel asc, Name asc
```

## Risk Tiers
- 🔴 **Critical** — credential pattern in the prompt on a broadly shared agent
- 🟠 **High** — credential pattern, or internal reference on a broadly shared agent
- 🟡 **Medium** — other sensitive content in the prompt

## Response Actions
1. Remove the secret from the prompt **and rotate it**.
2. Move secrets to Azure Key Vault / secured connection references.
3. Resolve `Owners` GUIDs via `IdentityInfo` and coach on secure prompt authoring.

## Notes
- Sample tenant showed real `Instructions` values (e.g., "You are a helpful assistant…"), so this detection runs against live data today.
