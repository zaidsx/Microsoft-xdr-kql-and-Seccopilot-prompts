# AI Agent Sensitive Information Disclosure (LLM02)

## Overview
Detects AI agents that draw on **sensitive data sources** (HR, finance, legal, executive, PII) while being **broadly or anonymously accessible**. When a sensitive-data agent has weak access control, anyone who can reach it can coax that data out of it — a direct path to information disclosure without ever touching the underlying system.

**OWASP LLM Top 10:** LLM02 — Sensitive Information Disclosure
**MITRE ATT&CK:** TA0009 — Collection | T1213 — Data from Information Repositories
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

Imagine a filing cabinet full of payroll records and a sign on it that says "open to everyone." The lock isn't broken — there just never was one.

An AI agent connected to sensitive data is that cabinet. If the agent is wired to HR files or financial records **and** anyone can talk to it without proving who they are, then anyone can simply *ask* the agent for that data and it'll hand it over. No hacking required.

This query finds agents that combine **sensitive sources** with **wide-open access** — the cabinets with no lock.

**In one sentence:** *It finds agents holding sensitive data that almost anyone is allowed to talk to.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.
> - Tune `SensitiveMarkers` to your organization's data classifications and source names.

## KQL Query

```kql
let SensitiveMarkers = dynamic([
    "hr", "payroll", "salary", "finance", "financial", "confidential",
    "ssn", "passport", "secret", "credential", "executive", "board",
    "legal", "medical", "patient", "gdpr", "pii", "customer", "contract"
]);
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| extend
    KnowledgeStr = tolower(tostring(KnowledgeDetails)),
    ContextStr   = tolower(strcat(AIAgentName, " ", AgentDescription))
| extend TouchesSensitive =
        KnowledgeStr has_any (SensitiveMarkers) or ContextStr has_any (SensitiveMarkers)
| extend Exposed =
        UserAuthenticationType == "None"
        or AccessControlPolicy in ("Any", "Any (multitenant)")
| where TouchesSensitive and Exposed
| extend RiskLevel = case(
        AccessControlPolicy == "Any (multitenant)", "Critical – Sensitive-data agent reachable cross-tenant",
        UserAuthenticationType == "None",           "Critical – Sensitive-data agent with no authentication",
        "High – Sensitive-data agent broadly accessible")
| project
    RiskLevel, AIAgentName, AIAgentId, KnowledgeDetails,
    UserAuthenticationType, AccessControlPolicy,
    OwnerAccountUpns, AgentDescription, RegistrySource
| sort by RiskLevel asc, AIAgentName asc
```

## Risk Tiers
- 🔴 **Critical** — sensitive-data agent reachable cross-tenant or with no authentication
- 🟠 **High** — sensitive-data agent open to "Any" in the org

## Response Actions
1. Confirm the agent genuinely needs the sensitive sources in `KnowledgeDetails`.
2. Require authentication and scope `AccessControlPolicy` to a specific group.
3. Add a system prompt that forbids disclosing raw records; return only what the task requires.

## Tuning Notes
- `SensitiveMarkers` is keyword-based on knowledge names/descriptions — pair with Microsoft Purview sensitivity labels for precision where available.

## Related Detections
- AI Agent XPIA Exposure Map — how poisoned input could trigger disclosure
- AI Agent Vector & Embedding Weaknesses — knowledge store scoping gaps
