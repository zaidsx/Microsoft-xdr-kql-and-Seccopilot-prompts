# AI Agent Sensitive Information Disclosure (LLM02) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic unchanged; columns mapped per [`../updated-tables.md`](../updated-tables.md). Dynamic-column matching is best-effort — validate against live data.

## Overview
Detects AI agents that draw on **sensitive data sources** (HR, finance, legal, executive, PII) while being **broadly or anonymously accessible**. A sensitive-data agent with weak access control lets anyone who can reach it coax that data out — direct information disclosure without touching the underlying system.

**OWASP LLM Top 10:** LLM02 — Sensitive Information Disclosure
**MITRE ATT&CK:** TA0009 — Collection | T1213 — Data from Information Repositories
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

A filing cabinet full of payroll records with a sign saying "open to everyone" — the lock isn't broken, there just never was one. An AI agent connected to sensitive data is that cabinet: if it's wired to HR or financial records **and** anyone can talk to it without authenticating, anyone can simply *ask* for that data. This query finds agents that combine **sensitive sources** with **wide-open access**.

**In one sentence:** *It finds agents holding sensitive data that almost anyone is allowed to talk to.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365.
> - Tune `SensitiveMarkers` to your organization's data classifications and source names.

## KQL Query

```kql
let SensitiveMarkers = dynamic([
    "hr", "payroll", "salary", "finance", "financial", "confidential",
    "ssn", "passport", "secret", "credential", "executive", "board",
    "legal", "medical", "patient", "gdpr", "pii", "customer", "contract"
]);
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| extend
    KnowledgeStr = tolower(tostring(DeclaredDataSources)),
    ContextStr   = tolower(strcat(AgentName, " ", AgentDescription)),
    AuthStr      = tolower(tostring(ToolsAuthenticationType)),
    AvailStr     = tolower(tostring(Availability))
| extend TouchesSensitive =
        KnowledgeStr has_any (SensitiveMarkers) or ContextStr has_any (SensitiveMarkers)
| extend Exposed =
        AuthStr has "none" or AuthStr has "anonymous"
        or AvailStr has_any (dynamic(["all", "everyone", "tenant", "organization", "any", "public"]))
| where TouchesSensitive and Exposed
| extend RiskLevel = case(
        AvailStr has_any (dynamic(["multitenant", "external"])), "Critical – Sensitive-data agent reachable cross-tenant",
        AuthStr has "none" or AuthStr has "anonymous",            "Critical – Sensitive-data agent with no authentication",
        "High – Sensitive-data agent broadly accessible")
| project
    RiskLevel, AgentName, AgentId, DeclaredDataSources,
    ToolsAuthenticationType, Availability, SharedWith,
    Owners, AgentDescription, Platform
| sort by RiskLevel asc, AgentName asc
```

## Risk Tiers
- 🔴 **Critical** — sensitive-data agent reachable cross-tenant or with no authentication
- 🟠 **High** — sensitive-data agent open to a broad audience

## Response Actions
1. Confirm the agent genuinely needs the sensitive sources in `DeclaredDataSources`.
2. Require authentication and scope `Availability` / `SharedWith` to a specific group.
3. Add a system prompt that forbids disclosing raw records.

## Migration Notes (vs AIAgentsInfo version)
- `KnowledgeDetails` → `DeclaredDataSources`.
- `UserAuthenticationType`/`AccessControlPolicy` → `ToolsAuthenticationType`/`Availability` + `SharedWith`.
- "Any (multitenant)" concept now inferred from `Availability` containing `multitenant`/`external`.
