# AI Agent Sensitive Information Disclosure (LLM02) — AgentsInfo

> **Verified against the live `AgentsInfo` schema** (`Name`, `Description`, etc.). `Availability` is wrapped in `column_ifexists()`; access exposure is inferred from `SharedWith`.

## Overview
Detects AI agents drawing on **sensitive data sources** (HR, finance, legal, executive, PII) that are **broadly shared** — letting anyone who can reach the agent coax that data out of it.

**OWASP LLM Top 10:** LLM02 — Sensitive Information Disclosure
**MITRE ATT&CK:** TA0009 — Collection | T1213 — Data from Information Repositories
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
A filing cabinet of payroll records with an "open to everyone" sign. This finds agents connected to sensitive data that are shared too broadly.

## KQL Query

```kql
// Includes document-name tokens (DeclaredDataSources are filenames like "Expenses_Policy.docx")
let SensitiveMarkers = dynamic(["hr","payroll","salary","finance","financial","confidential","ssn","passport","secret","credential","executive","board","legal","medical","patient","gdpr","pii","customer","contract","expense","expenses","policy","incident","budget","invoice","employee","compensation"]);
let BroadShare = dynamic(["everyone","all","organization","tenant","AllUsers","anyone","public"]);
AgentsInfo
| extend Availability = column_ifexists("Availability", "")
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| extend TouchesSensitive =
        tostring(DeclaredDataSources) has_any (SensitiveMarkers)
        or strcat(Name, " ", Description) has_any (SensitiveMarkers)
| extend BroadlyShared =
        strcat(tostring(Availability), " ", tostring(SharedWith)) has_any (BroadShare)
| where TouchesSensitive and BroadlyShared
| extend RiskLevel = case(
        strcat(tostring(Availability), " ", tostring(SharedWith)) has_any (dynamic(["multitenant","external"])), "Critical – Sensitive-data agent shared cross-tenant",
        "High – Sensitive-data agent broadly shared")
| project
    RiskLevel, Name, AgentId, DeclaredDataSources, SharedWith, Availability,
    Owners, Description, Platform
| sort by RiskLevel asc, Name asc
```

## Risk Tiers
- 🔴 **Critical** — sensitive-data agent shared cross-tenant/externally
- 🟠 **High** — sensitive-data agent shared broadly in the org

## Response Actions
1. Confirm the agent needs the sensitive sources in `DeclaredDataSources`.
2. Scope `SharedWith` to a specific security group.
3. Add a system prompt forbidding disclosure of raw records.
