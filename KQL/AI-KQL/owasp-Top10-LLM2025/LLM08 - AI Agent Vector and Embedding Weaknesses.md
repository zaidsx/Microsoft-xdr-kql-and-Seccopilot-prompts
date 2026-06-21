# AI Agent Vector & Embedding Weaknesses (LLM08)

## Overview
Detects AI agents whose **knowledge stores (RAG sources) are weakly scoped** — broad or anonymous agent access combined with shared/external knowledge sources and no group-level authorization. When the agent's retrieval layer isn't scoped to the right audience, one user can retrieve embeddings derived from data they should never see, and shared writable sources let poisoned content into the vector store. This is the access-control side of vector and embedding weaknesses.

**OWASP LLM Top 10:** LLM08 — Vector & Embedding Weaknesses
**MITRE ATT&CK:** TA0009 — Collection | T1213 — Data from Information Repositories
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

A RAG agent has a "memory library" — documents it searches to answer questions. Two things can go wrong with that library:

1. **Everyone reads everyone's shelf.** If the library isn't divided by who's allowed to see what, a regular employee can ask the agent something and get back content pulled from the executives' shelf. The agent leaks across users because the *library* never enforced boundaries.
2. **Anyone can plant a book.** If the source feeding the library is shared or writable by many, an attacker can drop a poisoned "book" in, and the agent will start quoting it as fact.

This query flags agents whose knowledge library is **open to a broad audience with no group-level boundaries** — the setups where cross-user leakage and poisoning are easiest.

**In one sentence:** *It finds agents whose knowledge library has no proper walls — so people can pull data they shouldn't, or slip in poisoned content.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.

## KQL Query

```kql
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| where isnotempty(KnowledgeDetails)
| extend KnowledgeStr = tolower(tostring(KnowledgeDetails))
| extend ApproxSourceCount = array_length(todynamic(KnowledgeDetails))
| extend HasExternalOrShared =
        KnowledgeStr has_any (dynamic(["http", "www.", "public", "external", "shared", "anyone", "everyone"]))
| extend BroadAccess =
        AccessControlPolicy in ("Any", "Any (multitenant)", "Copilot readers")
        or UserAuthenticationType == "None"
| extend NoGroupScoping =
        isempty(tostring(AuthorizedSecurityGroupIds)) or tostring(AuthorizedSecurityGroupIds) == "[]"
| where BroadAccess and (HasExternalOrShared or NoGroupScoping)
| extend RiskLevel = case(
        HasExternalOrShared and BroadAccess and NoGroupScoping, "Critical – Shared knowledge, broad access, no group scoping",
        HasExternalOrShared and BroadAccess,                    "High – External/shared knowledge reachable by broad audience",
        BroadAccess and NoGroupScoping,                         "High – Knowledge store with no group-level scoping",
        "Medium – Knowledge access weakly scoped")
| project
    RiskLevel, AIAgentName, AIAgentId, ApproxSourceCount, HasExternalOrShared,
    AccessControlPolicy, UserAuthenticationType, AuthorizedSecurityGroupIds,
    OwnerAccountUpns, RegistrySource
| sort by RiskLevel asc, ApproxSourceCount desc
```

## Risk Tiers
- 🔴 **Critical** — shared/external knowledge + broad access + no group scoping
- 🟠 **High** — external/shared knowledge with broad access, or no group-level scoping
- 🟡 **Medium** — weakly scoped knowledge access

## Response Actions
1. Scope the agent's knowledge sources to the specific security groups that should see them (`AuthorizedSecurityGroupIds`).
2. Make knowledge sources read-only and restrict who can contribute to them (prevents poisoning).
3. Separate sensitive sources into dedicated agents with tight access control.

## Tuning Notes
- `ApproxSourceCount` uses `array_length` on `KnowledgeDetails`; if your tenant stores it as a nested object rather than an array, adjust the path.

## Related Detections
- AI Agent Knowledge & Model Drift — when a poisoned source is added
- AI Agent Sensitive Information Disclosure — sensitive sources behind weak access
