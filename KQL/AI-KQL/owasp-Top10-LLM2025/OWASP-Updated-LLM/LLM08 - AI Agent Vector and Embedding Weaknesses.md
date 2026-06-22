# AI Agent Vector & Embedding Weaknesses (LLM08) — AgentsInfo

> **Migrated to the `AgentsInfo` table** (replaces the `AIAgentsInfo` version). Logic unchanged; columns mapped per [`../updated-tables.md`](../updated-tables.md). Dynamic-column matching is best-effort — validate against live data.

## Overview
Detects AI agents whose **knowledge stores (RAG sources) are weakly scoped** — broad or anonymous access combined with shared/external knowledge sources and no group-level authorization. When the retrieval layer isn't scoped to the right audience, one user can retrieve embeddings derived from data they should never see, and shared writable sources let poisoned content into the store.

**OWASP LLM Top 10:** LLM08 — Vector & Embedding Weaknesses
**MITRE ATT&CK:** TA0009 — Collection | T1213 — Data from Information Repositories
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

---

## In Plain English

A RAG agent has a "memory library." Two things go wrong: **everyone reads everyone's shelf** (no per-audience boundaries, so a regular user gets content from the executive shelf), and **anyone can plant a book** (shared/writable sources let an attacker drop in poisoned content the agent then quotes as fact). This query flags agents whose knowledge library is open to a broad audience with no group-level boundaries.

**In one sentence:** *It finds agents whose knowledge library has no proper walls — so people can pull data they shouldn't, or slip in poisoned content.*

---

## Prerequisites
> - `AgentsInfo` populated by Microsoft Agent 365.

## KQL Query

```kql
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus != "Deleted"
| where isnotempty(DeclaredDataSources)
| extend KnowledgeStr = tolower(tostring(DeclaredDataSources))
| extend ApproxSourceCount = array_length(todynamic(DeclaredDataSources))
| extend HasExternalOrShared =
        KnowledgeStr has_any (dynamic(["http", "www.", "public", "external", "shared", "anyone", "everyone"]))
| extend AuthStr  = tolower(tostring(ToolsAuthenticationType)),
         AvailStr = tolower(tostring(Availability))
| extend BroadAccess =
        AuthStr has "none" or AuthStr has "anonymous"
        or AvailStr has_any (dynamic(["all", "everyone", "tenant", "organization", "any"]))
| extend NoGroupScoping =
        isempty(tostring(SharedWith)) or tostring(SharedWith) in ("[]", "{}")
| where BroadAccess and (HasExternalOrShared or NoGroupScoping)
| extend RiskLevel = case(
        HasExternalOrShared and BroadAccess and NoGroupScoping, "Critical – Shared knowledge, broad access, no group scoping",
        HasExternalOrShared and BroadAccess,                    "High – External/shared knowledge reachable by broad audience",
        BroadAccess and NoGroupScoping,                         "High – Knowledge store with no group-level scoping",
        "Medium – Knowledge access weakly scoped")
| project
    RiskLevel, AgentName, AgentId, ApproxSourceCount, HasExternalOrShared,
    Availability, ToolsAuthenticationType, SharedWith, Owners, Platform
| sort by RiskLevel asc, ApproxSourceCount desc
```

## Risk Tiers
- 🔴 **Critical** — shared/external knowledge + broad access + no group scoping
- 🟠 **High** — external/shared knowledge with broad access, or no group-level scoping
- 🟡 **Medium** — weakly scoped knowledge access

## Response Actions
1. Scope knowledge sources to the specific security groups that should see them (`SharedWith`).
2. Make knowledge sources read-only and restrict contributors (prevents poisoning).
3. Separate sensitive sources into dedicated agents with tight access control.

## Migration Notes (vs AIAgentsInfo version)
- `KnowledgeDetails` → `DeclaredDataSources`; `AuthorizedSecurityGroupIds` → `SharedWith`; `AccessControlPolicy` → `Availability`.
- `ApproxSourceCount` assumes `DeclaredDataSources` is an array; adjust if it's a nested object.
