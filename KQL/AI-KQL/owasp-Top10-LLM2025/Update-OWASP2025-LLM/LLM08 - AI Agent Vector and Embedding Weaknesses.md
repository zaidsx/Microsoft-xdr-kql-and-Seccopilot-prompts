# AI Agent Vector & Embedding Weaknesses (LLM08) — AgentsInfo

> **Verified against the live `AgentsInfo` schema.** Uses confirmed `DeclaredDataSources` and `SharedWith`; `Availability` wrapped in `column_ifexists()`.

## Overview
Detects AI agents whose **knowledge stores (RAG sources) are weakly scoped** — broadly shared with external/shared sources and no group-level scoping (`SharedWith`). One user can then retrieve embeddings from data they shouldn't see, and shared writable sources allow poisoning.

**OWASP LLM Top 10:** LLM08 — Vector & Embedding Weaknesses
**MITRE ATT&CK:** TA0009 — Collection | T1213 — Data from Information Repositories
**Platform:** Microsoft Defender XDR — Advanced Hunting (`AgentsInfo`)

## In Plain English
A RAG agent's "memory library" goes wrong when everyone reads everyone's shelf (no boundaries) or anyone can plant a book (shared writable sources). This flags agents whose knowledge library is broadly shared with no group scoping.

## KQL Query

```kql
let BroadShare = dynamic(["everyone","all","organization","tenant","AllUsers","anyone","public"]);
AgentsInfo
| extend Availability = column_ifexists("Availability", "")
| summarize arg_max(Timestamp, *) by AgentId
| where LifecycleStatus !in ("Deleted", "Uninstalled")
| where isnotempty(DeclaredDataSources) and tostring(DeclaredDataSources) !in ("[]", "{}", "null")
| extend ApproxSourceCount = array_length(todynamic(DeclaredDataSources))
| extend HasExternalOrShared =
        tostring(DeclaredDataSources) has_any (dynamic(["http","https","www","public","external","shared","anyone","everyone"]))
| extend BroadlyShared = strcat(tostring(Availability), " ", tostring(SharedWith)) has_any (BroadShare)
| extend NoGroupScoping = isempty(SharedWith) or tostring(SharedWith) in ("[]", "{}", "null")
| where BroadlyShared or HasExternalOrShared or NoGroupScoping
| extend RiskLevel = case(
        HasExternalOrShared and BroadlyShared and NoGroupScoping, "Critical – Shared knowledge, broad share, no group scoping",
        HasExternalOrShared and (BroadlyShared or NoGroupScoping), "High – External/shared knowledge weakly scoped",
        BroadlyShared and NoGroupScoping,                          "High – Knowledge store with no group-level scoping",
        "Medium – Knowledge access weakly scoped")
| project RiskLevel, Name, AgentId, ApproxSourceCount, HasExternalOrShared,
          SharedWith, DeclaredDataSources, Owners, Platform
| sort by RiskLevel asc, ApproxSourceCount desc
```

## Risk Tiers
- 🔴 **Critical** — shared/external knowledge + broad share + no group scoping
- 🟠 **High** — external/shared knowledge weakly scoped, or no group scoping
- 🟡 **Medium** — weakly scoped knowledge access

## Response Actions
1. Scope knowledge sources to specific security groups (`SharedWith`).
2. Make knowledge sources read-only; restrict contributors.
3. Separate sensitive sources into tightly-scoped agents.

## Notes
- In the sample tenant `DeclaredDataSources` was often empty, so expect results only where agents declare knowledge sources.
