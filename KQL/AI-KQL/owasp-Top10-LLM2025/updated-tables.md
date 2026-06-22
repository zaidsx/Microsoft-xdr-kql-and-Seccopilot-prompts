# Updated Tables — Schema Migration Reference

This file tracks the Microsoft Defender XDR Advanced Hunting **table and column changes** that affect the detections in this folder, and how to migrate them. Source: [Advanced hunting schema — Naming changes](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-changes).

> ⚠️ **Action required by July 1, 2026:** the `AIAgentsInfo` table (used by most detections in this set) is being replaced by `AgentsInfo`. Queries saved **inside** the Defender portal (including custom detection rules) are migrated automatically by Microsoft. Queries saved **here in this repo are not** — they must be updated manually.

---

## Table renames affecting this set

| Old table | New table | Removed on | Used by |
|-----------|-----------|------------|---------|
| `AIAgentsInfo` | [`AgentsInfo`](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-agentsinfo-table) | **July 1, 2026** | LLM01–LLM09 (agent config) |
| `AADSpnSignInEventsBeta` | `EntraIdSpnSignInEvents` | Dec 9, 2025 (already) | LLM10 (sign-in volume) |
| `AADSignInEventsBeta` | `EntraIdSignInEvents` | Dec 9, 2025 (already) | — |

`AgentsInfo` is a **unified** table covering all agent types (Copilot Studio, Microsoft Foundry, Microsoft 365 Copilot, third-party, and endpoint-discovered agents), not just Copilot Studio. Microsoft Agent 365 customers should use it today.

---

## `AgentsInfo` — full schema

| Column | Type | Description |
|--------|------|-------------|
| `Timestamp` | datetime | When the agent info was recorded |
| `AgentId` | string | Unique identifier for the agent |
| `AgentName` | string | Display name |
| `Platform` | string | Platform that provided the info |
| `AgentDescription` | string | Description from the agent's source |
| `Version` | string | Agent version |
| `SourceAgentId` | string | Native identifier from the originating platform |
| `EntraAgentId` | string | Enterprise application object ID in Microsoft Entra |
| `EntraBlueprintId` | string | Entra agent identity blueprint ID (template the identity was created from) |
| `ToolsAuthenticationType` | dynamic | Structured summary of identity, authentication, and authorization model |
| `Permissions` | dynamic | Requested/granted permissions, approval state, consent enumeration |
| `PublishedStatus` | string | `Draft`, `Published` |
| `LifecycleStatus` | string | `Active`, `Blocked`, `Uninstalled`, `Deleted` |
| `Availability` | string | Deployment scope (all users / groups / individuals) |
| `CreatedDateTime` | datetime | When created |
| `LastPublishedDateTime` | datetime | When last published/deployed |
| `LastUpdatedDateTime` | datetime | When metadata last modified |
| `Owners` | dynamic | Primary owners |
| `SharedWith` | dynamic | Users and security groups the agent is shared with |
| `InstanceCount` | int | Instances created from the same Entra blueprint |
| `Instructions` | string | System prompt (behavior, persona, boundaries) |
| `Model` | string | AI model powering the agent |
| `Channels` | dynamic | Surfaces where the agent operates (M365 apps, APIs) |
| `Capabilities` | dynamic | Intents, actions, skills, orchestrations |
| `DeclaredDataSources` | dynamic | Data repositories and knowledge sources |
| `DeclaredTools` | dynamic | Tools the agent can invoke at runtime |
| `McpServers` | dynamic | Connected MCP servers, incl. server URLs and credential config |
| `Skills` | dynamic | Skills attached to the agent |
| `ConnectedAgents` | dynamic | Other agents linked for multi-agent orchestration |
| `Memory` | dynamic | Declarative memory store configuration |
| `Triggers` | dynamic | Agent triggers |
| `Guardrails` | dynamic | Guardrails attached and their coverage |
| `Endpoints` | dynamic | Runtime endpoints (URL, transport type, external connectivity flag) |
| `ObservabilityId` | dynamic | Correlates the agent with usage/activity in Microsoft Agent 365 |
| `RawAgentInfo` | dynamic | Additional agent data in JSON (no-data-loss catch-all) |

---

## Column mapping: `AIAgentsInfo` → `AgentsInfo`

Microsoft does **not** publish a 1:1 mapping; the table below is derived by diffing the two official schemas. Validate against live data before relying on it in production.

| AIAgentsInfo (old) | AgentsInfo (new) | Notes |
|--------------------|------------------|-------|
| `AIAgentId` (guid) | `AgentId` (string) | type change |
| `AIAgentName` | `AgentName` | |
| `AgentCreationTime` | `CreatedDateTime` | |
| `LastModifiedTime` | `LastUpdatedDateTime` | |
| `LastPublishedTime` | `LastPublishedDateTime` | |
| `OwnerAccountUpns` (string) | `Owners` (dynamic) | shape change string → dynamic |
| `AgentDescription` | `AgentDescription` | unchanged |
| `AgentStatus` (Created/Published/Deleted) | `LifecycleStatus` (Active/Blocked/Uninstalled/Deleted) **+** `PublishedStatus` (Draft/Published) | **split into two columns** |
| `IsBlocked` (bool) | `LifecycleStatus == "Blocked"` | |
| `UserAuthenticationType` / `AuthenticationTrigger` | `ToolsAuthenticationType` (dynamic) | now a structured object |
| `AccessControlPolicy` / `AgentUsers` / `AuthorizedSecurityGroupIds` | `Availability` + `SharedWith` (dynamic) | |
| `KnowledgeDetails` | `DeclaredDataSources` (dynamic) | |
| `AgentToolsDetails` | `DeclaredTools` (dynamic) **+** `McpServers` (dynamic) | tools split out; MCP now first-class |
| `AgentTopicsDetails` | `Capabilities` / `Skills` (dynamic) | |
| `AgentActionTriggers` | `Triggers` (dynamic) | |
| `ConnectedAgentsSchemaNames` / `ChildAgentsSchemaNames` | `ConnectedAgents` (dynamic) | |
| `EntraObjectId` | `EntraAgentId` | ~guid; `tostring()` for joins |
| `EntraBlueprintId` | `EntraBlueprintId` | unchanged |
| `AIModel` | `Model` | |
| `AccessCapabilities` / `ElementTypes` | `Capabilities` (dynamic) | |
| `SourceAgentId` | `SourceAgentId` | unchanged |
| `RawAgentInfo` (string) | `RawAgentInfo` (dynamic) | now dynamic |
| `CreatorAccountUpn`, `LastModifiedByUpn`, `LastPublishedByUpn`, `IsGenerativeOrchestrationEnabled`, `EnvironmentId`, `AgentAppId` | *(no clean 1:1)* | check `RawAgentInfo` JSON; orchestration flag likely under `Capabilities` / `RawAgentInfo` |
| — | `Guardrails`, `Endpoints`, `Memory`, `Channels`, `InstanceCount`, `ObservabilityId`, `Permissions` | **NEW** in AgentsInfo |

---

## Migration impact per detection

| Detection | Migration difficulty | Why |
|-----------|---------------------|-----|
| LLM07 System Prompt Leakage | 🟢 Easy | `Instructions` unchanged; status fields are scalar |
| LLM09 Misinformation | 🟢 Easy | mostly scalar (`Instructions`, status, `Model`) |
| LLM10 Unbounded Consumption | 🟢 Easy | already uses `EntraIdSpnSignInEvents`; only the join key changes (`EntraObjectId` → `EntraAgentId`) |
| LLM02 Sensitive Info Disclosure | 🟡 Medium | `KnowledgeDetails` → `DeclaredDataSources`; access fields restructured |
| LLM04 Knowledge & Model Drift | 🟡 Medium | `KnowledgeDetails`/`AIModel` → `DeclaredDataSources`/`Model` |
| LLM01 XPIA Exposure Map | 🟠 Harder | depends on `DeclaredDataSources` + `DeclaredTools` JSON shape |
| LLM03 Untrusted Tool Supply Chain | 🟠 Harder | moves to the new **`McpServers`** + `Endpoints` columns (actually cleaner once shapes known) |
| LLM05 Improper Output Handling | 🟠 Harder | `AgentToolsDetails` → `DeclaredTools` JSON shape |
| LLM06 Excessive Agency (×3) | 🟠 Harder | `DeclaredTools` + `Capabilities`; orchestration flag location TBD |

> 🟢 Easy = scalar columns, migratable now. 🟡 Medium = renamed dynamic columns. 🟠 Harder = needs validation of the new dynamic column JSON shapes (not documented by Microsoft) against live `AgentsInfo` data before rewriting.

---

## How to get the data needed to finish migration

Run this in Advanced Hunting and review the dynamic columns' structure:

```kql
AgentsInfo
| take 5
| project AgentId, AgentName, LifecycleStatus, PublishedStatus,
          DeclaredTools, McpServers, DeclaredDataSources,
          ToolsAuthenticationType, Capabilities, Permissions, Guardrails
```

The shapes of `DeclaredTools`, `McpServers`, `DeclaredDataSources`, and `ToolsAuthenticationType` are what determine the exact `parse_json` / `mv-expand` paths in the migrated queries.

---

*Last reviewed against Microsoft Learn: AgentsInfo and schema-changes pages dated 2026-06-03.*
