# OWASP LLM Top 10 (2025) — AI Agent KQL Detection Set

A complete library of Microsoft Defender XDR **Advanced Hunting** (KQL) detections, one mapped to **each category** of the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/). The set is purpose-built for hunting risks in **AI agents** (Microsoft Copilot Studio / Agent 365 / Power Platform) using the agent inventory and identity tables in Defender XDR.

---

## Why this set exists

AI agents are a new class of identity in the enterprise. They hold credentials, are granted permissions, read data, call tools, and take actions — often autonomously. Traditional detections built for users and devices don't see them. The OWASP LLM Top 10 (2025) is the industry-standard catalogue of *what can go wrong* with LLM applications; this set turns each of those risks into a **concrete, runnable hunting query** against data you already have in Defender XDR.

**The goal:** give a SOC analyst or detection engineer a single, ready-to-run pack that answers, for every OWASP LLM risk, *"which of our agents are exposed to this — right now?"*

---

## How the detections map to OWASP LLM Top 10 (2025)

| OWASP | Risk (plain meaning) | Detection file | What it surfaces |
|-------|----------------------|----------------|------------------|
| **LLM01** | Prompt Injection | `LLM01 - AI Agent XPIA Exposure Map` | Agents that **read untrusted content AND can act** — the precondition for indirect prompt injection (XPIA) |
| **LLM02** | Sensitive Information Disclosure | `LLM02 - AI Agent Sensitive Information Disclosure` | Agents wired to **sensitive data** but **broadly/anonymously accessible** |
| **LLM03** | Supply Chain | `LLM03 - AI Agent Untrusted Tool Supply Chain` | Agents calling **untrusted external endpoints / MCP servers** (non-HTTPS, raw IP, external) |
| **LLM04** | Data & Model Poisoning | `LLM04 - AI Agent Knowledge and Model Drift` | Agents whose **knowledge source or AI model changed** over time |
| **LLM05** | Improper Output Handling | `LLM05 - AI Agent Improper Output Handling` | Agents where the **AI decides outbound action inputs** (recipient / URL / payload) |
| **LLM06** | Excessive Agency | `LLM06 - AI Agent Autonomy Trifecta`<br>`LLM06 - AI Agent Over-Privileged Permissions`<br>`LLM06 - AI Agent Excessive Tool Surface` | Too much **autonomy**, too many **permissions**, too much **functionality** |
| **LLM07** | System Prompt Leakage | `LLM07 - AI Agent System Prompt Leakage` | **Secrets / internal refs embedded in the system prompt** |
| **LLM08** | Vector & Embedding Weaknesses | `LLM08 - AI Agent Vector and Embedding Weaknesses` | **Knowledge stores weakly scoped** — cross-user leakage / poisoning risk |
| **LLM09** | Misinformation | `LLM09 - AI Agent Misinformation Risk` | **Ungrounded generative agents** with no source of truth |
| **LLM10** | Unbounded Consumption | `LLM10 - AI Agent Unbounded Consumption` | Agents whose **activity spikes far above baseline** (cost / DoS / abuse) |

> LLM06 (Excessive Agency) carries **three** detections because the risk has three distinct facets — autonomy, permissions, and functionality — and an agent can be excessive in any one of them.

---

## Two kinds of detection in this pack

Understanding the difference tells you how to run each one.

**1. Posture / configuration detections** (most of the set)
They inspect the **current configuration** of each agent from `AIAgentsInfo` and answer "is this agent built in a risky way?" Run them **on demand** or on a **slow schedule** (daily). Findings are *risk debt to remediate*, not always live incidents.
→ LLM01, LLM02, LLM03, LLM05, LLM06, LLM07, LLM08, LLM09

**2. Change / behavior detections**
They compare **over time** — past config vs current, or baseline activity vs recent. Run them on a **recurring schedule** so each run compares the latest interval.
→ LLM04 (config drift), LLM10 (activity spike)

---

## Data sources used

| Table | Used by | Notes |
|-------|---------|-------|
| `AIAgentsInfo` | LLM01–LLM09 | Agent inventory & configuration. **Deprecating July 1 2026 → migrate to `AgentsInfo`.** Filter `RegistrySource` = `A365` or `PowerPlatform` as needed. |
| `EntraIdSpnSignInEvents` | LLM10 | Service-principal sign-ins. **Requires Microsoft Entra ID P2.** |
| `OAuthAppInfo` | LLM06 (Over-Privileged) | OAuth app permissions & consent. **Requires app governance** in Defender for Cloud Apps. |

**Key join:** `AIAgentsInfo.EntraObjectId` ↔ identity/activity tables' `ServicePrincipalId`. `EntraObjectId` is returned as a **guid**, so cast it: `extend EntraObjectId = tostring(EntraObjectId)` before joining to a string key.

---

## How to use these detections

1. **Open** Microsoft Defender portal → **Advanced hunting**.
2. **Paste** a detection's KQL block and run it. Each file's query is self-contained.
3. **Triage** by the `RiskLevel` column (Critical → High → Medium), which every detection produces.
4. **Tune** using the per-file *Tuning Notes* — keyword lists, thresholds, and time windows are environment-specific.
5. **Operationalize** the change/behavior ones (LLM04, LLM10) as **scheduled custom detection rules** so they run continuously.

Each detection file follows the same structure: **Overview → In Plain English → Prerequisites → KQL Query → Risk Tiers → Response Actions → Tuning Notes**.

---

## Important caveats

- **Schema accuracy:** queries are written against the official Microsoft Defender XDR Advanced Hunting schema. Some detections read **dynamic (JSON) columns** (`AgentToolsDetails`, `KnowledgeDetails`, `OAuthAppInfo.Permissions`) whose internal shape isn't fully documented — validate the dynamic fields on a small result set before trusting counts. This is flagged in each affected file's Tuning Notes.
- **Coverage depends on connectors:** if your tenant hasn't onboarded Agent 365 / Copilot Studio / Defender for Cloud Apps, the relevant tables return no rows.
- **Read-only:** KQL only *reads* data. These detections **find** risky agents; remediation (revoking permissions, adding guardrails, blocking agents) is done in the respective admin portals — see each file's Response Actions.
- **Not a substitute for built-in protection:** these complement, not replace, Microsoft's native agent security controls.

---

## At a glance

- **10 OWASP categories** → **12 detection files** (LLM06 ×3)
- **Primary table:** `AIAgentsInfo` (migrate to `AgentsInfo` before July 1 2026)
- **Severity model:** every detection emits a graded `RiskLevel`
- **Format:** Markdown, each with a plain-English explanation for non-specialists
