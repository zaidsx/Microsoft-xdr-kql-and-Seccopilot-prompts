# OWASP Top 10 for LLM (2025) — AI Agent KQL Detection Pack

> 12 Microsoft Defender XDR Advanced Hunting use cases, one per OWASP LLM risk, built against the live **`AgentsInfo`** table.

## Use Case List

| # | Use Case | OWASP | MITRE ATT&CK | What it hunts | File |
|---|----------|-------|--------------|---------------|------|
| 1 | **XPIA Exposure Map** (Indirect Prompt Injection) | LLM01 — Prompt Injection | TA0001 Initial Access · T1566 Phishing | Agents that **read untrusted content AND can act** — the precondition for indirect injection | [open](LLM01%20-%20AI%20Agent%20XPIA%20Exposure%20Map.md) |
| 2 | **Sensitive Information Disclosure** | LLM02 — Sensitive Info Disclosure | TA0009 Collection · T1213 Data from Repositories | Sensitive-data agents (HR/finance/PII) **shared too broadly** | [open](LLM02%20-%20AI%20Agent%20Sensitive%20Information%20Disclosure.md) |
| 3 | **Untrusted Tool Supply Chain** (MCP & external endpoints) | LLM03 — Supply Chain | TA0011 C2 · T1071 App Layer Protocol | MCP/endpoints over **non-HTTPS, raw-IP, or external** links | [open](LLM03%20-%20AI%20Agent%20Untrusted%20Tool%20Supply%20Chain.md) |
| 4 | **Knowledge & Model Drift** (Data/Model Poisoning) | LLM04 — Data & Model Poisoning | TA0042 Resource Dev · T1584 Compromise Infra | First-vs-last snapshot diff: **new external knowledge or model swap** | [open](LLM04%20-%20AI%20Agent%20Knowledge%20and%20Model%20Drift.md) |
| 5 | **Improper Output Handling** | LLM05 — Improper Output Handling | TA0010 Exfiltration · T1567 Exfil over Web | Autonomous agents **holding outbound send/HTTP actions** | [open](LLM05%20-%20AI%20Agent%20Improper%20Output%20Handling.md) |
| 6 | **Autonomy Trifecta** (Excessive Autonomy) | LLM06 — Excessive Agency | TA0002 Execution · T1648 Automated Execution | Autonomous + destructive tools + **no guardrails** | [open](LLM06%20-%20AI%20Agent%20Autonomy%20Trifecta.md) |
| 7 | **Excessive Tool Surface** (Excessive Functionality) | LLM06 — Excessive Agency | TA0040 Impact · T1565 Data Manipulation | Agents with **too many / too many high-impact tools** | [open](LLM06%20-%20AI%20Agent%20Excessive%20Tool%20Surface.md) |
| 8 | **Over-Privileged Permissions** | LLM06 — Excessive Agency | TA0004 Priv Esc · T1098 Account Manipulation | Agents holding **write/admin scopes** | [open](LLM06%20-%20AI%20Agent%20Over-Privileged%20Permissions.md) |
| 9 | **System Prompt Leakage** | LLM07 — System Prompt Leakage | TA0006 Credential Access · T1552 Unsecured Creds | **Secrets/credentials** in `Instructions` (flags only, never prints prompt) | [open](LLM07%20-%20AI%20Agent%20System%20Prompt%20Leakage.md) |
| 10 | **Vector & Embedding Weaknesses** | LLM08 — Vector & Embedding | TA0009 Collection · T1213 Data from Repositories | RAG knowledge stores **weakly scoped / no group scoping** | [open](LLM08%20-%20AI%20Agent%20Vector%20and%20Embedding%20Weaknesses.md) |
| 11 | **Misinformation Risk** | LLM09 — Misinformation | — | Generative agents with **no grounding source** | [open](LLM09%20-%20AI%20Agent%20Misinformation%20Risk.md) |
| 12 | **Unbounded Consumption** | LLM10 — Unbounded Consumption | TA0040 Impact · T1496 Resource Hijacking | SPN sign-in **volume spikes** vs each agent's own baseline | [open](LLM10%20-%20AI%20Agent%20Unbounded%20Consumption.md) |

## Notes

- **Three LLM06 use cases** (rows 6–8) intentionally — OWASP LLM06 *Excessive Agency* has three facets: excessive **autonomy**, excessive **functionality**, and excessive **permissions**.
- **Data sources:** all built on `AgentsInfo`; LLM10 also joins (via semi-join) `EntraIdSpnSignInEvents` (needs Entra ID P2).
- **Schema resilience:** tenant-optional columns (`Availability`, `Guardrails`, `Permissions`, `Endpoints`, `ToolsAuthenticationType`) are wrapped in `column_ifexists()` so queries never error across tenants.

## Coverage

| OWASP Risk | Covered |
|------------|---------|
| LLM01 Prompt Injection | ✅ |
| LLM02 Sensitive Info Disclosure | ✅ |
| LLM03 Supply Chain | ✅ |
| LLM04 Data & Model Poisoning | ✅ |
| LLM05 Improper Output Handling | ✅ |
| LLM06 Excessive Agency | ✅ (×3 facets) |
| LLM07 System Prompt Leakage | ✅ |
| LLM08 Vector & Embedding Weaknesses | ✅ |
| LLM09 Misinformation | ✅ |
| LLM10 Unbounded Consumption | ✅ |
