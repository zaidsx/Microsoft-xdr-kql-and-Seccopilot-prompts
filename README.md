# Microsoft Defender — KQL & Security Copilot Resources

This repository gives back to the Microsoft Defender community — helping anyone in security gain faster, clearer, and more effective insights using **KQL** and **Security Copilot**.

Everything here was built to solve real-world security challenges and is shared openly so the wider community can benefit. If it helps a SOC team, a detection engineer, or a customer improve their work, it has achieved its purpose. 💙

> ⭐ **Highlight:** this repo includes an open **KQL detection set mapped to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)** — purpose-built for hunting threats against **AI agents** in Microsoft Defender XDR.

---

## 📁 Repository Map

```
.
├── KQL/                                         # Hunting queries — Defender XDR / Sentinel (9 queries)
│   ├── AI-KQL/                                  # AI agent threat detections (8 queries + README)
│   │   └── owasp-Top10-LLM2025/                 # OWASP LLM Top 10 (2025) — 12 detections + README
│   │       ├── updated-tables.md                # AIAgentsInfo → AgentsInfo schema migration notes
│   │       └── Update-OWASP2025-LLM/            # Refreshed AgentsInfo pack — 12 detections + use case index
│   └── *.md                                     # Endpoint health, email/phishing, alert coverage
├── Workbooks/                                   # Sentinel cost optimization workbook + ARM deploy template
├── Security-Copilot-Agents/                     # Custom Security Copilot agents (YAML skillset manifests)
│   ├── SOCAlertAnalystEfficiencyDashboard-v400.yaml
│   └── README.md                                # 12-section SOC efficiency, cost & adoption dashboard
├── Security-Copilot-Custom-Plugins/             # Security Copilot custom plugins (roadmap)
├── Copilot-for-Security-Plugins/                # Security Copilot plugins (roadmap)
├── Copilot-for-Security-Promptbook-Playbooks/   # Security Copilot promptbooks (roadmap)
├── LICENSE
└── README.md
```

**At a glance:** 29 KQL detections (12 also shipped as refreshed `AgentsInfo` variants) · 1 Sentinel workbook + ARM deploy template · 1 Security Copilot agent

---

## 🤖 AI Agent Security (Featured)

As AI agents become first-class identities — holding credentials, permissions, tools, and autonomy — traditional user/device detections don't see them. This collection closes that gap.

### OWASP LLM Top 10 (2025) detection set
A complete pack with **one detection mapped to each OWASP LLM risk** → [`KQL/AI-KQL/owasp-Top10-LLM2025/`](KQL/AI-KQL/owasp-Top10-LLM2025/) (see its [README](KQL/AI-KQL/owasp-Top10-LLM2025/README.md) for the full mapping).

| OWASP | Risk | Detection |
|-------|------|-----------|
| LLM01 | Prompt Injection | XPIA Exposure Map |
| LLM02 | Sensitive Info Disclosure | Sensitive Information Disclosure |
| LLM03 | Supply Chain | Untrusted Tool Supply Chain |
| LLM04 | Data & Model Poisoning | Knowledge & Model Drift |
| LLM05 | Improper Output Handling | Improper Output Handling |
| LLM06 | Excessive Agency | Autonomy Trifecta · Over-Privileged Permissions · Excessive Tool Surface |
| LLM07 | System Prompt Leakage | System Prompt Leakage |
| LLM08 | Vector & Embedding Weaknesses | Vector & Embedding Weaknesses |
| LLM09 | Misinformation | Misinformation Risk |
| LLM10 | Unbounded Consumption | Unbounded Consumption |

### Additional AI agent detections → [`KQL/AI-KQL/`](KQL/AI-KQL/)
Credential abuse · Graph API sensitive access · Lateral movement · Lifecycle & permission-grant audit · T1/T2 token-exchange anomalies · Risky service principals · Dormant agent reactivation · Guardrail drift.

---

## 🔍 KQL Queries

Hunting queries, detection patterns, and investigation techniques for **Microsoft Defender XDR Advanced Hunting** and **Microsoft Sentinel** — across Defender for Endpoint, Identity, and Office 365.

**General detections** → [`KQL/`](KQL/)
- **Email & phishing:** Phishing Email Delivery Summary · Malicious URL Clicks by User · Attachment-Based Threats
- **Endpoint health:** Endpoint Sensor Health (5 checks) · MDE Sensor Data Collection Health · MDE Telemetry Latency · Defender AV Mode
- **Triage & coverage:** Defender XDR Alert Coverage Summary · Threat Behavior Summary (BehaviorInfo)

---

## 📊 Sentinel Workbooks

Interactive Microsoft Sentinel workbooks with one-click deployment → [`Workbooks/`](Workbooks/)
- **Cost Optimization workbook** — surface ingestion volume and spend by table/data source, spot noisy or low-value logs, and guide retention/tiering decisions. Ships with an ARM `deploy-` template for one-click deployment.

---

## 🛡️ Security Copilot Agents

Custom Security Copilot agents — complete YAML skillset manifests you can upload and run → [`Security-Copilot-Agents/`](Security-Copilot-Agents/)

### SOC Alert & Analyst Efficiency Dashboard v400

Ask *"How is my SOC performing?"* and get a **12-section** operational report built entirely from your own Microsoft Sentinel data:

| | Sections |
|---|---|
| **Performance** | Efficiency summary (MTTA / MTTR) · SLA breaches · Incident reopen rate |
| **Alert quality** | Alert volume by source · Noisiest detections with false-positive % |
| **People** | Analyst workload and unassigned backlog · Aging backlog by incident age |
| **Signals** | Daily trend with Z-score spike/drop anomaly detection |
| **Trust & cost** | Data connector & rule health · Estimated ingestion cost in USD · Security Copilot adoption |

One AGENT orchestrator drives a union-shaped KQL **snapshot** skill plus three failure-tolerant satellite skills, then renders all 12 sections itself — a missing `SentinelHealth`, `Usage`, or `CopilotActivity` table degrades only its own section instead of collapsing the report.

**Read-only and workspace-scoped** — no Azure Resource Manager access, no delegated Azure token, and no externally hosted OpenAPI spec. Cost is estimated from billable ingestion volume × a configurable price per GB rather than the billing API, a deliberate trade of invoice precision for a much smaller attack surface.

> ⚠️ **Tune before you trust it.** The SLA targets (4h / 24h / 72h) and the price per GB ($4.30) are **dummy defaults, not standards** — every organization must set them to its own SLA policy and commercial rate, or the breach counts and cost figures will not reflect reality.

→ Full architecture, install steps, SLA logic, and tuning notes in the [agent README](Security-Copilot-Agents/README.md).

---

## 🧰 Security Copilot Promptbooks *(roadmap)*

Reusable prompt structures to speed up investigations, guide Security Copilot step-by-step, and standardize SOC workflows — based on real customer scenarios. Tracked in [`Copilot-for-Security-Promptbook-Playbooks/`](Copilot-for-Security-Promptbook-Playbooks/); content is being added.

---

## 🚀 Getting Started

1. Open the **Microsoft Defender portal** → **Advanced hunting** (or Microsoft Sentinel → Logs).
2. Open any `.md` file here and copy its **KQL** block.
3. Paste, run, and triage by the `RiskLevel` column the detections produce.
4. **Tune** keyword lists, thresholds, and time windows to your environment (each file has Tuning Notes).

---

## ✅ Prerequisites & Coverage

- **Platform:** Microsoft Defender XDR Advanced Hunting / Microsoft Sentinel.
- **AI agent tables:** `AIAgentsInfo` (migrating to `AgentsInfo` by **July 1 2026**) — populated by Microsoft Agent 365 / Copilot Studio / Defender for Cloud Apps.
- **Identity activity:** `EntraIdSpnSignInEvents` requires **Microsoft Entra ID P2**.
- **App permissions:** `OAuthAppInfo` requires **app governance** in Defender for Cloud Apps.
- If a required connector isn't onboarded, the relevant queries return no rows.

---

## ⚠️ Disclaimer

These queries are **read-only** — they find and surface risk, they don't change configuration. Remediation is performed in the respective admin portals (see each detection's *Response Actions*). Always **test and tune** before operationalizing as scheduled detection rules. Provided as-is, with no warranty.

---

## 🤝 Contributing

Issues and pull requests are welcome — new detections, fixes, and tuning improvements all help the community. Please keep detections schema-accurate (validated against the official Microsoft Defender XDR schema) and include a short purpose + risk rationale.

---

## 📄 License

**MIT License** — free to use, modify, and share. See [LICENSE](LICENSE).
