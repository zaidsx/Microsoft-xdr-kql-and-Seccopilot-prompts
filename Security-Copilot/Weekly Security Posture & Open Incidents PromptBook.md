# 🛡️ Security Copilot Promptbook
## Weekly Security Posture & Open Incidents Report (Microsoft Defender XDR)

---

## 📌 Purpose

This promptbook is designed for **Information Security and SOC teams** to generate a **weekly security posture report** using **Microsoft Security Copilot** with **Microsoft Defender XDR** (and Microsoft Sentinel if unified).

The output provides:
- A weekly security posture overview
- Open incident and alert counts
- Incident and alert summaries grouped by **detection solution**
- Severity‑based prioritization (Critical → Low)
- Clear **guidance and next steps** based on findings

---

## 🧩 Supported Detection Solutions

- **MDE** – Microsoft Defender for Endpoint  
- **MDO** – Microsoft Defender for Office 365  
- **MDCA (MDA)** – Microsoft Defender for Cloud Apps  
- **MDI** – Microsoft Defender for Identity  
- **Multi‑signal** – Incidents involving multiple Defender workloads

---

## 🧑‍💻 Intended Audience

- SOC Analysts  
- Incident Responders  
- Security Operations Managers  
- Information Security Leadership

---

## 🔌 Required Plugins

- ✅ Microsoft Defender XDR  
- ➕ Microsoft Sentinel (optional, if incidents are unified)

---

## 🔧 Promptbook Inputs

Use **angle brackets with no spaces** when creating the promptbook.

- `<TIME_RANGE>` → e.g. `last 7 days`
- `<REPORT_DATE>` → e.g. `2026-03-25`
- `<TOP_N>` → e.g. `10`
- `<TENANT_OR_ENV>` → e.g. `Production`

---

# ▶️ Promptbook Flow

<!-- Weekly Security Posture & Open Incidents Prompt (Parameterized) -->

<p>
You are generating a <strong>Weekly Security Posture and Open Incidents Report</strong>
covering the period defined by <strong>&lt;TIME_RANGE&gt;</strong>.
</p>

<p>
<strong>Report Context:</strong><br />
Time Range: <strong>&lt;TIME_RANGE&gt;</strong> (e.g. last 7 days)<br />
Report Date: <strong>&lt;REPORT_DATE&gt;</strong> (e.g. 2026-03-25)<br />
Scope / Environment: <strong>&lt;TENANT_OR_ENV&gt;</strong> (e.g. Production)<br />
Top N Results: <strong>&lt;TOP_N&gt;</strong> (e.g. 10)
</p>

<p>
This report is generated on <strong>&lt;REPORT_DATE&gt;</strong>.
Use <strong>Microsoft Defender XDR</strong> data available to you.
If <strong>Microsoft Sentinel unified incidents</strong> are available, include them.
</p>

<p>
If any required data is unavailable, clearly state:
<strong>Not available from current data sources.</strong>
</p>

<hr />

<h3>1. Incident and Alert Overview</h3>
<p>
Provide counts of open incidents and alerts for <strong>&lt;TIME_RANGE&gt;</strong>.
Group findings by detection source:
<strong>MDE, MDO, MDCA (also labeled as MDA), MDI, and Multi-signal</strong>.
Sort all results by severity from <strong>Critical</strong> to <strong>Low</strong>.
End the report with a section titled:
<strong>Guidance and Next Steps (Prioritized) and Why</strong>.
</p>

<h3>2. Overall Security Posture Summary</h3>
<p>
Summarize the overall security posture for <strong>&lt;TIME_RANGE&gt;</strong>
based on Defender XDR signals in <strong>&lt;TENANT_OR_ENV&gt;</strong>.
Include:
</p>
<ul>
  <li>Top five security posture highlights</li>
  <li>Top five posture risks or gaps</li>
  <li>Notable trends observed during this period</li>
</ul>
<p>
Focus on detection coverage, telemetry health,
recurring attack patterns, and visibility gaps.
</p>

<h3>3. Metrics Overview</h3>
<p>
Provide a metrics overview for <strong>&lt;TIME_RANGE&gt;</strong> including:
</p>
<ul>
  <li>Total open incidents</li>
  <li>Total new incidents created during this period</li>
  <li>Total alerts associated with open incidents</li>
  <li>Open incidents by severity</li>
  <li>Alerts by severity</li>
</ul>
<p>
Present the results in a table followed by
<strong>three key insights</strong>.
</p>

<h3>4. Incident and Alert Classification</h3>
<p>
Classify incidents and alerts using the following detection sources:
</p>
<ul>
  <li>MDE – Microsoft Defender for Endpoint</li>
  <li>MDO – Microsoft Defender for Office 365</li>
  <li>MDCA / MDA – Microsoft Defender for Cloud Apps</li>
  <li>MDI – Microsoft Defender for Identity</li>
</ul>
<p>
If an incident spans multiple solutions,
classify it as <strong>Multi-signal</strong>
and list all contributing sources.
</p>

<h3>5. Open Incidents Details</h3>
<p>
List all currently open incidents for <strong>&lt;TENANT_OR_ENV&gt;</strong>,
grouped by detection source.
For each source, include a severity count summary.
Provide a table sorted by severity containing:
</p>
<ul>
  <li>Incident ID</li>
  <li>Title</li>
  <li>Severity</li>
  <li>Status</li>
  <li>First seen</li>
  <li>Last updated</li>
  <li>Impacted entities</li>
  <li>One-line summary</li>
</ul>

<h3>6. Alert Summary</h3>
<p>
Summarize alerts from <strong>&lt;TIME_RANGE&gt;</strong>
grouped by detection source and severity.
Include:
</p>
<ul>
  <li>A table of alert counts by source and severity</li>
  <li>Top <strong>&lt;TOP_N&gt;</strong> alert titles by frequency for each source</li>
  <li>Any spikes, anomalies, or recurring patterns</li>
</ul>

<h3>7. Top &lt;TOP_N&gt; Open Incidents</h3>
<p>
Select the top <strong>&lt;TOP_N&gt;</strong> open incidents ranked by severity and impact.
For each incident, provide:
</p>
<ul>
  <li>What happened in plain language</li>
  <li>Likely attack intent or stage</li>
  <li>Impacted entities and scope</li>
  <li>Key alert evidence</li>
  <li>Actions already taken, if available</li>
  <li>Three recommended next actions</li>
</ul>

<h3>8. Common Themes Analysis</h3>
<p>
Identify common themes across incidents and alerts observed during
<strong>&lt;TIME_RANGE&gt;</strong>.
For each theme, include:
</p>
<ul>
  <li>Description of the recurring pattern</li>
  <li>Detection sources involved (MDE, MDO, MDCA, MDI)</li>
  <li>Why this theme matters to <strong>&lt;TENANT_OR_ENV&gt;</strong></li>
  <li>Controls, detections, or configurations to review or tune</li>
</ul>

<h3>9. Recurring Patterns Summary</h3>
<p>
Identify recurring patterns observed during <strong>&lt;TIME_RANGE&gt;</strong>.
For each pattern, include:
</p>
<ul>
  <li>Description of the pattern</li>
  <li>Detection sources involved</li>
  <li>Why the pattern matters</li>
  <li>Controls or detections to review</li>
</ul>

<h3>10. Guidance and Next Steps (Prioritized) and Why</h3>
<p>
Create a final section titled:
<strong>Guidance and Next Steps (Prioritized) and Why</strong>.
</p>
<ul>
  <li>Prioritize actions from <strong>Critical</strong> to <strong>Low</strong></li>
  <li>For each action include:
    <ul>
      <li>Recommended action</li>
      <li>Responsible owner</li>
      <li>Why it matters</li>
      <li>Expected outcome</li>
    </ul>
  </li>
</ul>
<p>
Structure actions as <strong>Immediate</strong>, <strong>Near-term</strong>,
and <strong>Strategic</strong>.
Ensure all guidance directly maps to the findings in this report.
</p>

<h3>✅ Usage Notes</h3>
<ul>
  <li>Run this prompt weekly</li>
  <li>Validate Copilot output before executive distribution</li>
  <li>Use results for SOC prioritization and leadership reporting</li>
  <li>Track trends week-over-week for posture improvement</li>
</ul>

<p><strong>🏁 End of Prompt</strong></p>
