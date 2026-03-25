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

> **Important:**  
> Add the following prompts **in order** when creating the Promptbook in Security Copilot.  
> Each prompt builds on the previous one.

---

## Prompt 1 — Context & Rules

**Prompt:**
``
