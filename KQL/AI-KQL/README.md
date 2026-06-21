# AI Agent Threat Detection — Walkthrough & Use Case Guide

This guide explains the 6 KQL queries in this folder, what threats they detect, and when to use each one. Designed for SOC analysts and detection engineers working with Microsoft Foundry AI agents in Entra ID.

---

## Why AI Agents Need Dedicated Detection

AI agents are not human accounts. They:

- Authenticate **without MFA** — no second factor to stop an attacker
- Run **silently in the background** — no user to notice something is wrong
- Have **real permissions** to real resources — email, files, SharePoint, APIs
- Produce traffic that **blends in with normal automation** — hard to spot manually

If an attacker steals an AI agent token, they look **identical** to the agent itself. Standard user-focused detections won't catch this. These queries fill that gap.

---

## The 6 Queries — What They Do and When to Use Them

---

### 1. `AI Agent T1-T2 Token Exchange Anomaly.md`

**What it detects:**
Every AI agent action produces two back-to-back sign-in events — a T1 (Blueprint authenticates to Microsoft's token exchange) and a T2 (Agent Identity authenticates to the actual resource). These happen milliseconds apart. This query flags when that pattern breaks.

**When to use it:**
- Daily scheduled detection rule
- When investigating a suspected agent compromise
- When onboarding new agents — baseline their T1/T2 patterns

**Signals it catches:**

| Signal | What it means |
|--------|--------------|
| T1 with no T2 | Token was intercepted mid-exchange |
| T2 delayed >30 seconds | Token was stolen and replayed later |
| T2 authentication failure | Stolen token doesn't have the right permissions |

---

### 2. `AI Agent Lateral Movement Detection.md`

**What it detects:**
Builds a 10-day baseline of which resources each agent normally accesses. Flags any access in the recent window that falls outside that baseline.

**When to use it:**
- When an alert fires on an agent identity
- Weekly threat hunting across all agents
- After a broader incident — check if any agents were used to pivot

**Signals it catches:**

| Signal | What it means |
|--------|--------------|
| New resource not in baseline | Agent accessing something it was never built to touch |
| Thin baseline (<3 days) | New or recently recreated agent — investigate who deployed it |
| No baseline at all | Brand new agent with no history — treat as unknown risk |

---

### 3. `AI Agent Credential Abuse Detection.md`

**What it detects:**
Watches for burst activity — an agent hitting multiple distinct resources in a short 5-minute window. Legitimate agents follow predictable, scoped patterns. Bursts of multi-resource access are a stolen token being tested.

**When to use it:**
- Real-time or near-real-time alert rule
- Immediately after any credential leak or breach notification
- When investigating unusual agent behaviour flagged by other queries

**Signals it catches:**

| Signal | What it means |
|--------|--------------|
| 3+ resources in 5 minutes | Token being rapidly tested across environment |
| Multiple geographies in burst | Token in use from more than one location simultaneously |
| High failure rate in burst | Attacker probing with a token that doesn't have full permissions |

---

### 4. `AI Agent Lifecycle Audit – Creation and Permission Grants.md`

**What it detects:**
Monitors `AuditLogs` for high-risk events targeting confirmed AI agent identities — new agent creation, credential additions, permission grants, and Entra role assignments. Contains 3 queries covering known agents, brand new agents, and after-hours changes.

**When to use it:**
- Weekly compliance and change audit
- After any Entra ID change freeze period
- When investigating persistence after a breach
- As an insider threat detection control

**Signals it catches:**

| Signal | What it means |
|--------|--------------|
| New credential added to agent | Someone can now generate tokens for that agent — full impersonation |
| Role assigned to agent | Agent's permissions elevated beyond its original design |
| Admin consent granted | Agent now has tenant-wide API permissions |
| New registration + immediate permission grant | Rogue agent deployed fast — attacker standing up a backdoor |
| After-hours lifecycle change | No change ticket, no business justification |

---

### 5. `AI Agent Graph API Sensitive Access.md`

**What it detects:**
Watches which Microsoft Graph API endpoints AI agents are calling. Legitimate agents call only the endpoints they were built for. An agent calling mail, user directory, security alerts, or Conditional Access APIs is either compromised or was built maliciously.

**When to use it:**
- Weekly hunt across all agent Graph activity
- When investigating a suspected data exfiltration
- After deploying a new agent — verify it only calls expected endpoints

> **Prerequisite:** `MicrosoftGraphActivityLogs` must be routed to your Log Analytics workspace via diagnostic settings. This data has zero native retention — if diagnostic settings are not configured, the data is unrecoverable.

**Signals it catches:**

| Endpoint Called | Risk |
|----------------|------|
| `/me/messages`, `/users/messages` | Reading employee emails |
| `/me/drive`, `/sites/drive` | Reading OneDrive or SharePoint files |
| `/users`, `/groups`, `/directoryRoles` | Mapping the entire organisation |
| `/security/alerts` | Learning what security detections are in place |
| `/identity/conditionalAccess` | Reading your security policies and finding gaps |

**Risk levels:**

| Level | Condition |
|-------|-----------|
| Critical | Agent called 5+ distinct sensitive endpoints |
| High | Agent called security or Conditional Access APIs |
| Medium | Agent read emails or files |

---

### 6. `Risky AI Agent Service Principals.md`

**What it detects:**
Scores every AI agent across 5 behavioral dimensions and surfaces those crossing risk thresholds. Does not require Workload ID Premium — builds its own risk signals from sign-in log patterns.

**When to use it:**
- Weekly or daily risk review of all agent identities
- Starting point when you don't know where to look — run this first
- Prioritisation tool before digging into other queries
- When you don't have Workload ID Premium but still need risk visibility

**The 6 use cases this query covers:**

---

#### UC1 — Token Theft Detection (Multiple Geographies)
AI agents authenticate from fixed infrastructure — a server, a pipeline, a cloud service. They should never sign in from 3 different countries in the same week. If they do, someone has stolen the agent's token and is using it from a different location. The `UniqueLocations` signal catches this directly.

---

#### UC2 — Token Probing / Credential Stuffing (High Failure Rate)
An attacker with a partially valid token will attempt multiple sign-ins, most of which fail, until they find one that works. A legitimate agent rarely fails authentication. A failure rate above 20% on an agent is abnormal — above 30% combined with multi-location access is Critical.

---

#### UC3 — Compromised Agent Pivoting (Broad Resource Access)
A healthy agent accesses only the resources it was built for — typically 1 to 3 resources. If an agent suddenly starts touching 5, 10, or more distinct resources, its token is likely being used to explore the environment. The `ResourcesAccessed` signal flags this, and `ResourceNames` shows exactly what was touched.

---

#### UC4 — After-Hours Attacker Activity (Off-Hours Sign-Ins)
Legitimate automation runs on schedules. An agent that runs nightly jobs will have consistent after-hours patterns. But an agent with a sudden spike in after-hours sign-ins — especially combined with new IPs or locations — is a strong indicator of an attacker using a stolen token when SOC coverage is lowest.

---

#### UC5 — Infrastructure Anomaly Detection (Multiple IPs)
Agents sign in from consistent, known infrastructure. Multiple distinct source IPs in the same window mean the agent's token is being used from more than one machine — a clear sign of token theft or an attacker operating from rotating infrastructure.

---

#### UC6 — Prioritization Without Premium Licensing
The `RiskReasons` column explains in plain English why each agent was flagged. SOC analysts can use this to triage quickly — an agent flagged for "Multiple Geographies; High Failure Rate (45%)" is a higher priority than one flagged for "After-Hours Activity (6 sign-ins)" — without needing to dig into raw logs first.

---

## Risk Score Reference

| Score | Meaning | Recommended Action |
|-------|---------|-------------------|
| Critical | Multiple strong signals combined | Immediate investigation — revoke agent credentials |
| High | One strong signal confirmed | Investigate within 4 hours |
| Medium | Weak or single signal | Review within 24 hours — check for corroborating evidence |

---

## Where to Start

If you're running these for the first time, use this order:

1. **Start with Query 6** (`Risky AI Agent Service Principals`) — quick overview of all agents, ranked by risk
2. **Drill into flagged agents using Query 5** (`Graph API Sensitive Access`) — what were they calling?
3. **Check their access patterns with Query 2** (`Lateral Movement`) — did they go somewhere new?
4. **Look for burst activity with Query 3** (`Credential Abuse`) — were they hitting multiple things fast?
5. **Check the lifecycle with Query 4** (`Lifecycle Audit`) — was anything changed on this agent recently?
6. **Validate the token exchange with Query 1** (`T1/T2 Anomaly`) — was the authentication flow itself clean?

---

## MITRE ATT&CK Coverage

| Query | Technique |
|-------|-----------|
| T1/T2 Token Exchange Anomaly | T1550.001 — Use Alternate Authentication Material |
| Lateral Movement Detection | T1078.004 — Valid Accounts: Cloud Accounts |
| Credential Abuse Detection | T1550.001, T1078.004 |
| Lifecycle Audit | TA0003 — Persistence, T1098 — Account Manipulation |
| Graph API Sensitive Access | TA0010 — Exfiltration, T1530 — Data from Cloud Storage |
| Risky Agent Behavioral Signals | T1078.004, T1550.001 |
