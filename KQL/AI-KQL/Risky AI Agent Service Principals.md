# Risky AI Agent Service Principals

## Overview
Originally designed to use Microsoft's Workload ID Premium risk tables (`RiskyServicePrincipals`, `ServicePrincipalRiskEvents`), this query was rebuilt to work without premium licensing. Instead of relying on Microsoft's risk engine, it **builds its own risk signals** directly from `AADServicePrincipalSignInLogs` using behavioral patterns that indicate a compromised or abused agent identity.

AI agents are different from human accounts — they should behave predictably and consistently. They sign in from the same infrastructure, access the same resources, and operate during business hours. Any deviation from this pattern is a signal worth investigating.

The query scores each agent across 5 behavioral dimensions and surfaces only those that cross risk thresholds.

**MITRE ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts | T1550.001 — Token Theft

## Prerequisites
> No premium licensing required. Works with any Log Analytics workspace that has `AADServicePrincipalSignInLogs` diagnostic data flowing in.
> If you have **Workload ID Premium**, enrich this query by joining against `RiskyServicePrincipals` and `ServicePrincipalRiskEvents`.

---

## KQL Query

```kql
let LookbackWindow = ago(7d);
let BusinessHourStart = 8;
let BusinessHourEnd = 18;

AADServicePrincipalSignInLogs
| where TimeGenerated > LookbackWindow
| extend AgentInfo = todynamic(Agent)
| where isnotempty(Agent)
| where AgentInfo.agentType == "agenticAppInstance"
| extend HourOfDay = datetime_part("Hour", TimeGenerated)
| extend IsAfterHours = HourOfDay < BusinessHourStart or HourOfDay >= BusinessHourEnd
| summarize
    TotalSignIns = count(),
    FailedSignIns = countif(ResultType != "0"),
    ResourcesAccessed = dcount(ResourceIdentity),
    ResourceNames = make_set(ResourceDisplayName, 5),
    UniqueIPs = dcount(IPAddress),
    IPAddresses = make_set(IPAddress, 5),
    UniqueLocations = dcount(Location),
    Locations = make_set(Location, 5),
    AfterHoursSignIns = countif(IsAfterHours == true),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ServicePrincipalId, ServicePrincipalName
| extend FailureRate = round((FailedSignIns * 1.0 / TotalSignIns) * 100, 1)
| extend RiskScore = case(
    UniqueLocations >= 3 and FailureRate >= 30, "Critical",
    UniqueLocations >= 3 or (FailureRate >= 30 and ResourcesAccessed >= 5), "High",
    AfterHoursSignIns >= 10 or UniqueIPs >= 5, "High",
    FailureRate >= 20 or ResourcesAccessed >= 5, "Medium",
    AfterHoursSignIns >= 5 or UniqueIPs >= 3, "Medium",
    "Low")
| extend RiskReasons = strcat(
    iff(UniqueLocations >= 3, "Multiple Geographies; ", ""),
    iff(FailureRate >= 20, strcat("High Failure Rate (", tostring(FailureRate), "%); "), ""),
    iff(ResourcesAccessed >= 5, strcat("Broad Resource Access (", tostring(ResourcesAccessed), " resources); "), ""),
    iff(AfterHoursSignIns >= 5, strcat("After-Hours Activity (", tostring(AfterHoursSignIns), " sign-ins); "), ""),
    iff(UniqueIPs >= 3, strcat("Multiple IPs (", tostring(UniqueIPs), "); "), ""))
| where RiskScore in ("Critical", "High", "Medium")
| project
    LastSeen,
    ServicePrincipalName,
    RiskScore,
    RiskReasons,
    TotalSignIns,
    FailedSignIns,
    FailureRate,
    ResourcesAccessed,
    ResourceNames,
    UniqueLocations,
    Locations,
    UniqueIPs,
    IPAddresses,
    AfterHoursSignIns,
    FirstSeen
| sort by RiskScore asc, FailureRate desc
```

---

## Bonus: Confirmed High-Risk Agents (Quick View)

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| extend AgentInfo = todynamic(Agent)
| where isnotempty(Agent)
| where AgentInfo.agentType == "agenticAppInstance"
| summarize
    FailedSignIns = countif(ResultType != "0"),
    TotalSignIns = count(),
    UniqueLocations = dcount(Location),
    ResourcesAccessed = dcount(ResourceIdentity)
    by ServicePrincipalName
| extend FailureRate = round((FailedSignIns * 1.0 / TotalSignIns) * 100, 1)
| where FailureRate >= 20 or UniqueLocations >= 3 or ResourcesAccessed >= 5
| sort by FailureRate desc
```

---

## Risk Score Logic
| Score | Conditions |
|-------|-----------|
| Critical | 3+ locations AND 30%+ failure rate |
| High | 3+ locations OR (30%+ failures AND 5+ resources) OR after-hours + multiple IPs |
| Medium | 20%+ failure rate OR 5+ resources OR repeated after-hours activity |

## Columns Explained
| Column | Description |
|--------|-------------|
| RiskScore | Critical / High / Medium based on behavioral signals |
| RiskReasons | Plain-English explanation of why the agent was flagged |
| FailureRate | Percentage of sign-ins that failed |
| ResourcesAccessed | Number of distinct resources the agent touched |
| UniqueLocations | Number of distinct geographies sign-ins came from |
| AfterHoursSignIns | Sign-ins outside 08:00–18:00 |
| UniqueIPs | Number of distinct source IP addresses |

## Use Cases

**UC1 — Token Theft Detection (Multiple Geographies)**
AI agents authenticate from fixed infrastructure — a server, a pipeline, a cloud service. They should never sign in from 3 different countries in the same week. If they do, someone has stolen the agent's token and is using it from a different location. The `UniqueLocations` signal catches this directly.

**UC2 — Token Probing / Credential Stuffing (High Failure Rate)**
An attacker with a partially valid token will attempt multiple sign-ins, most of which fail, until they find one that works. A legitimate agent rarely fails authentication. A failure rate above 20% on an agent is abnormal — above 30% combined with multi-location access is Critical.

**UC3 — Compromised Agent Pivoting (Broad Resource Access)**
A healthy agent accesses only the resources it was built for — typically 1 to 3 resources. If an agent suddenly starts touching 5, 10, or more distinct resources, its token is likely being used to explore the environment. The `ResourcesAccessed` signal flags this, and `ResourceNames` shows exactly what was touched.

**UC4 — After-Hours Attacker Activity (Off-Hours Sign-Ins)**
Legitimate automation runs on schedules. An agent that runs nightly jobs will have consistent after-hours patterns. But an agent with a sudden spike in after-hours sign-ins — especially combined with new IPs or locations — is a strong indicator of an attacker using a stolen token when SOC coverage is lowest.

**UC5 — Infrastructure Anomaly Detection (Multiple IPs)**
Agents sign in from consistent, known infrastructure. Multiple distinct source IPs in the same window mean the agent's token is being used from more than one machine — a clear sign of token theft or an attacker operating from rotating infrastructure.

**UC6 — Prioritization Without Premium Licensing**
The `RiskReasons` column explains in plain English why each agent was flagged. SOC analysts can use this to triage quickly — an agent flagged for "Multiple Geographies; High Failure Rate (45%)" is a higher priority than one flagged for "After-Hours Activity (6 sign-ins)" — without needing to dig into raw logs first.
