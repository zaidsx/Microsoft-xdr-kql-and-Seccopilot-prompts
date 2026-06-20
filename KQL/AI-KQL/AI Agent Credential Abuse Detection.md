# AI Agent Credential Abuse Detection

## Overview
Detects multiple T2 sign-in events from the same Agent Identity hitting different resources in a short window — a strong indicator of token theft and reuse. Legitimate agents follow predictable, scoped access patterns; bursts of multi-resource access are abnormal.

**MITRE ATT&CK:** T1550.001 — Use Alternate Authentication Material | T1078.004 — Valid Accounts

## KQL Query

```kql
let LookbackWindow = ago(1d);
let BurstWindow = 5m;
let ResourceThreshold = 3; // Flag agents hitting 3+ distinct resources in BurstWindow

AADServicePrincipalSignInLogs
| where TimeGenerated > LookbackWindow
| extend AgentInfo = todynamic(Agent)
| where AgentInfo.agentType == "agenticAppInstance"
| summarize
    ResourcesAccessed = dcount(ResourceIdentity),
    ResourceNames = make_set(ResourceDisplayName, 10),
    IPAddresses = make_set(IPAddress, 5),
    Locations = make_set(Location, 5),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    FailedAttempts = countif(ResultType != "0"),
    TotalAttempts = count()
    by ServicePrincipalId, ServicePrincipalName, bin(TimeGenerated, BurstWindow)
| where ResourcesAccessed >= ResourceThreshold
| extend
    BurstDuration = datetime_diff('minute', LastAccess, FirstAccess),
    MultipleLocations = array_length(Locations) > 1,
    HighFailureRate = (FailedAttempts * 1.0 / TotalAttempts) > 0.3
| extend RiskScore = case(
    MultipleLocations and ResourcesAccessed >= 5, "Critical",
    MultipleLocations or HighFailureRate, "High",
    ResourcesAccessed >= ResourceThreshold, "Medium",
    "Low")
| where RiskScore in ("Critical", "High", "Medium")
| project
    FirstAccess,
    ServicePrincipalName,
    ResourcesAccessed,
    ResourceNames,
    IPAddresses,
    Locations,
    MultipleLocations,
    FailedAttempts,
    TotalAttempts,
    RiskScore
| sort by RiskScore asc, ResourcesAccessed desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| ServicePrincipalName | The AI agent identity showing burst behaviour |
| ResourcesAccessed | Distinct resources accessed in the burst window |
| ResourceNames | Names of resources accessed |
| MultipleLocations | True if access originated from multiple geographies |
| HighFailureRate | True if >30% of attempts failed (probing behaviour) |
| RiskScore | Critical / High / Medium based on combined signals |

## Use Cases
- Detect stolen agent tokens being rapidly tested against multiple resources
- Identify agents used in automated exfiltration pipelines (TA0010)
- Correlate with RiskyServicePrincipals for enriched risk context (requires Workload ID Premium)
