# AI Agent T1/T2 Token Exchange Anomaly

## Overview
Detects broken or suspicious token exchanges in Microsoft Foundry agent authentication flows. Each legitimate agent request produces a paired T1 (Blueprint) and T2 (Agent Identity) sign-in event within milliseconds. A T1 with no matching T2, or an unexpected T2 resource target, indicates a potential compromise or misconfiguration.

**MITRE ATT&CK:** T1550.001 — Use Alternate Authentication Material (Token Theft/Reuse)

## KQL Query

```kql
let LookbackWindow = ago(1d);
let TokenExchangeResource = "fb60f99c-7a34-4190-8149-302f77469936";
let MaxPairingWindow = 30; // seconds, as integer to match datetime_diff output

// T1 events: Blueprint authenticating to Token Exchange endpoint
let T1Events =
    AADServicePrincipalSignInLogs
    | where TimeGenerated > LookbackWindow
    | where ResourceIdentity == TokenExchangeResource
    | extend AgentInfo = todynamic(Agent)
    | where AgentInfo.agentType == "agentIdentityBlueprintPrincipal"
    | project
        T1_Time = TimeGenerated,
        T1_CorrelationId = CorrelationId,
        BlueprintSPN = ServicePrincipalName,
        BlueprintSPNId = ServicePrincipalId,
        IPAddress,
        Location;

// T2 events: Agent Identity authenticating to actual target resource
let T2Events =
    AADServicePrincipalSignInLogs
    | where TimeGenerated > LookbackWindow
    | extend AgentInfo = todynamic(Agent)
    | where AgentInfo.agentType == "agenticAppInstance"
    | project
        T2_Time = TimeGenerated,
        T2_CorrelationId = CorrelationId,
        AgentSPN = ServicePrincipalName,
        AgentSPNId = ServicePrincipalId,
        TargetResource = ResourceDisplayName,
        TargetResourceId = ResourceIdentity,
        ResultType;

// Find T1 events with no matching T2 within expected window
T1Events
| join kind=leftouter T2Events on $left.T1_CorrelationId == $right.T2_CorrelationId
| extend TimeDelta = datetime_diff('second', T2_Time, T1_Time)
| extend Anomaly = case(
    isnull(T2_Time), "Broken Token Exchange: T1 with no T2",
    TimeDelta > MaxPairingWindow, "Delayed T2: Possible Token Replay",
    ResultType != "0", "T2 Authentication Failure",
    "Normal")
| where Anomaly != "Normal"
| project
    T1_Time,
    BlueprintSPN,
    AgentSPN,
    TargetResource,
    IPAddress,
    Location,
    TimeDelta,
    Anomaly
| sort by T1_Time desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| BlueprintSPN | The Blueprint service principal that initiated the T1 |
| AgentSPN | The Agent Identity that performed the T2 |
| TargetResource | Resource the agent attempted to access |
| TimeDelta | Seconds between T1 and T2 (>30s is suspicious) |
| Anomaly | Classification of the detected anomaly |

## Use Cases
- Detect token theft where T1 completes but T2 is replayed later
- Identify broken agent authentication flows indicating misconfiguration or tampering
- Baseline normal T1→T2 pairing latency for your environment
