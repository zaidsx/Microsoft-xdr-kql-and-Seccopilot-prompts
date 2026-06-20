# AI Agent Lateral Movement Detection

## Overview
Identifies AI agent service principals (agenticAppInstance) authenticating to resources outside their expected or baseline scope. Agents should only access a defined set of resources — any deviation is a lateral movement signal, especially if the agent identity has been compromised or its token stolen.

**MITRE ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts

## KQL Query

```kql
let LookbackWindow = ago(20d);
let BaselineWindow = ago(30d);

// Check if any baseline data exists at all
let BaselineDataExists =
    AADServicePrincipalSignInLogs
    | where TimeGenerated between (BaselineWindow .. LookbackWindow)
    | extend AgentInfo = todynamic(Agent)
    | where AgentInfo.agentType == "agenticAppInstance"
    | summarize TotalBaselineEvents = count()
    | project HasBaseline = TotalBaselineEvents > 0;

// Build baseline of resources each agent normally accesses
let AgentBaseline =
    AADServicePrincipalSignInLogs
    | where TimeGenerated between (BaselineWindow .. LookbackWindow)
    | extend AgentInfo = todynamic(Agent)
    | where AgentInfo.agentType == "agenticAppInstance"
    | where isnotempty(Agent)
    | summarize
        BaselineResources = make_set(ResourceIdentity),
        BaselineResourceNames = make_set(ResourceDisplayName),
        BaselineDays = dcount(bin(TimeGenerated, 1d))
        by ServicePrincipalId, ServicePrincipalName;

// Get recent agent sign-ins
let RecentActivity =
    AADServicePrincipalSignInLogs
    | where TimeGenerated > LookbackWindow
    | extend AgentInfo = todynamic(Agent)
    | where AgentInfo.agentType == "agenticAppInstance"
    | where isnotempty(Agent)
    | project
        TimeGenerated,
        ServicePrincipalId,
        ServicePrincipalName,
        ResourceIdentity,
        ResourceDisplayName,
        IPAddress,
        Location,
        ResultType;

// Flag access to resources outside baseline
RecentActivity
| join kind=leftouter AgentBaseline on ServicePrincipalId
| extend IsNewResource = not(set_has_element(BaselineResources, ResourceIdentity))
| where IsNewResource == true or isnull(BaselineResources)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    AccessCount = count(),
    IPAddresses = make_set(IPAddress),
    Locations = make_set(Location),
    BaselineResources = take_any(BaselineResources),
    BaselineDays = take_any(BaselineDays)
    by ServicePrincipalName, ResourceDisplayName, ResourceIdentity
| extend Risk = case(
    isnull(BaselineResources), "⚠️ New Agent — No History Found",
    BaselineDays < 3, "⚠️ Thin Baseline — Less Than 3 Days of History",
    "🚨 Out-of-Scope Resource Access")
| extend Confidence = case(
    isnull(BaselineResources), "Low — Cannot confirm if access is abnormal",
    BaselineDays < 3, "Low — Baseline too short to be reliable",
    BaselineDays < 7, "Medium — Baseline exists but limited",
    "High — Strong baseline, access is genuinely new")
| project
    FirstSeen,
    LastSeen,
    ServicePrincipalName,
    ResourceDisplayName,
    ResourceIdentity,
    AccessCount,
    IPAddresses,
    Locations,
    BaselineDays,
    Risk,
    Confidence
| sort by Risk asc, AccessCount desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| ServicePrincipalName | The AI agent identity performing the access |
| ResourceDisplayName | Resource the agent accessed outside its baseline |
| AccessCount | Number of out-of-scope access attempts |
| IPAddresses | Source IPs used during out-of-scope access |
| Risk | Classification of the anomaly |

## Use Cases
- Detect compromised agent tokens being used to pivot to new resources
- Identify agents with overly permissive scopes accessing unintended services
- Alert on newly deployed agents with no established baseline (immediate risk)
