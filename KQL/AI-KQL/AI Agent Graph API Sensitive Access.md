# AI Agent Graph API Sensitive Access

## Overview
Surfaces Microsoft Graph API calls made by AI agent service principals (agenticAppInstance) targeting sensitive endpoints such as mail, files, directory objects, and security APIs. Requires MicrosoftGraphActivityLogs to be enabled via diagnostic settings — this data has zero native retention in the Entra portal and is not recoverable retroactively.

**MITRE ATT&CK:** TA0010 — Exfiltration | T1530 — Data from Cloud Storage

## Prerequisites
> MicrosoftGraphActivityLogs must be routed to the same Log Analytics Workspace as your Entra sign-in logs. Without diagnostic settings configured in advance, this data is unrecoverable.

## KQL Query

```kql
let LookbackWindow = ago(1d);

// Define sensitive Graph API endpoint patterns
let SensitiveEndpoints = dynamic([
    "/me/messages", "/users/.*/messages",        // Mail read
    "/me/mailFolders", "/users/.*/mailFolders",   // Mail folders
    "/me/drive", "/users/.*/drive",               // OneDrive files
    "/sites/.*/drive",                            // SharePoint files
    "/users",                                     // Directory enumeration
    "/groups",                                    // Group enumeration
    "/directoryRoles",                            // Role enumeration
    "/security/alerts",                           // Security alerts
    "/identity/conditionalAccess",               // CA policy read
    "/applications",                              // App registrations
    "/servicePrincipals"                          // Service principal enum
]);

MicrosoftGraphActivityLogs
| where TimeGenerated > LookbackWindow
| where ServicePrincipalId != ""
// Join to identify which calls are from agent identities
| join kind=inner (
    AADServicePrincipalSignInLogs
    | where TimeGenerated > LookbackWindow
    | extend AgentInfo = todynamic(Agent)
    | where AgentInfo.agentType == "agenticAppInstance"
    | summarize by ServicePrincipalId, ServicePrincipalName
) on ServicePrincipalId
| where RequestUri has_any (SensitiveEndpoints)
| summarize
    CallCount = count(),
    UniqueEndpoints = dcount(RequestUri),
    Endpoints = make_set(RequestUri, 10),
    IPAddresses = make_set(IPAddress, 5),
    FirstCall = min(TimeGenerated),
    LastCall = max(TimeGenerated)
    by ServicePrincipalName, ServicePrincipalId
| extend RiskLevel = case(
    UniqueEndpoints >= 5, "Critical – Broad Graph Enumeration",
    CallCount >= 100, "High – High Volume Graph Access",
    Endpoints has "/security" or Endpoints has "/conditionalAccess", "High – Security API Access",
    Endpoints has "messages" or Endpoints has "drive", "Medium – Mail or File Access",
    "Low")
| sort by RiskLevel asc, CallCount desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| ServicePrincipalName | AI agent identity making Graph API calls |
| CallCount | Total Graph API calls in the window |
| UniqueEndpoints | Number of distinct endpoints accessed |
| Endpoints | Sample of endpoints called |
| RiskLevel | Risk classification based on endpoint sensitivity and volume |

## Use Cases
- Detect agents performing directory enumeration (users, groups, roles)
- Identify agents reading email or files outside expected workflow
- Alert on agents accessing security or Conditional Access policy APIs
- Correlate with T2 sign-in anomalies for full attack chain reconstruction
