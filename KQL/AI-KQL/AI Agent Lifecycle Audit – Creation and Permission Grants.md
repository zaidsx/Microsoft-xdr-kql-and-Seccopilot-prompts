# AI Agent Lifecycle Audit – Creation and Permission Grants

## Overview
Monitors `AuditLogs` for high-risk lifecycle events targeting confirmed AI agent identities — Blueprint creation, credential additions, permission grants, and Entra role assignments.

The query solves a key problem: `AuditLogs` has no native `Agent` flag. It records what happened to a service principal but doesn't know if that SPN is an AI agent or a regular app. To close this gap, the query first builds a list of confirmed agent identities from `AADServicePrincipalSignInLogs` (which does have the `Agent` column), then uses that list to filter audit events — ensuring only events targeting genuine AI agent identities are returned.

**MITRE ATT&CK:**
- TA0003 — Persistence (credential addition, new agent creation)
- T1098.003 — Account Manipulation: Additional Cloud Roles
- T1098 — Account Manipulation (permission grants)

---

## Query 1 — Lifecycle Events on Known Agent Identities

Covers agents that already exist and have signed in at least once in the last 30 days.

```kql
let LookbackWindow = ago(7d);
let AgentHistoryWindow = ago(30d);

// Step 1: Build confirmed AI agent identity list from sign-in logs
let KnownAgents =
    AADServicePrincipalSignInLogs
    | where TimeGenerated > AgentHistoryWindow
    | extend AgentInfo = todynamic(Agent)
    | where isnotempty(Agent)
    | where AgentInfo.agentType in ("agenticAppInstance", "agentIdentityBlueprintPrincipal")
    | summarize
        AgentType = take_any(tostring(AgentInfo.agentType)),
        LastSeen = max(TimeGenerated),
        SignInCount = count()
        by ServicePrincipalName, ServicePrincipalId;

// Step 2: Audit events targeting those confirmed agent identities only
AuditLogs
| where TimeGenerated > LookbackWindow
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend InitiatedByIPAddress = tostring(InitiatedBy.user.ipAddress)
| extend TargetResource = tostring(TargetResources[0].displayName)
| extend TargetResourceType = tostring(TargetResources[0].type)
| where OperationName in (
    "Add application",
    "Add service principal",
    "Update application – Certificates and secrets management",
    "Add application credentials",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Consent to application",
    "Add member to role",
    "Add eligible member to role"
)
// Step 3: Only keep events where target is a confirmed AI agent
| join kind=inner KnownAgents on $left.TargetResource == $right.ServicePrincipalName
| extend EventRisk = case(
    OperationName has "credentials" or OperationName has "credential", "Critical – New Credential on Agent",
    OperationName has "role assignment", "High – Role Assigned to Agent",
    OperationName has "Add member to role" or OperationName has "eligible member", "High – Entra Role Granted to Agent",
    OperationName has "Consent", "High – Admin Consent Granted to Agent",
    OperationName has "delegated", "Medium – Delegated Permission Added to Agent",
    OperationName has "Add application" or OperationName has "Add service principal", "Medium – New Agent Identity Registered",
    "Low")
| extend Initiator = case(
    isnotempty(InitiatedByUser), InitiatedByUser,
    isnotempty(InitiatedByApp), strcat("App: ", InitiatedByApp),
    "Unknown")
| project
    TimeGenerated,
    EventRisk,
    OperationName,
    AgentType,
    TargetResource,
    Initiator,
    InitiatedByIPAddress,
    Result,
    ResultDescription,
    LoggedByService,
    CorrelationId
| sort by EventRisk asc, TimeGenerated desc
```

---

## Query 2 — Net-New Agent Creation (No Prior History Required)

The main query misses brand new agents that have never signed in before (they won't be in `KnownAgents` yet). This query catches those — any new application or service principal registration that is immediately followed by permission grants, a strong signal of rogue agent deployment.

```kql
let LookbackWindow = ago(7d);

// Find new app/SPN registrations
let NewRegistrations =
    AuditLogs
    | where TimeGenerated > LookbackWindow
    | where OperationName in ("Add application", "Add service principal")
    | extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
    | extend NewAppName = tostring(TargetResources[0].displayName)
    | project
        RegistrationTime = TimeGenerated,
        NewAppName,
        InitiatedByUser,
        CorrelationId;

// Find permission grants or credential additions after registration
let PostRegistrationActivity =
    AuditLogs
    | where TimeGenerated > LookbackWindow
    | where OperationName in (
        "Add application credentials",
        "Add app role assignment to service principal",
        "Consent to application",
        "Add member to role"
    )
    | extend TargetApp = tostring(TargetResources[0].displayName)
    | extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
    | project
        ActivityTime = TimeGenerated,
        OperationName,
        TargetApp,
        InitiatedByUser;

// Join: new registration followed by suspicious activity within 1 hour
NewRegistrations
| join kind=inner PostRegistrationActivity on $left.NewAppName == $right.TargetApp
| where (ActivityTime - RegistrationTime) between (0min .. 60min)
| project
    RegistrationTime,
    ActivityTime,
    NewAppName,
    InitiatedByUser,
    OperationName
| sort by RegistrationTime desc
```

---

## Query 3 — After-Hours Lifecycle Events on Agent Identities

Legitimate agent deployments happen during business hours with change tickets. After-hours changes to agent identities are high-risk.

```kql
let LookbackWindow = ago(7d);
let AgentHistoryWindow = ago(30d);
let BusinessHourStart = 8;
let BusinessHourEnd = 18;

let KnownAgents =
    AADServicePrincipalSignInLogs
    | where TimeGenerated > AgentHistoryWindow
    | extend AgentInfo = todynamic(Agent)
    | where isnotempty(Agent)
    | where AgentInfo.agentType in ("agenticAppInstance", "agentIdentityBlueprintPrincipal")
    | summarize by ServicePrincipalName;

AuditLogs
| where TimeGenerated > LookbackWindow
| extend HourOfDay = datetime_part("Hour", TimeGenerated)
| where HourOfDay < BusinessHourStart or HourOfDay >= BusinessHourEnd
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetResource = tostring(TargetResources[0].displayName)
| where OperationName in (
    "Add application credentials",
    "Add app role assignment to service principal",
    "Consent to application",
    "Add member to role"
)
| join kind=inner KnownAgents on $left.TargetResource == $right.ServicePrincipalName
| project
    TimeGenerated,
    HourOfDay,
    OperationName,
    TargetResource,
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    Result
| sort by TimeGenerated desc
```

---

## Columns Explained
| Column | Description |
|--------|-------------|
| EventRisk | Risk classification specific to the AI agent context |
| AgentType | Blueprint principal or Agent Instance |
| TargetResource | The AI agent identity that was modified |
| Initiator | Who performed the action — user UPN or app name |
| InitiatedByIPAddress | Source IP of the person who made the change |
| LoggedByService | Which Microsoft service recorded the event |
| ResultDescription | Detail on why an operation failed |

---

## Use Cases

**UC1 — Rogue agent deployment detection**
Query 2 catches a new agent registered and immediately granted permissions within the same hour — a pattern consistent with an attacker deploying a backdoor agent identity outside normal change processes.

**UC2 — Credential harvesting on existing agents**
A critical signal: someone adds a new client secret or certificate to an existing agent. The original owner may not know. The agent's token can now be generated by whoever added the credential — full impersonation.

**UC3 — Privilege escalation via agent identity**
Attacker gains access to an agent SPN and assigns it an Entra role (e.g. Global Reader, Security Reader). The agent now has elevated access beyond its original design — and it blends in as automation traffic.

**UC4 — Admin consent abuse**
"Consent to application" on an agent SPN grants it tenant-wide API permissions. If done by a non-admin or outside a change window, this is a persistence mechanism — the agent can now access resources across the tenant silently.

**UC5 — After-hours changes (Query 3)**
Legitimate agent lifecycle changes happen during business hours with change tickets. Any credential addition, role grant, or permission consent outside business hours on an agent identity should trigger immediate investigation.

**UC6 — Insider threat visibility**
The `Initiator` column shows exactly who made each change. Combined with `InitiatedByIPAddress`, you can identify whether the action came from a corporate IP, a personal device, or an unexpected geography.
