# AI Agent XPIA Exposure Map (Indirect Prompt Injection)

## Overview
Maps every AI agent that meets the **structural precondition for indirect prompt injection (XPIA)**: it *reads untrusted external content* AND *can take an outbound or destructive action*. You can't easily detect the injection payload itself — but you can inventory every agent an attacker could weaponize by planting instructions in a document, web page, or email the agent ingests. An agent that reads the open web and can send email is a loaded gun; one that only summarizes internal docs is not.

**OWASP LLM Top 10:** LLM01 — Prompt Injection (indirect / XPIA)
**MITRE ATT&CK:** TA0001 — Initial Access | T1566 — Phishing (content-borne instructions)
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

Indirect prompt injection works like this: an attacker hides secret instructions inside something the agent will *read* — a web page, a shared document, an incoming email. The agent reads it, mistakes the hidden text for a real command, and obeys.

For that attack to do damage, two things must both be true:

1. **The agent reads stuff from outside** (the web, uploaded files, email) — that's how the poison gets in.
2. **The agent can actually do something** (send email, call a website, change data) — that's how the damage gets out.

An agent that only reads untrusted content but can't act = annoying, not dangerous. An agent that can act but only reads trusted internal data = hard to poison. It's the **combination** that's lethal.

This query lists every agent where **both are true** — your map of "who could be hijacked through what they read." Lock these down first.

**In one sentence:** *It finds agents that both read untrusted content and can take action — the ones an attacker can hijack by hiding commands in a document.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.
> - Tune `UntrustedSources` and `ActOps` to your tenant's knowledge sources and connector operation IDs.

## KQL Query

```kql
// Markers that an agent ingests untrusted / external content
let UntrustedSources = dynamic([
    "http", "www.", "public", "external", "web search",
    "website", "url", "internet", "rss", "feed"
]);
// Action types that let an agent reach out or change things
let ActOps = dynamic([
    "SendEmail", "SendEmailV2", "ForwardEmail", "HttpRequestAction",
    "PostMessage", "CreateItem", "UpdateItem", "DeleteItem", "RemoteMCPServer"
]);
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
| extend
    KnowledgeStr = tolower(tostring(KnowledgeDetails)),
    ToolsStr     = tostring(AgentToolsDetails),
    TopicsStr    = tostring(AgentTopicsDetails)
// 1) Does it read untrusted/external content?
| extend ReadsUntrusted =
        KnowledgeStr has_any (UntrustedSources)
        or ToolsStr  has "HttpRequestAction"
        or TopicsStr has "HttpRequestAction"
// 2) Can it take an outbound / destructive action?
| extend CanAct = ToolsStr has_any (ActOps) or TopicsStr has_any (ActOps)
| where ReadsUntrusted and CanAct
| extend Autonomous = IsGenerativeOrchestrationEnabled == true
| extend Exposed    = UserAuthenticationType == "None" or AccessControlPolicy == "Any"
| extend RiskLevel = case(
        Autonomous and Exposed, "Critical – Injectable, autonomous, and openly reachable",
        Autonomous,             "High – Reads untrusted content and can autonomously act",
        Exposed,                "High – Injectable and openly reachable",
        "Medium – Reads untrusted content and can act")
| project
    RiskLevel, AIAgentName, AIAgentId, ReadsUntrusted, CanAct, Autonomous, Exposed,
    UserAuthenticationType, AccessControlPolicy, KnowledgeDetails,
    AIModel, OwnerAccountUpns, RegistrySource
| sort by RiskLevel asc, AIAgentName asc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| `ReadsUntrusted` | Agent ingests web/external/uploaded content — the injection entry point |
| `CanAct` | Agent can send, call out, or modify data — the damage path |
| `Autonomous` | Generative orchestration makes the agent easier to steer |
| `Exposed` | Anonymously reachable, so anyone can feed it poisoned content |
| `KnowledgeDetails` | The actual sources to review for trustworthiness |
| `RiskLevel` | Severity from the read-untrusted + can-act combination |

## Risk Tiers
- 🔴 **Critical** — reads untrusted + can act + autonomous + openly reachable
- 🟠 **High** — autonomous, or openly reachable, on top of the read+act combo
- 🟡 **Medium** — the base read-untrusted + can-act precondition

## Response Actions
1. For each agent, review `KnowledgeDetails` — can you restrict it to trusted, internal sources only?
2. Where the agent must read external content, **constrain the actions** it can take (remove send/HTTP/delete, or require human approval).
3. Add a system prompt that explicitly tells the agent to ignore instructions embedded in retrieved content.
4. Tighten exposure (`UserAuthenticationType` / `AccessControlPolicy`) so untrusted users can't feed it directly.

## Related Detections
- AI Agent Autonomy Trifecta — agents that can act with no guardrails
- AI Agent Untrusted Tool Supply Chain — where the agent's tools reach out to
- AI Agent Knowledge & Model Drift — when a poisoning source gets added
