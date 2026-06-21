# AI Agent Autonomy Trifecta (Excessive Autonomy)

## Overview
Detects the single most dangerous AI-agent configuration that can exist: an agent that **decides for itself what to do** (generative orchestration), **can take destructive real-world actions** (send email, make HTTP calls, delete data), and **has no behavioral guardrails** (empty system prompt). Any one of these alone is manageable. All three together is an agent that can be talked into doing almost anything — the textbook definition of *excessive agency*.

**OWASP LLM Top 10:** LLM06 — Excessive Agency (excessive autonomy)
**MITRE ATT&CK:** TA0002 — Execution | T1648 — Serverless/Automated Execution
**Platform:** Microsoft Defender XDR — Advanced Hunting

---

## In Plain English

Think of an AI agent like an intern:

- **Generative orchestration** = the intern decides on their own how to get a task done, instead of following a fixed checklist.
- **Destructive tools** = the intern has the keys to send company emails, call outside services, and delete files.
- **No system prompt** = nobody gave the intern any rules or boundaries.

Each is fine on its own. But an intern who **improvises freely, holds dangerous keys, and was never told the rules** is an accident — or an attack — waiting to happen. Trick them once, and they'll do real damage with real tools.

This query finds agents where **all three are true at the same time**, and ranks anything close to that combination so you can lock it down before someone exploits it.

**In one sentence:** *It finds AI agents that can freely decide to do dangerous things with no rules holding them back.*

---

## Prerequisites
> - `AIAgentsInfo` populated by Defender for Cloud Apps (Power Platform) and/or Microsoft Agent 365.
> - Destructive-action detection inspects `AgentToolsDetails` and `AgentTopicsDetails` — tune the `DestructiveOps` list to your environment's connectors.

## KQL Query

```kql
// Action types that can cause real-world / destructive effects
let DestructiveOps = dynamic([
    "SendEmail", "SendEmailV2", "ForwardEmail",
    "HttpRequestAction", "RemoteMCPServer",
    "DeleteItem", "DeleteFile", "CreateItem", "UpdateItem",
    "PostMessage", "CreateEvent"
]);
AIAgentsInfo
| summarize arg_max(Timestamp, *) by AIAgentId
| where AgentStatus != "Deleted"
// 1) Does the agent decide its own actions?
| extend HasGenOrchestration =
        IsGenerativeOrchestrationEnabled == true
        or tostring(todynamic(RawAgentInfo).Bot.Attributes.configuration) has '"GenerativeActionsEnabled": true'
// 2) Does it have no behavioral guardrails?
| extend NoInstructions = isempty(Instructions) or Instructions == "N/A"
// 3) Can it take a destructive action?
| extend HasDestructiveTool =
        tostring(AgentToolsDetails)  has_any (DestructiveOps)
        or tostring(AgentTopicsDetails) has_any (DestructiveOps)
// Score the three pillars (+ exposure bonus)
| extend Pillars =
        toint(HasGenOrchestration) + toint(NoInstructions) + toint(HasDestructiveTool)
| extend Exposed =
        UserAuthenticationType == "None" or AccessControlPolicy == "Any"
| where HasDestructiveTool and Pillars >= 2     // destructive + at least one more pillar
| extend RiskLevel = case(
        Pillars == 3 and Exposed, "Critical – Full autonomy trifecta on an exposed agent",
        Pillars == 3,             "Critical – Autonomous, destructive, no guardrails",
        Pillars == 2 and Exposed, "High – Two pillars on an exposed agent",
        Pillars == 2,             "High – Two of three autonomy pillars present",
        "Medium")
| extend MissingControls = trim(", ", strcat(
        iff(NoInstructions,       "no system prompt, ", ""),
        iff(HasGenOrchestration,  "generative orchestration on, ", ""),
        iff(HasDestructiveTool,   "destructive tools present, ", ""),
        iff(Exposed,              "weak access control, ", "")))
| project
    RiskLevel, AIAgentName, AIAgentId, MissingControls,
    HasGenOrchestration, NoInstructions, HasDestructiveTool, Exposed,
    UserAuthenticationType, AccessControlPolicy, AIModel,
    OwnerAccountUpns, CreatorAccountUpn, AgentStatus, RegistrySource
| sort by RiskLevel asc, AIAgentName asc
```

## The Three Pillars
| Pillar | Column | Risk it adds |
|--------|--------|--------------|
| Autonomy | `IsGenerativeOrchestrationEnabled` | Agent improvises its own action plan |
| Capability | `AgentToolsDetails` / `AgentTopicsDetails` | Agent can send, call out, or delete |
| No guardrails | `Instructions` empty | No boundaries on behavior |
| (bonus) Exposure | `UserAuthenticationType` / `AccessControlPolicy` | Anyone can drive it |

## Risk Tiers
- 🔴 **Critical** — all three pillars (optionally + weak access control)
- 🟠 **High** — two pillars (destructive capability + one more)
- 🟡 **Medium** — destructive capability with a single additional weakness

## Response Actions
1. For Critical agents: add a constraining **system prompt** immediately and confirm the destructive tools are actually required.
2. If generative orchestration isn't needed for the use case, **disable it** — pin the agent to a fixed action flow.
3. Tighten `AccessControlPolicy` / `UserAuthenticationType` so the agent isn't anonymously reachable.
4. Confirm ownership (`OwnerAccountUpns`) and intended purpose with the owner.

## Tuning Notes
- `DestructiveOps` is the key tuning lever — add your tenant's specific connector operation IDs (e.g., custom HTTP/Power Automate actions).
- Drop the `Pillars >= 2` floor to `== 3` if you only want the strict trifecta and less noise.

## Related Detections
- AI Agent Guardrail Drift Detection — when these protections get removed over time
- AI Agent Over-Privileged Permissions — the permission facet of excessive agency
- AI Agent Excessive Tool Surface — the functionality facet of excessive agency
