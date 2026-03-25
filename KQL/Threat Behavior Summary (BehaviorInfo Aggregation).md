# 🔍 Threat Landscape Overview – KQL Query

This **KQL query** provides a high‑level **threat landscape overview** by aggregating behavioral security signals across **Microsoft Defender XDR** and **Microsoft Sentinel**.

It analyzes data from the `BehaviorInfo` table and summarizes threat‑related metadata such as:

- Action types  
- Behavior categories  
- MITRE ATT&CK techniques  
- Detection and service sources  
- First and last observed timestamps  

By grouping and counting these behaviors, the query helps security teams quickly identify:

- 🔥 **Which threat actions occur most frequently**
- 🧭 **Which behavior categories are most active**
- 🕒 **When suspicious or malicious behavior was first and last seen**
- 🎯 **Relevant attack techniques and descriptions to understand attacker intent**

This delivers an immediate snapshot of your current threat landscape and ongoing attacker activity.

---

## 🎯 How This Helps Your Security Team

### 1️⃣ Threat Landscape Awareness
The query provides a clear view of which malicious or suspicious behaviors are most common in your environment.

Instead of reviewing raw logs, analysts get an aggregated view of real activity across:
- Devices  
- Identities  
- Email  
- Cloud workloads  

---

### 2️⃣ Faster Investigation & Triage
Because the query pulls example descriptions and attack techniques, analysts immediately understand:

- What the behavior represents  
- Which MITRE ATT&CK techniques it aligns with  
- Whether it relates to credential abuse, lateral movement, persistence, or exfiltration  

This provides instant context without drilling into individual events.

---

### 3️⃣ Cross‑Source Correlation (XDR + Sentinel)
The query includes `ServiceSource` and `DetectionSource`, allowing analysts to identify whether signals originate from:

- Microsoft Defender for Cloud Apps  
- Microsoft Sentinel Analytics Rules  
- Microsoft Sentinel UEBA behaviors  

This makes it easier to detect multi‑vector attacks and correlate activity across security products.

---

### 4️⃣ Realistic Threat Scenarios
By showing **first and last seen timestamps** along with **attack technique examples**, the query supports scenario‑based investigation:

- Is this a one‑time event or recurring behavior?  
- Is the attacker escalating activity?  
- Is this technique part of a broader kill chain?  
- Is the tactic common across affected devices or identities?  

This helps teams understand attacker behavior and technique progression.

---

### 5️⃣ Prioritization Through Sorting
Sorting by **ThreatCount (descending)** ensures the SOC focuses on the most frequent and impactful threats first.

---

## 🧠 KQL Query

```kql
BehaviorInfo
| where isnotempty(ActionType) and isnotempty(Categories)
| summarize
    ThreatCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    ExampleDescription = any(Description),
    ExampleAttackTechniques = any(AttackTechniques)
    by ActionType, tostring(Categories), ServiceSource, DetectionSource
| extend
    ThreatType = ActionType,
    ThreatCategory = tostring(Categories),
    Source = ServiceSource,
    Detection = DetectionSource
| project
    ThreatType,
    ThreatCategory,
    ThreatCount,
    FirstSeen,
    LastSeen,
    Source,
    Detection,
    ExampleAttackTechniques,
    ExampleDescription
| sort by ThreatCount desc
