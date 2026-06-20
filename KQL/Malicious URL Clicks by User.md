# Malicious URL Clicks by User

## Overview
Identifies users who clicked on URLs flagged as malicious by Defender for Office 365 Safe Links. Prioritizes by click count and verdict to highlight highest-risk users for immediate follow-up.

## KQL Query

```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType in ("ClickBlocked", "ClickAllowed")
| where ThreatTypes has_any ("Phish", "Malware")
| summarize
    TotalClicks = count(),
    BlockedClicks = countif(ActionType == "ClickBlocked"),
    AllowedClicks = countif(ActionType == "ClickAllowed"),
    Urls = make_set(Url, 5)
    by AccountUpn, NetworkMessageId
| sort by AllowedClicks desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| AccountUpn | User who clicked the URL |
| TotalClicks | Total malicious URL clicks |
| BlockedClicks | Clicks Safe Links blocked |
| AllowedClicks | Clicks that went through (highest risk) |
| Urls | Sample malicious URLs clicked |

## Use Cases
- Identify users who bypassed Safe Links (AllowedClicks > 0)
- Prioritize users for immediate password reset or session revocation
- Track which URLs are most clicked for threat intel
