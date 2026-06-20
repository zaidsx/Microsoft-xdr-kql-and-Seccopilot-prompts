# Attachment-Based Threats

## Overview
Detects emails carrying malicious attachments (malware, exploits) that were delivered or attempted in the last 7 days. Correlates with Safe Attachments verdicts to identify policy gaps.

## KQL Query

```kql
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where ThreatTypes has_any ("Malware", "Exploit")
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(7d)
    | project NetworkMessageId, RecipientEmailAddress, DeliveryAction, SenderFromAddress
) on NetworkMessageId
| summarize
    MaliciousAttachments = count(),
    AffectedUsers = dcount(RecipientEmailAddress),
    DeliveredCount = countif(DeliveryAction == "Delivered"),
    FileNames = make_set(FileName, 5),
    FileTypes = make_set(FileType, 5)
    by SenderFromAddress, ThreatTypes
| sort by DeliveredCount desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| SenderFromAddress | Sender of the malicious attachment |
| ThreatTypes | Malware, Exploit, etc. |
| MaliciousAttachments | Total flagged attachments |
| DeliveredCount | How many reached the mailbox (policy gap indicator) |
| FileNames / FileTypes | Sample filenames and extensions |

## Use Cases
- Spot malicious attachment campaigns targeting your org
- Identify file types slipping through Safe Attachments
- Correlate with endpoint telemetry to check if attachments were opened
