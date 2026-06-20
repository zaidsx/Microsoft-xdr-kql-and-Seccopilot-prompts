# Phishing Email Delivery Summary

## Overview
Surfaces phishing emails that were successfully delivered to mailboxes in the last 7 days, including sender, recipient, subject, and delivery action. Helps SOC teams identify users who received malicious mail before policies caught it.

## KQL Query

```kql
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| summarize
    PhishingEmails = count(),
    AffectedUsers = dcount(RecipientEmailAddress),
    Example_Subjects = make_set(Subject, 5)
    by SenderFromAddress, DeliveryLocation, ThreatTypes
| sort by PhishingEmails desc
```

## Columns Explained
| Column | Description |
|--------|-------------|
| SenderFromAddress | The sender address of the phishing email |
| DeliveryLocation | Where the email landed (Inbox, Junk, etc.) |
| PhishingEmails | Count of phishing emails from that sender |
| AffectedUsers | Unique recipients targeted |
| Example_Subjects | Sample subject lines for triage |

## Use Cases
- Identify repeat phishing senders evading filters
- Find users who received phish in their Inbox (highest risk)
- Feed into incident response for targeted user awareness
