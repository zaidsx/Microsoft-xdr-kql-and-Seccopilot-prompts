# Sentinel Cost Optimization Workbook

An **extension of the built-in "Microsoft Sentinel Cost" workbook** (`sentinel-SentinelCosts`) — not a replacement. It keeps every stock tile and adds two things on top: a **per-host / per-product ingestion breakdown** and a **cost-optimization** section. All read-only; every number is an estimate.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fzaidsx%2FMicrosoft-xdr-kql-and-Seccopilot-prompts%2Fmain%2FWorkbooks%2Fdeploy-sentinel-cost-workbook.json)

## Why this exists

The Sentinel bill jumps 30% one month. Finance asks why. You open the built-in cost workbook and it tells you `SecurityEvent` and `CommonSecurityLog` are your biggest tables — which you already knew. It doesn't tell you *which* of your 400 servers got chatty, or *which* firewall started shipping debug logs, or whether last week's spike was a one-off or your new normal. So you go write the KQL by hand, again, every time someone asks.

That's the gap. The stock workbook is great at *how much* but silent on *who* and *what changed* — the two questions you actually need to answer to bring the number back down.

This extension answers them: it breaks ingestion down to the individual host and appliance, flags the day something spiked, compares this period against the last, and models whether a commitment tier or a cheaper log plan would save money. Deploy it once and the next time the bill moves, the answer is already on screen.

## What it adds

**1. Per-host / per-product breakdown** (the main reason to use it)
The stock workbook shows cost *by table*. This shows cost *by host and appliance*, so you can see exactly what to tune:

- `SecurityEvent`, `Event`, `Syslog` — billable GB + cost per host
- `CommonSecurityLog` (CEF) — per vendor/product, drill down to each appliance
- `AzureDiagnostics` — per resource
- Daily trend chart of the top 10 noisiest hosts

**2. Cost optimization**
- Commitment tier recommendation (PAYG vs 100–5000 GB/day tiers)
- Log plan savings (Analytics vs Basic vs Auxiliary)
- Run-rate projection (full-month cost from your avg GB/day)
- Period-over-period change (what suddenly cost more)
- Ingestion spike detection

## Licensing note

The per-host tables aren't covered by the **M365 E5/A5/F5/G5** Sentinel grant. But `SecurityEvent` **is** covered by the **Defender for Servers Plan 2** benefit (500 MB/node/day), so its real cost may be lower than shown. `CommonSecurityLog` and `Syslog` aren't covered by either.

## Deploy

### Option A — Deploy to Azure button (easiest)

Click the button above. In the portal blade:
1. Pick your **subscription** and **resource group**.
2. Set **Workspace Resource Id** to your Log Analytics workspace ID
   (`/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>`).
3. Optionally change the **Workbook Display Name**.
4. **Review + create** → **Create**. The workbook lands in Sentinel → **Workbooks** → **My workbooks**.

> Uses `Workbooks/deploy-sentinel-cost-workbook.json` (an ARM template that embeds the workbook). The button won't work until that file is pushed to the repo.

### Option B — Advanced Editor (no ARM, quickest for testing)

Sentinel → **Workbooks** → **+ New** → open the Advanced Editor (`</>`) → paste the contents of `sentinel-cost-optimization-workbook.json` → **Apply** → **Save**.

### Option C — Azure CLI

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file Workbooks/deploy-sentinel-cost-workbook.json \
  --parameters workspaceResourceId="/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>"
```

## Key parameters

| Parameter | Default | Notes |
| --- | --- | --- |
| `Price` | 4 | Analytics ingestion $/GB — set to your rate |
| `TotalE5Seats` | 0 | E5/A5/F5/G5 seats (enables the grant tiles) |
| `BasicLogsPrice` / `AuxLogsPrice` | 0.65 / 0.15 | For log-plan savings |

Prices are placeholders — match your region and agreement, and validate tiers against the [Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/).

## Files

| File | Purpose |
| --- | --- |
| `sentinel-cost-optimization-workbook.json` | The workbook definition (use with Option B). |
| `deploy-sentinel-cost-workbook.json` | ARM template wrapping the workbook (used by the button + Option C). |
| `README.md` | This file. |
