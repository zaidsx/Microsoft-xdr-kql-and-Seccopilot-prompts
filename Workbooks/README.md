# Export-ActivityExplorer

A PowerShell script for bulk-exporting **Microsoft Purview Activity Explorer** data (DLP rule matches, sensitivity label activity, Endpoint DLP device events, and more) to CSV.

It wraps the `Export-ActivityExplorerData` cmdlet from the ExchangeOnlineManagement module and adds the things that make a real-world export painless:

- **Exports every field by default** — nested objects (like `PolicyMatchInfo`) are automatically flattened into `Parent.Child` columns; arrays become compact JSON instead of `System.Object[]`.
- **Automatic paging** through unlimited result sets (the service caps each request at 5,000 records).
- **Retry with exponential backoff** and automatic session reconnection, so long exports survive throttling and transient errors.
- **Incremental writes** — each page is appended to the CSV immediately, so an interrupted run keeps everything fetched so far.
- **Handles the WAM "window handle" sign-in bug** (ExchangeOnlineManagement 3.7.0+) by retrying with `-DisableWAM`.
- **UTC → local time conversion** via an added `HappenedLocal` column.
- **PowerShell 5.1 and 7+ compatible.**

---

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement) module 3.2 or later:
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  ```
- An account with **Activity Explorer access** in Microsoft Purview (e.g. a role group containing *Data Classification List Viewer*, or Compliance Administrator-equivalent)
- Microsoft 365 E5 / E5 Compliance licensing (required for Activity Explorer data to exist)

---

## Quick start

```powershell
# Allow the script to run in this session if needed
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Export all DLP rule matches for a week (all columns, auto-discovered)
.\Export-ActivityExplorer.ps1 `
    -StartTime "06/01/2026" -EndTime "06/07/2026" `
    -Activities @("DLPRuleMatch") `
    -OutputCsv "DLPMatches_June.csv"
```

On first run it signs you in via `Connect-IPPSSession`. If you hit the WAM "window handle" error, the script retries automatically with `-DisableWAM`; you can also connect manually first:

```powershell
Connect-IPPSSession -DisableWAM
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-StartTime` | string | *(required)* | Start of window, e.g. `"06/01/2026"` or `"06/01/2026 08:00 AM"` (MM/dd/yyyy). Interpreted as **UTC** by the service. |
| `-EndTime` | string | *(required)* | End of window. Activity Explorer retains a maximum of **30 days**. |
| `-Activities` | string[] | all | One or more activity IDs (OR'ed). Case-sensitive exact matches. |
| `-Workload` | string[] | all | One or more of `Endpoint`, `Exchange`, `SharePoint`, `OneDrive`, `OnPremisesFileShareScanner`, `OnPremisesSharePointScanner`, `PowerBI`, `Copilot`, `PurviewDataMap` (OR'ed). |
| `-Filter3` / `-Filter4` / `-Filter5` | string[] | — | Extra filters in cmdlet format: field name first, then one or more values, e.g. `@("User","someone@contoso.com")`. Values OR'ed within a filter; filters AND'ed together. |
| `-Columns` | string[] | all columns | Custom column list (dot notation supported, e.g. `PolicyMatchInfo.PolicyName`). Omit to auto-export every field. |
| `-OutputCsv` | string | `ActivityExplorer_Export.csv` | Output file path. Overwritten at the start of each run. |
| `-PageSize` | int | 5000 | Records per request (1–5000). 5000 is the service maximum. |
| `-LocalTimeZone` | string | `Arab Standard Time` | Windows timezone ID for `HappenedLocal`. List IDs with `Get-TimeZone -ListAvailable`. |
| `-UserPrincipalName` | string | — | Pre-fills the sign-in account. |
| `-DeviceAuth` | switch | off | Forces device-code authentication. |

---

## Examples

### Endpoint DLP egress for a week

```powershell
.\Export-ActivityExplorer.ps1 `
    -StartTime "06/01/2026" -EndTime "06/07/2026" `
    -Activities @("FileUploadedToCloud","FileCopiedToRemovableMedia",
                  "FileTransferredByBluetooth","FilePrinted","LabelChanged") `
    -Workload "Endpoint" `
    -OutputCsv "EndpointDLP_June.csv"
```

### Multiple workloads at once

```powershell
.\Export-ActivityExplorer.ps1 `
    -StartTime "06/01/2026" -EndTime "06/07/2026" `
    -Workload @("SharePoint","OneDrive","Exchange") `
    -OutputCsv "Cloud_June.csv"
```

### Pick specific columns, including nested fields

```powershell
.\Export-ActivityExplorer.ps1 `
    -StartTime "06/01/2026" -EndTime "06/07/2026" `
    -Activities @("DLPRuleMatch") `
    -Columns @("HappenedLocal","Workload","ActivityId","User","ItemName",
               "PolicyMatchInfo.PolicyName","PolicyMatchInfo.RuleName") `
    -OutputCsv "DLP_Focused.csv"
```

### Extra filters (per-user, per-application, stacked)

```powershell
# All DLP matches by one user
.\Export-ActivityExplorer.ps1 `
    -StartTime "06/01/2026" -EndTime "06/07/2026" `
    -Activities @("DLPRuleMatch") `
    -Filter3 @("User","user@example.com") `
    -OutputCsv "User_DLP.csv"

# Stacked: one user's labeled Office-document egress
.\Export-ActivityExplorer.ps1 `
    -StartTime "06/01/2026" -EndTime "06/07/2026" `
    -Activities @("FileCopiedToRemovableMedia","FileUploadedToCloud") `
    -Workload "Endpoint" `
    -Filter3 @("User","user@example.com") `
    -Filter4 @("FileExtension","docx","xlsx","pdf") `
    -Filter5 @("SensitivityLabel","Confidential") `
    -OutputCsv "UserEgress_Labeled.csv"
```

### Discovery run (no filters — learn what your tenant emits)

```powershell
.\Export-ActivityExplorer.ps1 -StartTime "06/09/2026" -EndTime "06/10/2026"
```

---

## How columns work

**Default (no `-Columns`):** the script reads the first page of results, takes the union of all property names, and uses that as the CSV schema. Nested objects are expanded (`PolicyMatchInfo` → `PolicyMatchInfo.PolicyName`, `PolicyMatchInfo.RuleName`, …) and arrays are written as compact JSON. A `HappenedLocal` column is always added.

**Custom (`-Columns`):** pass exactly the columns you want, in order. Top-level field names work directly; nested fields use dot notation (`PolicyMatchInfo.PolicyName`). Columns that don't exist on a row come out empty, so mixing workload-specific fields is safe.

To discover available field names, run a discovery export and read the CSV header, or inspect one record manually:

```powershell
$res  = Export-ActivityExplorerData -StartTime "06/09/2026" -EndTime "06/10/2026" `
            -Filter1 @("Activity","DLPRuleMatch") -PageSize 100 -OutputFormat Json
($res.ResultData | ConvertFrom-Json)[0] | Format-List *
```

---

## Notes & limitations

- **Filter values are exact matches** — no wildcards or subnet ranges. For fuzzy matching (subnets, partial filenames), export without that filter and slice the CSV afterward with `Where-Object { $_.ClientIP -like "10.0.0.*" }`.
- **30-day retention:** Activity Explorer holds 30 days of data. Schedule recurring exports or forward events to Log Analytics/Sentinel for longer retention.
- **Times are UTC:** `-StartTime`/`-EndTime` are interpreted as UTC by the service. The `HappenedLocal` column converts each row to your chosen timezone.
- **Column schema is set from the first page.** For single-activity exports the schema is uniform; for large mixed exports where a field might appear only on later pages, run one export per activity type.
- **Output file is overwritten** each run — use unique names to keep history, and close the CSV in Excel before re-running (a lock causes a delete error).

---

## License

[MIT](LICENSE) — free to use, modify, and share.

## Contributing

Issues and pull requests welcome. This started as a practical tool for pulling Purview Activity Explorer data at scale; if you've extended it (new filters, output formats, scheduling wrappers), contributions that keep it simple and dependency-light are appreciated.

## Disclaimer

This is an independent, community-maintained script and is not affiliated with or endorsed by Microsoft. It uses supported Microsoft PowerShell cmdlets but is provided "as is" — test against a non-production tenant first.
