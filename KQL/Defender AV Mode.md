<h2>🛡️ Defender AV Mode (Active / Passive / EDR Blocked) – With Missing-Data Explanation</h2>

<p>
This KQL reports the Microsoft Defender Antivirus mode using TVM assessment data (<code>DeviceTvmSecureConfigurationAssessment</code>),
specifically <code>ConfigurationId = "scid-2010"</code>. It also explains why <code>AVMode</code> can be blank (for example: non-Windows
devices or missing TVM assessment rows).
</p>

<h3>✅ KQL Query</h3>

<pre><code class="language-kql">let AVModeTable =
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2010" and isnotnull(Context)
| summarize arg_max(Timestamp, *) by DeviceId
| extend avdata = parse_json(Context)
| extend AVModeCode = tostring(avdata[0][0])
| extend AVMode =
    case(
        AVModeCode == "0", "Active",
        AVModeCode == "1", "Passive",
        AVModeCode == "4", "EDR Blocked",
        "Unknown"
    )
| project DeviceId, AVMode, AVModeCode, AVModeTimestamp=Timestamp;
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| extend IsWindows = OSPlatform startswith "Windows"
| join kind=leftouter AVModeTable on DeviceId
| extend AVModeFinal =
    case(
        IsWindows == false, "N/A (Non-Windows)",
        isnull(AVMode),     "No scid-2010 data",
        AVMode
    )
| extend AVModeReason =
    case(
        IsWindows == false, "This device is not Windows; Defender AV mode is not reported here.",
        isnull(AVMode),     "No TVM scid-2010 assessment row found for this device.",
        "Reported by TVM assessment (scid-2010)."
    )
| project DeviceName, OSPlatform, ClientVersion,
          AVModeFinal, AVModeCode, AVModeTimestamp,
          AVModeReason, Timestamp
| order by OSPlatform asc, DeviceName asc</code></pre>

<h3>🧠 Notes</h3>
<ul>
  <li><b>AVModeFinal = N/A (Non-Windows)</b>: expected for Linux/macOS endpoints since “Defender AV mode” is a Windows Defender Antivirus concept.</li>
  <li><b>AVModeFinal = No scid-2010 data</b>: the device has no <code>scid-2010</code> TVM assessment record (TVM data not present/not applicable).</li>
  <li><b>AVModeFinal = Active/Passive/EDR Blocked</b>: mode mapped from <code>scid-2010</code> context values (commonly used Advanced Hunting pattern).</li>
</ul>

<h3>🔎 Quick Sanity Check (Do we have scid-2010 at all?)</h3>

<pre><code class="language-kql">DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2010"
| summarize DevicesWithData=dcount(DeviceId)</code></pre>

<h4>🔎 Devices Missing scid-2010 (No AV Mode Data)</h3>

<p>
This query returns the <b>exact machines</b> that do <b>not</b> have a <code>DeviceTvmSecureConfigurationAssessment</code> record
for <code>ConfigurationId = "scid-2010"</code>. These devices will not show AV mode (Active/Passive/EDR Blocked) using the standard
TVM-based AVMode query.
</p>

<pre><code class="language-kql">let DevicesWithScid2010 =
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2010"
| summarize by DeviceId;
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| join kind=leftanti DevicesWithScid2010 on DeviceId
| project DeviceName, OSPlatform, ClientVersion, LastDeviceInfoSeen=Timestamp
| order by OSPlatform asc, DeviceName asc</code></pre>

<p><b>Notes:</b></p>
<ul>
  <li><b>Non-Windows</b> devices (Linux/macOS) may commonly appear here since “Defender AV mode” is a Windows Defender Antivirus concept.</li>
  <li>If <b>Windows</b> devices appear here, it typically means the TVM assessment row for <code>scid-2010</code> is not present for those devices.</li>
</ul>
