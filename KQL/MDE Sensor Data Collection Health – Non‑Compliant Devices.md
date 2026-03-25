<h1>🛑 Sensor Data Collection – Non‑Compliant Devices (KQL)</h1>

<p>
This <strong>KQL query</strong> identifies all devices where <strong>Sensor Data Collection is NOT compliant</strong>.
These devices are failing to collect or send critical <strong>Microsoft Defender XDR</strong> telemetry such as:
</p>

<ul>
  <li>Process events</li>
  <li>Network events</li>
  <li>System signals</li>
  <li>Behavioral indicators</li>
</ul>

<p>
<strong>Sensor Data Collection</strong> is one of the most critical Defender configuration checks because it determines
whether devices are providing the data required by <strong>Microsoft Defender XDR</strong> and
<strong>Microsoft Sentinel</strong> for detection, correlation, and investigation.
</p>

<hr/>

<h2>✅ How This KQL Helps SOC &amp; Security Teams</h2>

<h3>1️⃣ Reveals Visibility Blind Spots</h3>
<p>
Devices with Sensor Data Collection disabled or broken become invisible to XDR and Sentinel for key signals.
This query immediately highlights endpoints that represent <strong>telemetry blind spots</strong>.
</p>

<h3>2️⃣ Improves Detection Coverage</h3>
<p>
Without telemetry, devices cannot trigger behavioral detections — allowing threats to hide.
This query enables the SOC to prioritize remediation and restore full detection capability.
</p>

<h3>3️⃣ Ensures Investigations Are Complete</h3>
<p>
Missing telemetry leads to incomplete investigations, including:
</p>

<ul>
  <li>No process tree</li>
  <li>No lateral movement visibility</li>
  <li>Missing network data</li>
  <li>No behavioral evidence</li>
</ul>

<p>
This query identifies devices that would cause misleading or incomplete investigations.
</p>

<h3>4️⃣ Proactive Health Monitoring</h3>
<p>
The SOC can run this query regularly to:
</p>

<ul>
  <li>Maintain device telemetry health</li>
  <li>Detect configuration drift</li>
  <li>Catch onboarding failures early</li>
  <li>Ensure endpoint compliance before incidents occur</li>
</ul>

<h3>5️⃣ Cross‑Correlation With Alerts</h3>
<p>
By joining this dataset with <code>AlertInfo</code>, <code>DeviceEvents</code>, or Sentinel incidents, the SOC can identify:
</p>

<ul>
  <li>Alerts generated on devices with broken telemetry</li>
  <li>Suspicious activity where the sensor was not functioning</li>
</ul>

<p>
This is critical for validating whether the SOC has the <strong>full investigative picture</strong>.
</p>

<hr/>

<h2>✅ Understanding <code>ActionType</code></h2>

<p>
<strong>ActionType does NOT represent missing telemetry.</strong>
</p>

<p>
Instead, <code>ActionType</code> shows the <strong>security events that were successfully collected</strong>, even if the sensor is partially broken.
</p>

<p><strong>Examples:</strong></p>
<ul>
  <li>ProcessCreation</li>
  <li>NetworkConnection</li>
  <li>FileCreated</li>
  <li>MalwareDetected</li>
  <li>SmartScreenUrlWarning</li>
</ul>

<p>
These indicate <strong>what data you still have</strong>, not what is missing.
</p>

<hr/>

<h2>❗ What Telemetry Is Missing?</h2>

<p>
When <code>IsCompliant = false</code>, some or many of the following may be missing:
</p>

<ul>
  <li>Process events</li>
  <li>Network flow events</li>
  <li>Behavior events</li>
  <li>Identity signals</li>
  <li>EDR correlation artifacts</li>
</ul>

<p>
Defender does not expose a list of exactly which events are missing.
Instead, <strong>SCID‑2001</strong> indicates:
</p>

<blockquote>
“This device is not sending all telemetry required for full detection and investigation.”
</blockquote>

<p>
The KQL query shows the <strong>last known telemetry that DID arrive</strong> — not the telemetry that is missing.
</p>

<hr/>

<h2>🧠 Telemetry Health Indicators</h2>

<ul>
  <li><strong>MissingProcess</strong> – Loss of execution visibility (malware, LOLBins, ransomware)</li>
  <li><strong>MissingNetwork</strong> – No C2, exfiltration, or lateral movement detection</li>
  <li><strong>MissingFile</strong> – No visibility into file drops or encryption activity</li>
  <li><strong>MissingLogon</strong> – Identity attacks become invisible</li>
  <li><strong>MissingHeartbeat</strong> – Device may be offline, stale, or broken</li>
</ul>

<hr/>

<h2>🧠 KQL Query</h2>

<pre><code>
let TimeRange = 30d;

// === Devices where Sensor Data Collection is NOT compliant ===
let sensorBad =
    DeviceTvmSecureConfigurationAssessment
    | where Timestamp > ago(TimeRange)
    | where ConfigurationId == "scid-2001"
    | summarize arg_max(Timestamp, *) by DeviceId
    | where IsCompliant == false
    | project DeviceId, DeviceName, IsCompliant;

let proc = DeviceProcessEvents | where Timestamp > ago(TimeRange) | summarize hasProcess = count() by DeviceId;
let net  = DeviceNetworkEvents | where Timestamp > ago(TimeRange) | summarize hasNetwork = count() by DeviceId;
let file = DeviceFileEvents    | where Timestamp > ago(TimeRange) | summarize hasFile = count() by DeviceId;
let logon= DeviceLogonEvents   | where Timestamp > ago(TimeRange) | summarize hasLogon = count() by DeviceId;
let reg  = DeviceRegistryEvents| where Timestamp > ago(TimeRange) | summarize hasRegistry = count() by DeviceId;
let img  = DeviceImageLoadEvents| where Timestamp > ago(TimeRange) | summarize hasImageLoad = count() by DeviceId;
let dns  = DeviceNetworkInfo   | where Timestamp > ago(TimeRange) | summarize hasDNS = count() by DeviceId;
let hb   = DeviceInfo          | where Timestamp > ago(TimeRange) | summarize hasHeartbeat = count() by DeviceId;

sensorBad
| join kind=leftouter proc on DeviceId
| join kind=leftouter net on DeviceId
| join kind=leftouter file on DeviceId
| join kind=leftouter logon on DeviceId
| join kind=leftouter reg on DeviceId
| join kind=leftouter img on DeviceId
| join kind=leftouter dns on DeviceId
| join kind=leftouter hb on DeviceId
| extend
    MissingProcess   = iff(coalesce(hasProcess, 0) == 0, "Missing", "OK"),
    MissingNetwork   = iff(coalesce(hasNetwork, 0) == 0, "Missing", "OK"),
    MissingFile      = iff(coalesce(hasFile, 0) == 0, "Missing", "OK"),
    MissingLogon     = iff(coalesce(hasLogon, 0) == 0, "Missing", "OK"),
    MissingRegistry  = iff(coalesce(hasRegistry, 0) == 0, "Missing", "OK"),
    MissingImageLoad = iff(coalesce(hasImageLoad, 0) == 0, "Missing", "OK"),
    MissingDNS       = iff(coalesce(hasDNS, 0) == 0, "Missing", "OK"),
    MissingHeartbeat = iff(coalesce(hasHeartbeat, 0) == 0, "Missing", "OK")
| project DeviceName, DeviceId, IsCompliant,
          MissingProcess, MissingNetwork, MissingFile, MissingLogon,
          MissingRegistry, MissingImageLoad, MissingDNS, MissingHeartbeat
| sort by DeviceName asc
</code></pre>

<p>
📘 <a href="https://learn.microsoft.com/en-us/defender-endpoint/linux-support-events" target="_blank">
Troubleshoot missing events or alerts issues for Microsoft Defender for Endpoint on Linux
</a>
</p>
