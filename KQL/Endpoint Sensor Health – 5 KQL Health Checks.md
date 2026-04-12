<h2>🩺 Endpoint Sensor Health – 5 KQL Health Checks (MDE / Defender XDR)</h2>

<p>
These queries help validate endpoint sensor health beyond “Last Seen”, by checking telemetry freshness and completeness.
This aligns with the SOC need to detect <b>telemetry blind spots</b> (devices that stop sending critical signals like process/network events). 
</p>

<hr>

<h3>1) ⏱️ Telemetry Freshness (Device Heartbeat / Last Seen)</h3>
<p>
Measures how long ago the device last updated its <code>DeviceInfo</code> record (high-level telemetry freshness).
</p>

<pre><code class="language-kql">DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| extend TelemetryLatencyMinutes = toint((now() - Timestamp) / 1m)
| extend LatencyBucket =
    case(
        TelemetryLatencyMinutes &lt;= 15,  "0-15m",
        TelemetryLatencyMinutes &lt;= 60,  "15-60m",
        TelemetryLatencyMinutes &lt;= 240, "1-4h",
        TelemetryLatencyMinutes &lt;= 1440,"4-24h",
        "24h+"
    )
| summarize Devices=dcount(DeviceId) by LatencyBucket
| order by Devices desc</code></pre>

<p><b>Why it matters:</b> Aged heartbeats indicate devices that may be offline or not communicating with Defender services.</p>

<hr>

<h3>2) 🧩 Telemetry Completeness (Process Signals)</h3>
<p>
Checks whether endpoints are actively sending <b>process telemetry</b> (one of the most critical EDR data sources).
</p>

<pre><code class="language-kql">DeviceProcessEvents
| summarize LastProcessEvent=max(Timestamp) by DeviceId, DeviceName
| extend ProcessTelemetryLatencyHours = (now() - LastProcessEvent) / 1h
| where ProcessTelemetryLatencyHours &gt; 4
| project DeviceName, DeviceId, LastProcessEvent, ProcessTelemetryLatencyHours
| order by ProcessTelemetryLatencyHours desc</code></pre>

<p><b>Interpretation:</b> Devices showing high latency here may be onboarded but effectively “blind” for EDR investigations.</p>

<hr>

<h3>3) 🌐 Telemetry Completeness (Network Signals)</h3>
<p>
Checks whether endpoints are actively sending <b>network telemetry</b> (critical for lateral movement, C2, beaconing visibility).
</p>

<pre><code class="language-kql">DeviceNetworkEvents
| summarize LastNetworkEvent=max(Timestamp) by DeviceId, DeviceName
| extend NetworkTelemetryLatencyHours = (now() - LastNetworkEvent) / 1h
| where NetworkTelemetryLatencyHours &gt; 4
| project DeviceName, DeviceId, LastNetworkEvent, NetworkTelemetryLatencyHours
| order by NetworkTelemetryLatencyHours desc</code></pre>

<p><b>Interpretation:</b> A device can appear “present” but still miss network visibility if these events stop flowing.</p>

<hr>

<h3>4) 🛡️ Security Engine / Protection Baseline (Configuration Compliance)</h3>
<p>
Validates whether key security configuration signals are compliant using Defender VM / Secure Configuration tables.
(<i>Note: choose the ConfigurationId(s) relevant to your org baseline.</i>)
</p>

<pre><code class="language-kql">DeviceTvmSecureConfigurationAssessment
| where Timestamp &gt; ago(7d)
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| summarize NonCompliant=countif(IsCompliant == false),
           Compliant=countif(IsCompliant == true)
           by ConfigurationId
| order by NonCompliant desc</code></pre>

<p><b>Tip:</b> Use this to track protection posture drift (e.g., real-time protection off, tamper protections, etc.)</p>

<hr>

<h3>5) 🧍 Device Activity Check (Recent Logons / Device “Alive” Signal)</h3>
<p>
Helps differentiate <b>device offline</b> vs <b>sensor issue</b> by checking last user/device logon activity.
</p>

<pre><code class="language-kql">DeviceLogonEvents
| summarize LastLogon=max(Timestamp) by DeviceId, DeviceName
| extend DeviceIdleHours = (now() - LastLogon) / 1h
| where DeviceIdleHours &gt; 24
| project DeviceName, DeviceId, LastLogon, DeviceIdleHours
| order by DeviceIdleHours desc</code></pre>

<p><b>Interpretation:</b></p>
<ul>
  <li>If <b>Logon is recent</b> but <b>Process/Network telemetry is old</b> → likely a <b>sensor/telemetry issue</b>.</li>
  <li>If <b>Logon is old</b> and telemetry is old → device may be <b>offline</b> or inactive.</li>
</ul>

<hr>

<h3>🧠 Important Architecture Insight (Very Important)</h3>
<p>This “latency” is <b>NOT</b>:</p>
<ul>
  <li>❌ Network latency</li>
  <li>❌ Event ingestion delay</li>
  <li>❌ Alert processing time</li>
</ul>
<p>
It is a measurement of <b>telemetry freshness</b> and whether the endpoint is still producing and sending security signals.
This is exactly how you detect <b>visibility blind spots</b> across endpoint telemetry (process, network, system signals). 
</p>
