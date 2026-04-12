<h2>📊 MDE Telemetry Latency (DeviceInfo) – Bucketed View</h2>

<p>
This KQL measures <b>telemetry freshness</b> by calculating the time difference between <code>now()</code> and the latest
<code>DeviceInfo.Timestamp</code> per device. The output groups devices into latency buckets to help identify reporting gaps.
</p>

<h3>✅ KQL Query</h3>

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

<h3>🧠 Important Architecture Insight (Very Important)</h3>

<p>This latency is <b>NOT</b>:</p>

<ul>
  <li>❌ Network latency</li>
  <li>❌ Event ingestion delay</li>
  <li>❌ Alert processing time</li>
</ul>

<p>
This latency represents the time since the endpoint last successfully communicated with the
Microsoft Defender for Endpoint cloud service (sensor heartbeat / telemetry reporting).
</p>

<h3>📌 Interpretation of the Buckets</h3>

<ul>
  <li><b>0–15m</b>: ✅ Device is actively reporting telemetry (Healthy)</li>
  <li><b>15–60m</b>: ⚠️ Slight delay (Sleep / Low activity)</li>
  <li><b>1–4h</b>: 🚨 Sensor not actively communicating</li>
  <li><b>4–24h</b>: ❌ Likely offline / connectivity issue</li>
  <li><b>24h+</b>: 🔴 Telemetry loss (XDR blind spot)</li>
</ul>

<hr>

<h3>📈 Identify Risky Devices (Telemetry Latency &gt; 4 Hours)</h3>

<p>
Use the following query to list endpoints that are not actively reporting telemetry to the Defender cloud.
These devices may create visibility gaps in your Microsoft XDR coverage.
</p>

<pre><code class="language-kql">DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| extend TelemetryLatencyHours = (now() - Timestamp) / 1h
| where TelemetryLatencyHours &gt; 4
| project DeviceName, OSPlatform, ClientVersion, Timestamp, TelemetryLatencyHours
| order by TelemetryLatencyHours desc</code></pre>
