<h2>🧠 Promptbook 2 — IRM Insider Threat Escalation</h2>

<p><strong>🎯 Use Case:</strong><br>
Identify and escalate high-risk insider threats using Microsoft Purview Insider Risk Management and Microsoft Security Copilot.
</p>

<hr>

<h3>📘 Promptbook Flow</h3>

<h4>🔹 Step 1 — Alert Summary</h4>
<pre><code class="language-text">
Summarize the Insider Risk alert &lt;AlertID&gt; including risky activities timeline.
</code></pre>

<h4>🔹 Step 2 — File Access Investigation</h4>
<pre><code class="language-text">
Show me all files accessed, shared, or downloaded by this user in the last 5 days.
</code></pre>

<h4>🔹 Step 3 — Data Exfiltration Detection</h4>
<pre><code class="language-text">
Did the user attempt any data exfiltration such as:
• external sharing
• USB copy
• cloud upload
after accessing sensitive files?
</code></pre>

<h4>🔹 Step 4 — Correlate with DLP Signals</h4>
<pre><code class="language-text">
Correlate this IRM alert with any Microsoft Purview DLP alerts related to the same user.
</code></pre>

<h4>🔹 Step 5 — Risk‑Based Escalation</h4>
<pre><code class="language-text">
Provide an insider risk severity score and recommend:
• Monitor
• Investigate
• Escalate to Legal/HR
</code></pre>

<hr>

<h3>✅ Expected Outcome</h3>
<ul>
<li>Identify malicious insider behavior</li>
<li>Correlate user risk across IRM and DLP</li>
<li>Detect potential data exfiltration attempts</li>
<li>Support evidence‑based escalation decisions</li>
<li>Improve insider threat investigation workflow</li>
</ul>

<hr>

<h3>📌 Operational Value</h3>
<p>
This promptbook enables Security Copilot to assist analysts in investigating Insider Risk Management alerts by correlating user activities, identifying risky behavioral patterns, and recommending appropriate escalation actions.
</p>
