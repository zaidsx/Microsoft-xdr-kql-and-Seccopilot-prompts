<h2>🧠 Promptbook 1 — DLP Incident Risk Prioritization</h2>

<p><strong>🎯 Use Case:</strong><br>
Help the Data Security / Compliance Team decide which Microsoft Purview DLP alert represents a real data breach versus normal business activity using Microsoft Security Copilot.
</p>

<hr>

<h3>📘 Promptbook Flow</h3>

<h4>🔹 Step 1 — Identify High Priority Alerts</h4>
<pre><code class="language-text">
Which Microsoft Purview DLP alerts should I prioritize today based on sensitive data type and user risk score?
</code></pre>

<h4>🔹 Step 2 — Focus on Sensitive Labeled Data</h4>
<pre><code class="language-text">
Summarize the top 5 DLP alerts that involve labeled Confidential or Highly Confidential data.
</code></pre>

<h4>🔹 Step 3 — Understand Data Exposure</h4>
<pre><code class="language-text">
For Alert ID &lt;AlertID&gt;, identify:
• data involved
• destination
• external recipients
• device or endpoint used
</code></pre>

<h4>🔹 Step 4 — Check User Behavioral Pattern</h4>
<pre><code class="language-text">
Show me if the user involved in this alert has performed similar risky actions in the last 7 days.
</code></pre>

<h4>🔹 Step 5 — Classify the Incident</h4>
<pre><code class="language-text">
Based on the investigation, classify this alert as:
• Malicious Insider
• Accidental Data Leak
• Policy Misconfiguration

Provide reasoning for the classification.
</code></pre>

<hr>

<h3>✅ Expected Outcome</h3>
<ul>
<li>Reduce DLP alert fatigue</li>
<li>Prioritize real data exfiltration incidents</li>
<li>Improve SOC investigation efficiency</li>
<li>Enable risk-based compliance triage</li>
<li>Standardize DLP incident classification process</li>
</ul>

<hr>

<h3>📌 Operational Value</h3>
<p>
This promptbook enables Security Copilot to assist analysts in quickly summarizing, prioritizing, and classifying Microsoft Purview DLP alerts, allowing organizations to focus their investigation efforts on high-impact data exposure incidents.
</p>
