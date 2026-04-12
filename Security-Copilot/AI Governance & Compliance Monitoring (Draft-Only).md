<h2>🧠 Promptbook 3 — AI Governance &amp; Compliance Monitoring</h2>

<p><strong>🎯 Use Case:</strong><br>
Enable SOC and Compliance teams to audit how AI agents interact with enterprise data using Microsoft Security Copilot.
</p>

<hr>

<h3>🔌 Required Security Copilot Plugins</h3>

<pre><code class="language-text">
Microsoft Purview DSPM for AI Plugin
Microsoft Purview Insider Risk Management Plugin
Microsoft Purview DLP Plugin
</code></pre>

<p>
These plugins are required to monitor AI interactions, detect policy violations, and correlate AI usage activity with Insider Risk and DLP signals.
</p>

<hr>

<h3>📘 Promptbook Flow</h3>

<h4>🔹 Step 1 — AI Interaction Summary</h4>
<pre><code class="language-text">
Summarize all AI agent interactions recorded in audit logs over the past 7 days.
</code></pre>

<h4>🔹 Step 2 — Sensitive Data Detection</h4>
<pre><code class="language-text">
Identify any interactions involving files with applied sensitivity labels.
</code></pre>

<h4>🔹 Step 3 — Policy Violation Monitoring</h4>
<pre><code class="language-text">
Show any AI interactions that triggered DLP policy violations.
</code></pre>

<h4>🔹 Step 4 — Insider Risk Correlation</h4>
<pre><code class="language-text">
Correlate these interactions with Insider Risk Management signals.
</code></pre>

<h4>🔹 Step 5 — Compliance Reporting</h4>
<pre><code class="language-text">
Generate a compliance report for AI usage suitable for Security or Audit teams.
</code></pre>

<hr>

<h3>✅ Expected Outcome</h3>
<ul>
<li>Monitor AI agent data access activity</li>
<li>Detect unauthorized access to labeled content</li>
<li>Identify DLP policy violations in AI interactions</li>
<li>Correlate AI usage with insider risk signals</li>
<li>Support AI governance and compliance reporting</li>
</ul>

<hr>

<h3>📌 Operational Value</h3>
<p>
This promptbook enables Security Copilot to assist analysts in auditing AI agent interactions and ensuring compliance with enterprise data protection policies.
</p>
