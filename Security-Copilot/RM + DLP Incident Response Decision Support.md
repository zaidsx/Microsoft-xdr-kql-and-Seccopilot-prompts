<h2>🧠 Promptbook 3 — IRM + DLP Incident Response Decision Support</h2>

<p><strong>🎯 Use Case:</strong><br>
Support SOC and Compliance teams in determining the appropriate response action for Microsoft Purview DLP or Insider Risk Management incidents using Microsoft Security Copilot.
</p>

<hr>

<h3>📘 Promptbook Flow</h3>

<h4>🔹 Step 1 — Alert Context Summary</h4>
<pre><code class="language-text">
Summarize the DLP or IRM alert &lt;AlertID&gt; including:
• policy match
• sensitivity label
• impacted files
• user risk level
</code></pre>

<h4>🔹 Step 2 — Impacted Entity Identification</h4>
<pre><code class="language-text">
List all impacted entities:
• files
• users
• external recipients
• device involved
</code></pre>

<h4>🔹 Step 3 — Business Risk Assessment</h4>
<pre><code class="language-text">
What business data risk does this incident pose?
(e.g., IP theft, financial data exposure, PII leak)
</code></pre>

<h4>🔹 Step 4 — Containment Recommendation</h4>
<pre><code class="language-text">
Generate a containment recommendation:
• Block user
• Remove sharing link
• Revoke access
• Apply sensitivity label
</code></pre>

<h4>🔹 Step 5 — Executive Reporting</h4>
<pre><code class="language-text">
Generate an executive summary suitable for CISO or Compliance Officer.
</code></pre>

<hr>

<h3>✅ Expected Outcome</h3>
<ul>
<li>Enable consistent incident response decisions</li>
<li>Accelerate DLP and Insider Risk investigations</li>
<li>Improve containment action accuracy</li>
<li>Support business‑risk‑based remediation</li>
<li>Provide executive‑level incident reporting</li>
</ul>

<hr>

<h3>📌 Operational Value</h3>
<p>
This promptbook enables Security Copilot to assist analysts in determining the appropriate containment or remediation action for Microsoft Purview DLP and Insider Risk incidents based on correlated investigation insights.
</p>
