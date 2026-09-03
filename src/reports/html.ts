import type { ScanResult } from '../models/scan-result.js';

export function renderHtmlReport(result: ScanResult): string {
  const resultJson = JSON.stringify(result);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DeepCleaner Security Report - ${escapeHtml(result.project.name)}</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --heading: #f0f6fc;
      --critical: #f85149;
      --high: #ff7b72;
      --medium: #d29922;
      --low: #58a6ff;
      --info: #8b949e;
      --success: #3fb950;
      --accent: #238636;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 24px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    h1 { color: var(--heading); font-size: 24px; display: flex; align-items: center; gap: 10px; }
    .meta-tag { background: #21262d; padding: 4px 10px; border-radius: 6px; font-size: 13px; color: var(--text-muted); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .card-title { font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; margin-bottom: 8px; }
    .card-val { font-size: 28px; font-weight: 700; color: var(--heading); }
    .risk-score { color: ${result.riskScore.score > 70 ? 'var(--critical)' : result.riskScore.score > 35 ? 'var(--medium)' : 'var(--success)'}; }
    .severity-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .sev-CRITICAL { background: rgba(248, 81, 73, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .sev-HIGH { background: rgba(255, 123, 114, 0.2); color: var(--high); border: 1px solid var(--high); }
    .sev-MEDIUM { background: rgba(210, 153, 34, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .sev-LOW { background: rgba(88, 166, 255, 0.2); color: var(--low); border: 1px solid var(--low); }
    .sev-INFO { background: rgba(139, 148, 158, 0.2); color: var(--info); border: 1px solid var(--info); }
    .controls { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
    input[type="text"], select {
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 14px;
    }
    input[type="text"] { flex: 1; min-width: 250px; }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 12px;
      padding: 16px;
      transition: border-color 0.15s ease;
    }
    .finding-card:hover { border-color: var(--text-muted); }
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; }
    .finding-title { font-size: 16px; font-weight: 600; color: var(--heading); }
    .finding-location { font-family: monospace; font-size: 13px; color: var(--low); margin-bottom: 8px; }
    .evidence-block {
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px;
      font-family: monospace;
      font-size: 12px;
      overflow-x: auto;
      margin: 8px 0;
      color: #7ee787;
    }
    .remediation-box {
      background: rgba(35, 134, 54, 0.1);
      border-left: 3px solid var(--accent);
      padding: 8px 12px;
      border-radius: 0 4px 4px 0;
      font-size: 13px;
      margin-top: 8px;
    }
    .disclaimer-footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
      font-size: 12px;
      color: var(--text-muted);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>DeepCleaner AG <span class="meta-tag">v${result.tool.version}</span></h1>
        <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Target: ${escapeHtml(result.target.absolutePath)}</div>
      </div>
      <div style="text-align: right;">
        <div class="meta-tag">${escapeHtml(result.timestamp)}</div>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <div class="card-title">Risk Score</div>
        <div class="card-val risk-score">${result.riskScore.score}<span style="font-size: 16px; color: var(--text-muted);">/100</span> (Grade ${result.riskScore.grade})</div>
      </div>
      <div class="card">
        <div class="card-title">Critical / High</div>
        <div class="card-val" style="color: var(--critical);">${result.summary.critical + result.summary.high}</div>
      </div>
      <div class="card">
        <div class="card-title">Total Findings</div>
        <div class="card-val">${result.summary.total}</div>
      </div>
      <div class="card">
        <div class="card-title">Scanned Files</div>
        <div class="card-val">${result.project.totalFiles} <span style="font-size: 14px; color: var(--text-muted);">(${(result.project.totalBytes / 1024 / 1024).toFixed(1)} MB)</span></div>
      </div>
    </div>

    <div class="controls">
      <input type="text" id="searchInput" placeholder="Search by title, rule ID, or filename..." onkeyup="filterFindings()">
      <select id="severityFilter" onchange="filterFindings()">
        <option value="ALL">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
        <option value="INFO">Info</option>
      </select>
    </div>

    <div id="findingsContainer">
      ${result.findings.map(renderHtmlFinding).join('')}
    </div>

    <div class="disclaimer-footer">
      <strong>Safety Disclaimers:</strong>
      <ul style="margin-left: 20px; margin-top: 6px;">
        ${result.disclaimers.map((d) => `<li>${escapeHtml(d)}</li>`).join('')}
      </ul>
    </div>
  </div>

  <script>
    const scanData = ${resultJson};

    function filterFindings() {
      const q = document.getElementById('searchInput').value.toLowerCase();
      const sev = document.getElementById('severityFilter').value;
      const cards = document.querySelectorAll('.finding-card');

      cards.forEach(card => {
        const title = card.getAttribute('data-title') || '';
        const file = card.getAttribute('data-file') || '';
        const id = card.getAttribute('data-id') || '';
        const cardSev = card.getAttribute('data-severity') || '';

        const matchesQuery = !q || title.includes(q) || file.includes(q) || id.includes(q);
        const matchesSev = sev === 'ALL' || cardSev === sev;

        if (matchesQuery && matchesSev) {
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      });
    }
  </script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderHtmlFinding(f: any): string {
  const evidence = f.redactedEvidence || f.evidence || '';
  return `
    <div class="finding-card" data-severity="${escapeHtml(f.severity)}" data-title="${escapeHtml(f.title.toLowerCase())}" data-file="${escapeHtml(f.file.toLowerCase())}" data-id="${escapeHtml(f.id.toLowerCase())}">
      <div class="finding-header">
        <div>
          <span class="severity-badge sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
          <span class="finding-title" style="margin-left: 8px;">${escapeHtml(f.title)}</span>
        </div>
        <span class="meta-tag">${escapeHtml(f.id)}</span>
      </div>
      <div class="finding-location">${escapeHtml(f.file)}${f.line ? `:${f.line}` : ''} (${f.scanner} | Confidence: ${f.confidence}%)</div>
      <div style="font-size: 14px; margin-bottom: 6px;">${escapeHtml(f.description)}</div>
      ${evidence ? `<pre class="evidence-block">${escapeHtml(evidence)}</pre>` : ''}
      ${f.aiAnalysis ? `<div style="background: #1f242c; padding: 8px 12px; border-radius: 4px; font-size: 13px; margin-top: 6px;"><strong>AI Advisory (${escapeHtml(f.aiAnalysis.verdict.toUpperCase())}):</strong> ${escapeHtml(f.aiAnalysis.explanation || f.aiAnalysis.reasoningSummary)}</div>` : ''}
      ${f.remediation ? `<div class="remediation-box"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>` : ''}
    </div>
  `;
}
