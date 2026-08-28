from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from redsentinel.application.contracts import AgentSecurityReport


def _safe_json_for_html(data: dict[str, Any]) -> str:
    return (
        json.dumps(data, ensure_ascii=False, sort_keys=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def render_modern_dashboard(report: AgentSecurityReport) -> str:
    data = _safe_json_for_html(report.model_dump(mode="json"))
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RedSentinel - Agent 上线安全审计报告</title>
  <style>
    :root {{
      --primary: #2563eb;
      --primary-light: #dbeafe;
      --success: #16a34a;
      --success-light: #dcfce7;
      --warning: #f59e0b;
      --warning-light: #fef3c7;
      --danger: #dc2626;
      --danger-light: #fee2e2;
      --critical: #7c3aed;
      --critical-light: #f3e8ff;
      --border: #e5e7eb;
      --bg: #f9fafb;
      --text: #111827;
      --text-muted: #6b7280;
      --card: #ffffff;
      --shadow: 0 1px 3px rgba(0,0,0,0.1);
      --shadow-lg: 0 4px 6px rgba(0,0,0,0.1);
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
    header {{ margin-bottom: 32px; }}
    header h1 {{ font-size: 28px; font-weight: 700; color: var(--text); margin-bottom: 8px; }}
    header p {{ color: var(--text-muted); font-size: 16px; }}
    .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 32px; }}
    .metric-card {{ background: var(--card); border-radius: 12px; padding: 20px; box-shadow: var(--shadow); border-left: 4px solid var(--primary); transition: transform 0.2s; }}
    .metric-card:hover {{ transform: translateY(-2px); }}
    .metric-card.low {{ border-left-color: var(--success); }}
    .metric-card.medium {{ border-left-color: var(--warning); }}
    .metric-card.high {{ border-left-color: var(--danger); }}
    .metric-card.critical {{ border-left-color: var(--critical); }}
    .metric-label {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
    .metric-value {{ font-size: 32px; font-weight: 700; color: var(--text); }}
    .metric-value.success {{ color: var(--success); }}
    .metric-value.warning {{ color: var(--warning); }}
    .metric-value.danger {{ color: var(--danger); }}
    .metric-value.critical {{ color: var(--critical); }}
    .metric-subtitle {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}
    .chart-section {{ background: var(--card); border-radius: 12px; padding: 24px; box-shadow: var(--shadow); margin-bottom: 32px; }}
    .chart-section h2 {{ font-size: 18px; font-weight: 600; margin-bottom: 20px; }}
    .chart-container {{ position: relative; height: 300px; }}
    canvas {{ width: 100% !important; height: 100% !important; }}
    .section {{ background: var(--card); border-radius: 12px; padding: 24px; box-shadow: var(--shadow); margin-bottom: 32px; }}
    .section-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px; }}
    .section-title {{ font-size: 18px; font-weight: 600; }}
    .filters {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .filter-group {{ display: flex; flex-direction: column; gap: 4px; }}
    .filter-group label {{ font-size: 12px; color: var(--text-muted); }}
    .filter-group input, .filter-group select {{ padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: var(--bg); }}
    .filter-group input:focus, .filter-group select:focus {{ outline: none; border-color: var(--primary); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th {{ text-align: left; padding: 12px; background: var(--bg); font-weight: 600; color: var(--text-muted); text-transform: uppercase; font-size: 12px; }}
    td {{ padding: 12px; border-bottom: 1px solid var(--border); }}
    tr:hover td {{ background: var(--bg); }}
    .status-badge {{ display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
    .status-badge.pass {{ background: var(--success-light); color: var(--success); }}
    .status-badge.fail {{ background: var(--danger-light); color: var(--danger); }}
    .severity-badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
    .severity-badge.low {{ background: var(--success-light); color: var(--success); }}
    .severity-badge.medium {{ background: var(--warning-light); color: var(--warning); }}
    .severity-badge.high {{ background: var(--danger-light); color: var(--danger); }}
    .severity-badge.critical {{ background: var(--critical-light); color: var(--critical); }}
    .decision-badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
    .decision-badge.allow {{ background: var(--danger-light); color: var(--danger); }}
    .decision-badge.block {{ background: var(--success-light); color: var(--success); }}
    .expandable-row {{ cursor: pointer; }}
    .expandable-row::before {{ content: '▶ '; font-size: 10px; color: var(--text-muted); }}
    .expandable-row.expanded::before {{ content: '▼ '; }}
    .details-panel {{ background: var(--bg); padding: 16px; border-radius: 8px; margin-top: 8px; display: none; }}
    .details-panel.visible {{ display: block; }}
    .attack-path {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }}
    .path-node {{ padding: 8px 12px; border-radius: 8px; font-size: 13px; font-weight: 600; background: var(--card); border: 2px solid var(--border); }}
    .path-node.intercepted {{ background: var(--danger-light); border-color: var(--danger); color: var(--danger); }}
    .path-node.passed {{ background: var(--success-light); border-color: var(--success); color: var(--success); }}
    .path-arrow {{ color: var(--text-muted); font-size: 16px; }}
    .modal-overlay {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 1000; display: none; }}
    .modal-overlay.visible {{ display: flex; }}
    .modal {{ background: var(--card); border-radius: 12px; width: 90%; max-width: 800px; max-height: 80vh; overflow: hidden; }}
    .modal-header {{ padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
    .modal-header h3 {{ font-size: 18px; font-weight: 600; }}
    .modal-close {{ background: none; border: none; font-size: 24px; cursor: pointer; color: var(--text-muted); }}
    .modal-body {{ padding: 20px; overflow-y: auto; max-height: 60vh; }}
    .trajectory-step {{ padding: 16px; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid var(--primary); }}
    .trajectory-step.llm_inference {{ background: var(--primary-light); }}
    .trajectory-step.tool_call {{ background: var(--success-light); border-left-color: var(--success); }}
    .step-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
    .step-type {{ font-size: 12px; font-weight: 600; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; background: var(--primary); color: white; }}
    .step-type.tool_call {{ background: var(--success); }}
    .step-time {{ font-size: 12px; color: var(--text-muted); }}
    .step-content {{ font-size: 14px; }}
    .replay-controls {{ display: flex; justify-content: center; gap: 12px; margin-top: 20px; }}
    .replay-btn {{ padding: 8px 20px; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; }}
    .replay-btn:hover:not(:disabled) {{ opacity: 0.8; }}
    .replay-btn:disabled {{ opacity: 0.5; }}
    .replay-btn.primary {{ background: var(--primary); color: white; }}
    .replay-btn.secondary {{ background: var(--bg); color: var(--text); border: 1px solid var(--border); }}
    .replay-progress {{ text-align: center; margin-bottom: 12px; font-size: 14px; color: var(--text-muted); }}
    .conclusion-card {{ background: var(--card); border-radius: 12px; padding: 24px; box-shadow: var(--shadow); margin-bottom: 32px; border-left: 4px solid var(--primary); }}
    .conclusion-card h2 {{ font-size: 18px; font-weight: 600; margin-bottom: 16px; }}
    .conclusion-summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; }}
    .conclusion-item {{ text-align: center; padding: 12px; background: var(--bg); border-radius: 8px; }}
    .conclusion-item-label {{ font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }}
    .conclusion-item-value {{ font-size: 24px; font-weight: 700; }}
    .conclusion-item-value.positive {{ color: var(--success); }}
    .conclusion-item-value.negative {{ color: var(--danger); }}
    @media (max-width: 768px) {{ 
      .container {{ padding: 16px; }} 
      .section-header {{ flex-direction: column; align-items: flex-start; }} 
      header h1 {{ font-size: 22px; }}
      .metric-value {{ font-size: 26px; }}
      table {{ font-size: 12px; }}
      th, td {{ padding: 8px; }}
      .modal {{ width: 95%; }}
    }}
    @media (max-width: 480px) {{ 
      .metrics-grid {{ grid-template-columns: 1fr; }}
      .attack-path {{ flex-direction: column; }}
      .path-arrow {{ display: none; }}
    }}
    .fade-in {{ animation: fadeIn 0.3s ease-out; }}
    @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
    .slide-down {{ animation: slideDown 0.3s ease-out; }}
    @keyframes slideDown {{ from {{ opacity: 0; max-height: 0; }} to {{ opacity: 1; max-height: 500px; }} }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🔒 RedSentinel - Agent 上线安全审计报告</h1>
      <p>Agent: <code>{escape(report.agent_id)}</code> | Tenant: <code>{escape(report.tenant_id)}</code> | Benchmark: <code>{escape(report.benchmark)}</code></p>
    </header>
    <div class="metrics-grid" id="metrics-grid">
      <div class="metric-card" id="score-card"><div class="metric-label">Overall Score</div><div class="metric-value" id="overall-score">{report.overall_score}</div><div class="metric-subtitle">0-100</div></div>
      <div class="metric-card" id="risk-card"><div class="metric-label">Risk Level</div><div class="metric-value" id="risk-level">{report.risk_level.upper()}</div><div class="metric-subtitle">Security posture</div></div>
      <div class="metric-card" id="asr-card"><div class="metric-label">Attack Success Rate</div><div class="metric-value" id="attack-success-rate">{(report.attack_success_rate * 100):.1f}%</div><div class="metric-subtitle">Attacks succeeded</div></div>
      <div class="metric-card" id="fpr-card"><div class="metric-label">False Positive Rate</div><div class="metric-value" id="false-positive-rate">{(report.false_positive_rate * 100):.1f}%</div><div class="metric-subtitle">Legitimate blocked</div></div>
    </div>
    <div class="chart-section"><h2>📈 ASR Convergence Curve</h2><div class="chart-container"><canvas id="asr-chart"></canvas></div></div>
    <div class="section">
      <div class="section-header">
        <div class="section-title">⚔️ Attack Scenarios</div>
        <div class="filters">
          <div class="filter-group"><label for="search-filter">Search</label><input type="text" id="search-filter" placeholder="Search..."></div>
          <div class="filter-group"><label for="severity-filter">Severity</label><select id="severity-filter"><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
          <div class="filter-group"><label for="status-filter">Status</label><select id="status-filter"><option value="">All</option><option value="pass">Pass</option><option value="fail">Fail</option></select></div>
        </div>
      </div>
      <table id="scenarios-table">
        <thead><tr><th>Status</th><th>Scenario</th><th>Category</th><th>Severity</th><th>Expected</th><th>Actual</th><th>Impact</th><th>Evidence</th></tr></thead>
        <tbody id="scenarios-body"></tbody>
      </table>
    </div>
    <div class="section">
      <div class="section-header"><div class="section-title">⚠️ Findings</div></div>
      <table id="findings-table">
        <thead><tr><th>Severity</th><th>Scenario</th><th>Title</th><th>Impact</th><th>Recommendation</th></tr></thead>
        <tbody id="findings-body"></tbody>
      </table>
    </div>
    <div class="conclusion-card">
      <h2>📊 Conclusion</h2>
      <div class="conclusion-summary">
        <div class="conclusion-item"><div class="conclusion-item-label">Total Scenarios</div><div class="conclusion-item-value" id="total-scenarios">{report.summary.get('attacks_total', '--')}</div></div>
        <div class="conclusion-item"><div class="conclusion-item-label">Blocked</div><div class="conclusion-item-value positive" id="attacks-blocked">{report.summary.get('attacks_blocked', '--')}</div></div>
        <div class="conclusion-item"><div class="conclusion-item-label">Passed</div><div class="conclusion-item-value negative" id="attacks-passed">{report.summary.get('attacks_passed', '--')}</div></div>
        <div class="conclusion-item"><div class="conclusion-item-label">Defenses</div><div class="conclusion-item-value" id="defenses-mounted">{report.summary.get('defenses_mounted', '--')}</div></div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="trajectory-modal">
    <div class="modal"><div class="modal-header"><h3>🚀 Trajectory Playback</h3><button class="modal-close" onclick="closeModal()">×</button></div><div class="modal-body"><div class="replay-progress" id="replay-progress">Step 1 / 1</div><div id="trajectory-content"></div><div class="replay-controls"><button class="replay-btn secondary" onclick="prevStep()" id="btn-prev">◀ Prev</button><button class="replay-btn primary" onclick="togglePlay()" id="btn-play">▶ Play</button><button class="replay-btn secondary" onclick="nextStep()" id="btn-next">Next ▶</button></div></div></div>
  </div>
  <script id="dashboard-data" type="application/json">{data}</script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    const reportData = JSON.parse(document.getElementById('dashboard-data').textContent);
    let currentTrajectory = [], currentStep = 0, isPlaying = false, playInterval = null;

    function escapeHtml(value) {{
      return String(value ?? '').replace(/[&<>"']/g, char => ({{
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      }}[char]));
    }}

    function safeCssToken(value, fallback = '') {{
      return String(value ?? '').toLowerCase().replace(/[^a-z0-9_-]/g, '') || fallback;
    }}

    function render() {{
      renderMetrics(); renderASRChart(); renderScenarios(); renderFindings();
    }}

    function renderMetrics() {{
      const riskColors = {{'low':'success','medium':'warning','high':'danger','critical':'critical'}};
      const risk = reportData.risk_level;
      ['score-card','risk-card'].forEach(id => document.getElementById(id).className = 'metric-card ' + riskColors[risk]);
      document.getElementById('risk-level').className = 'metric-value ' + riskColors[risk];
      document.getElementById('asr-card').className = 'metric-card ' + (reportData.attack_success_rate > 0.3 ? 'danger' : reportData.attack_success_rate > 0.1 ? 'warning' : 'success');
      document.getElementById('attack-success-rate').className = 'metric-value ' + (reportData.attack_success_rate > 0.3 ? 'danger' : reportData.attack_success_rate > 0.1 ? 'warning' : 'success');
    }}

    function renderASRChart() {{
      const conv = reportData.asr_convergence || [];
      if (!conv.length) return;
      new Chart(document.getElementById('asr-chart'), {{
        type: 'line',
        data: {{
          labels: conv.map(d => 'Round ' + d.round),
          datasets: [{{label: 'ASR (%)', data: conv.map(d => d.asr*100), borderColor: '#dc2626', backgroundColor: 'rgba(220,38,38,0.1)', fill: true}}]
        }},
        options: {{responsive: true, maintainAspectRatio: false, scales: {{y: {{beginAtZero: true, max: 100}}, x: {{title: {{display: true, text: 'Attack Round'}}}}}}
      }});
    }}

    function renderScenarios() {{
      const tbody = document.getElementById('scenarios-body');
      tbody.innerHTML = (reportData.scenario_results || []).map((s, i) => `
        <tr class="expandable-row" data-index="${{i}}" onclick="toggleDetails(${{i}})">
          <td><span class="status-badge ${{s.passed?'pass':'fail'}}">${{s.passed?'PASS':'FAIL'}}</span></td>
          <td><code>${{escapeHtml(s.scenario_id || '--')}}</code></td>
          <td>${{escapeHtml(s.category || '--')}}</td>
          <td><span class="severity-badge ${{safeCssToken(s.severity, 'medium')}}">${{escapeHtml(String(s.severity || '--').toUpperCase())}}</span></td>
          <td><span class="decision-badge ${{safeCssToken(s.expected_decision)}}">${{escapeHtml(String(s.expected_decision || '--').toUpperCase())}}</span></td>
          <td><span class="decision-badge ${{safeCssToken(s.actual_decision)}}">${{escapeHtml(String(s.actual_decision || '--').toUpperCase())}}</span></td>
          <td>${{escapeHtml(s.business_impact || '--')}}</td>
          <td><button onclick="event.stopPropagation(); openTrajectory(${{i}})" style="background:none;border:none;color:#2563eb;cursor:pointer;text-decoration:underline;">View</button></td>
        </tr>
        <tr id="details-${{i}}"><td colspan="8"><div class="details-panel" id="details-panel-${{i}}"></div></td></tr>
      `).join('');
      setupFilters();
    }}

    function setupFilters() {{
      const filter = () => {{
        const search = document.getElementById('search-filter').value.toLowerCase();
        const severity = document.getElementById('severity-filter').value;
        const status = document.getElementById('status-filter').value;
        document.querySelectorAll('.expandable-row').forEach(row => {{
          const s = reportData.scenario_results[row.dataset.index];
          const scenarioId = String(s.scenario_id || '').toLowerCase();
          const category = String(s.category || '').toLowerCase();
          const match = (!search || scenarioId.includes(search) || category.includes(search)) &&
                        (!severity || s.severity === severity) &&
                        (!status || (status === 'pass' && s.passed) || (status === 'fail' && !s.passed));
          row.style.display = match ? '' : 'none';
          document.getElementById('details-'+row.dataset.index).style.display = match ? '' : 'none';
        }});
      }};
      ['search-filter','severity-filter','status-filter'].forEach(id => document.getElementById(id).addEventListener('input', filter));
    }}

    function toggleDetails(i) {{
      document.querySelector(`tr[data-index="${{i}}"]`).classList.toggle('expanded');
      const panel = document.getElementById('details-panel-'+i);
      panel.classList.toggle('visible');
      if (panel.classList.contains('visible') && !panel.innerHTML) renderNodeAttribution(panel, i);
    }}

    function renderNodeAttribution(panel, i) {{
      const attr = reportData.scenario_results[i].node_attribution || {{}};
      const attackPath = attr.attack_path || [];
      const interceptedNode = attr.intercepted_node || '';
      let html = '';
      if (attackPath.length) {{
        html += '<div class="attack-path">';
        attackPath.forEach((node, j) => {{
          html += `<div class="path-node ${{node === interceptedNode ? 'intercepted' : (interceptedNode ? j < attackPath.indexOf(interceptedNode) ? 'passed' : '' : 'passed')}}">${{escapeHtml(node)}}</div>`;
          if (j < attackPath.length - 1) html += '<span class="path-arrow">→</span>';
        }});
        html += '</div>';
      }}
      html += interceptedNode ? `<p><strong>✅ Intercepted:</strong> ${{escapeHtml(interceptedNode)}} (${{escapeHtml(attr.defense_type || 'unknown')}})</p>` : '<p><strong>❌ Not intercepted!</strong></p>';
      panel.innerHTML = html;
    }}

    function renderFindings() {{
      document.getElementById('findings-body').innerHTML = (reportData.findings || []).map(f => `
        <tr><td><span class="severity-badge ${{safeCssToken(f.severity, 'medium')}}">${{escapeHtml(String(f.severity || '--').toUpperCase())}}</span></td><td><code>${{escapeHtml(f.scenario_id || '-')}}</code></td><td>${{escapeHtml(f.title || '-')}}</td><td>${{escapeHtml(f.business_impact || '-')}}</td><td>${{escapeHtml(f.recommendation || '-')}}</td></tr>
      `).join('');
    }}

    function openTrajectory(i) {{
      currentTrajectory = reportData.scenario_results[i].trajectory || [];
      currentStep = 0; isPlaying = false;
      document.getElementById('trajectory-modal').classList.add('visible');
      document.getElementById('btn-play').textContent = '▶ Play';
      renderCurrentStep();
    }}

    function closeModal() {{ document.getElementById('trajectory-modal').classList.remove('visible'); stopPlay(); }}

    function renderCurrentStep() {{
      const content = document.getElementById('trajectory-content');
      if (!currentTrajectory.length) {{ content.innerHTML = '<p>No data</p>'; return; }}
      document.getElementById('replay-progress').textContent = `Step ${{currentStep+1}} / ${{currentTrajectory.length}}`;
      const s = currentTrajectory[currentStep];
      const stepType = s.step_type || 'unknown';
      const stepBody = stepType === 'llm_inference' ?
        `<p><strong>Model:</strong> ${{escapeHtml(s.model || '-')}}</p><p><strong>Output:</strong> ${{escapeHtml(s.output_content || '(empty)')}}</p>` :
        `<p><strong>Tool:</strong> ${{escapeHtml(s.name || '-')}}</p><p><strong>Args:</strong> ${{escapeHtml(JSON.stringify(s.arguments || {{}}))}}</p><p><strong>Response:</strong> ${{escapeHtml(JSON.stringify(s.response || {{}}))}}</p>`;
      content.innerHTML = `
        <div class="trajectory-step ${{safeCssToken(stepType, 'unknown')}}">
          <div class="step-header"><span class="step-type ${{safeCssToken(stepType, 'unknown')}}">${{escapeHtml(String(stepType).replace('_',' '))}}</span><span class="step-time">${{escapeHtml(s.timestamp || '')}}</span></div>
          <div class="step-content">${{stepBody}}</div>
        </div>
      `;
      document.getElementById('btn-prev').disabled = currentStep === 0;
      document.getElementById('btn-next').disabled = currentStep === currentTrajectory.length - 1;
    }}

    function prevStep() {{ if (currentStep > 0) {{ currentStep--; renderCurrentStep(); }} }}
    function nextStep() {{ if (currentStep < currentTrajectory.length - 1) {{ currentStep++; renderCurrentStep(); }} }}
    function togglePlay() {{ if (isPlaying) stopPlay(); else startPlay(); }}
    function startPlay() {{
      isPlaying = true; document.getElementById('btn-play').textContent = '⏸ Pause';
      playInterval = setInterval(() => {{ if (currentStep < currentTrajectory.length - 1) {{ currentStep++; renderCurrentStep(); }} else stopPlay(); }}, 1500);
    }}
    function stopPlay() {{ isPlaying = false; document.getElementById('btn-play').textContent = '▶ Play'; if (playInterval) {{ clearInterval(playInterval); playInterval = null; }} }}

    render();
  </script>
</body>
</html>
"""


def generate_dashboard_html(report: AgentSecurityReport) -> str:
    return render_modern_dashboard(report)


def write_dashboard_html(report: AgentSecurityReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(generate_dashboard_html(report), encoding="utf-8")
