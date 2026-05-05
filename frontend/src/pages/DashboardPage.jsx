import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { projectsAPI, scansAPI } from '../services/api';
import RiskScoreMeter from '../components/RiskScoreMeter';
import PDFExportButton from '../components/PDFExport';

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEVERITY_ICONS = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢', INFO: '🔵' };
const SEVERITY_COLORS = {
  CRITICAL: 'var(--critical)', HIGH: 'var(--high)',
  MEDIUM: 'var(--medium)', LOW: 'var(--low)', INFO: 'var(--info)',
};

function getRiskColor(score) {
  if (!score) return 'var(--text-muted)';
  if (score >= 85) return 'var(--critical)';
  if (score >= 68) return 'var(--high)';
  if (score >= 45) return 'var(--medium)';
  return 'var(--low)';
}

/* ===================== Stat Card ===================== */
function StatCard({ label, value, severity, icon, subtitle }) {
  return (
    <div className={`stat-card ${severity || 'total'}`} style={{ position: 'relative', overflow: 'hidden' }}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value" style={{ color: `var(--${severity || 'accent'})` }}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
      {subtitle && (
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>{subtitle}</div>
      )}
    </div>
  );
}

/* ===================== AI Intro Banner ===================== */
function AIIntroBanner() {
  return (
    <div className="ai-intro-banner">
      <div className="ai-intro-icon">🤖</div>
      <div className="ai-intro-content">
        <div className="ai-intro-title">AI-Enhanced Risk Intelligence Engine</div>
        <div className="ai-intro-text">
          Our AI model analyzes response divergence, HTTP method severity, and access control gap patterns
          to assign precise threat scores from <strong style={{ color: 'var(--accent)' }}>0–100</strong>.
          Focus remediation on the highest-impact issues first — aligned with <strong>OWASP A01:2021</strong>.
        </div>
      </div>
      <div className="ai-intro-badge">
        <span className="cyber-badge">🔥 Live AI</span>
      </div>
    </div>
  );
}

/* ===================== Score Summary Header ===================== */
function ScoreSummary({ avgScore, maxScore, topSeverity, total }) {
  const riskLabel = avgScore >= 75 ? 'CRITICAL RISK' : avgScore >= 55 ? 'HIGH RISK' : avgScore >= 35 ? 'MEDIUM RISK' : 'LOW RISK';
  const riskColor = avgScore >= 75 ? 'var(--critical)' : avgScore >= 55 ? 'var(--high)' : avgScore >= 35 ? 'var(--medium)' : 'var(--low)';

  return (
    <div style={{
      background: 'linear-gradient(135deg, rgba(124,109,248,0.07), rgba(168,85,247,0.04), rgba(0,0,0,0))',
      border: '1px solid rgba(124,109,248,0.18)',
      borderRadius: 'var(--radius-lg)',
      padding: '24px 28px',
      marginBottom: 28,
      display: 'flex',
      alignItems: 'center',
      gap: 32,
      flexWrap: 'wrap',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Gradient top border */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: 'linear-gradient(90deg, var(--accent), var(--accent-2), var(--teal))' }} />

      <div style={{ textAlign: 'center' }}>
        <RiskScoreMeter score={avgScore} severity={topSeverity || 'LOW'} size={100} />
        <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginTop: 6 }}>Avg Risk Score</div>
      </div>

      <div style={{ width: 1, height: 80, background: 'var(--border)', flexShrink: 0 }} />

      <div style={{ flex: 1, minWidth: 160 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <span style={{
            fontSize: 11, fontWeight: 800, letterSpacing: 1, textTransform: 'uppercase',
            color: riskColor, padding: '3px 12px', borderRadius: 100,
            background: `${riskColor}18`, border: `1px solid ${riskColor}40`,
          }}>{riskLabel}</span>
        </div>
        <div style={{ fontSize: 28, fontWeight: 900, color: 'var(--text-primary)', fontFamily: 'Outfit, sans-serif', letterSpacing: -1 }}>
          {total} <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-muted)' }}>vulnerabilities found</span>
        </div>
        <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginTop: 4 }}>
          Peak AI risk: <span style={{ color: getRiskColor(maxScore), fontWeight: 700, fontFamily: 'JetBrains Mono' }}>{maxScore}/100</span>
          {topSeverity && <span style={{ marginLeft: 12 }}>Top severity: <span className={`badge ${topSeverity}`}>{topSeverity}</span></span>}
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 140 }}>
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
          const score = sev === 'CRITICAL' ? 90 : sev === 'HIGH' ? 72 : sev === 'MEDIUM' ? 50 : 25;
          return (
            <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: SEVERITY_COLORS[sev], flexShrink: 0 }} />
              <span style={{ fontSize: 10, color: 'var(--text-muted)', width: 56, textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 700 }}>{sev}</span>
              <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 100, overflow: 'hidden' }}>
                <div style={{ width: `${score}%`, height: '100%', background: SEVERITY_COLORS[sev], borderRadius: 100 }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ===================== AI Risk Row ===================== */
function AIRiskRow({ findings }) {
  const avgRiskScore = findings.length > 0
    ? Math.round(findings.reduce((acc, f) => acc + (f.ai_risk_score || 0), 0) / findings.length)
    : 0;
  const maxRiskScore = findings.length > 0 ? Math.max(...findings.map(f => f.ai_risk_score || 0)) : 0;
  const topSeverity = findings.some(f => f.ai_severity === 'CRITICAL') ? 'CRITICAL'
    : findings.some(f => f.ai_severity === 'HIGH') ? 'HIGH'
    : findings.some(f => f.ai_severity === 'MEDIUM') ? 'MEDIUM' : 'LOW';

  return (
    <div className="ai-risk-overview">
      <div className="ai-risk-card" style={{ position: 'relative' }}>
        <div className="ai-risk-card-label">Avg AI Score</div>
        <RiskScoreMeter score={avgRiskScore} severity={topSeverity || 'LOW'} size={84} />
      </div>
      <div className="ai-risk-card" style={{ position: 'relative' }}>
        <div className="ai-risk-card-label">Peak AI Score</div>
        <RiskScoreMeter score={maxRiskScore} severity="CRITICAL" size={84} />
      </div>
      <div className="ai-risk-card ai-risk-stats" style={{ position: 'relative' }}>
        <div className="ai-risk-card-label">AI Severity Mix</div>
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
          const count = findings.filter(f => f.ai_severity === sev).length;
          const pct = findings.length > 0 ? (count / findings.length) * 100 : 0;
          return (
            <div key={sev} className="ai-dist-row">
              <span className={`badge ${sev}`} style={{ minWidth: 72, justifyContent: 'center', fontSize: 9.5 }}>{sev}</span>
              <div className="ai-dist-bar">
                <div className={`ai-dist-fill ${sev.toLowerCase()}`} style={{ width: `${pct}%` }} />
              </div>
              <span className="ai-dist-count">{count}</span>
            </div>
          );
        })}
      </div>
      <div className="ai-risk-card ai-confidence-card" style={{ position: 'relative' }}>
        <div className="ai-risk-card-label">Confidence</div>
        {['HIGH', 'MEDIUM', 'LOW'].map(conf => {
          const count = findings.filter(f => f.ai_confidence === conf).length;
          return (
            <div key={conf} className="conf-row">
              <div className={`conf-dot conf-${conf.toLowerCase()}`} />
              <span style={{ fontWeight: 600 }}>{conf}</span>
              <span className="conf-count">{count}</span>
            </div>
          );
        })}
        <div style={{ marginTop: 'auto', paddingTop: 8, borderTop: '1px solid var(--border)', width: '100%' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center' }}>
            {findings.length} total findings
          </div>
        </div>
      </div>
    </div>
  );
}

/* ===================== Finding Modal ===================== */
function FindingModal({ finding, onClose }) {
  const [tab, setTab] = useState('ai');

  return (
    <div style={{
      position: 'fixed', inset: 0,
      background: 'rgba(0,0,0,0.85)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 1000, padding: 24,
      backdropFilter: 'blur(12px)',
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-light)',
        borderRadius: 'var(--radius-xl)',
        width: '100%', maxWidth: 900,
        maxHeight: '92vh', overflow: 'auto',
        boxShadow: 'var(--shadow), 0 0 60px rgba(124,109,248,0.1)',
        animation: 'fadeInUp 0.25s ease',
        position: 'relative',
      }}>
        {/* Top accent line */}
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, height: 2,
          background: `linear-gradient(90deg, var(--accent), var(--accent-2), var(--teal))`,
          borderRadius: '20px 20px 0 0',
        }} />

        {/* Modal header */}
        <div style={{ padding: '22px 28px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <span className={`badge ${finding.severity}`}>{SEVERITY_ICONS[finding.severity]} {finding.severity}</span>
            <span className="vuln-chip">{finding.vuln_type?.replace(/_/g, ' ')}</span>
            {finding.ai_risk_score && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: getRiskColor(finding.ai_risk_score), fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
                🤖 {finding.ai_risk_score}/100
              </span>
            )}
          </div>
          <button className="btn btn-secondary btn-sm" onClick={onClose} style={{ flexShrink: 0 }}>✕ Close</button>
        </div>

        <div style={{ padding: '0 28px' }}>
          <div className="tabs">
            {[
              { key: 'ai', label: '🤖 AI Analysis' },
              { key: 'explanation', label: '💡 Explanation' },
              { key: 'diff', label: '🔀 Req / Resp' },
              { key: 'fix', label: '🔧 Remediation' },
            ].map(t => (
              <div key={t.key} className={`tab ${tab === t.key ? 'active' : ''}`} onClick={() => setTab(t.key)}>
                {t.label}
              </div>
            ))}
          </div>

          {/* AI Analysis Tab */}
          {tab === 'ai' && (
            <div style={{ paddingBottom: 28 }}>
              <div className="ai-analysis-panel">
                <div className="ai-meter-section">
                  <RiskScoreMeter score={finding.ai_risk_score || 0} severity={finding.ai_severity || 'LOW'} size={130} />
                  <div style={{ textAlign: 'center', marginTop: 6 }}>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1.2, marginBottom: 6 }}>AI Risk Score</div>
                    <span className={`badge ${finding.ai_severity || 'LOW'}`}>🤖 {finding.ai_severity || 'LOW'}</span>
                  </div>
                </div>
                <div className="ai-detail-section">
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8, fontWeight: 700 }}>Model Confidence</div>
                    <div className="ai-confidence-display">
                      <span className={`conf-badge conf-${(finding.ai_confidence || 'low').toLowerCase()}`}>
                        {finding.ai_confidence || 'LOW'} Confidence
                      </span>
                      <div style={{ height: 6, flex: 1, background: 'rgba(255,255,255,0.06)', borderRadius: 100, overflow: 'hidden' }}>
                        <div style={{
                          height: '100%', borderRadius: 100,
                          width: finding.ai_confidence === 'HIGH' ? '85%' : finding.ai_confidence === 'MEDIUM' ? '55%' : '25%',
                          background: finding.ai_confidence === 'HIGH' ? 'var(--low)' : finding.ai_confidence === 'MEDIUM' ? 'var(--medium)' : 'var(--text-muted)',
                          transition: 'width 0.8s ease',
                        }} />
                      </div>
                    </div>
                  </div>
                  <div className="ai-reasoning-box">
                    <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--accent)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>🤖</span> AI Reasoning
                    </div>
                    <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.75, margin: 0 }}>
                      {finding.ai_reasoning || 'No AI reasoning available for this finding.'}
                    </p>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    {[
                      { label: 'CWE Reference', value: finding.cwe_id, icon: '🔗' },
                      { label: 'OWASP Ref', value: finding.owasp_ref, icon: '📋' },
                    ].map(item => item.value && (
                      <div key={item.label} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', borderRadius: 8, border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: 9.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 700, marginBottom: 4 }}>{item.label}</div>
                        <div style={{ fontSize: 12, color: 'var(--info)', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{item.icon} {item.value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {tab === 'explanation' && (
            <div style={{ paddingBottom: 28 }}>
              <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
                <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--info)', background: 'rgba(56,189,248,0.08)', padding: '4px 12px', borderRadius: 6, border: '1px solid rgba(56,189,248,0.2)' }}>
                  {finding.method} {finding.endpoint}
                </span>
                {finding.cwe_id && (
                  <a href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`}
                    target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm">
                    🔗 {finding.cwe_id}
                  </a>
                )}
              </div>
              <div style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.8, whiteSpace: 'pre-wrap', background: 'rgba(0,0,0,0.15)', padding: '18px 20px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                {finding.explanation}
              </div>
            </div>
          )}

          {tab === 'diff' && (
            <div style={{ paddingBottom: 28 }}>
              <div className="diff-viewer">
                <div>
                  <div className="diff-pane-label">🔵 Original Request</div>
                  <pre className="code-block" style={{ maxHeight: 200, overflow: 'auto' }}>{finding.original_request || 'N/A'}</pre>
                  <div className="diff-pane-label" style={{ marginTop: 14 }}>🔵 Original Response</div>
                  <pre className="code-block" style={{ maxHeight: 200, overflow: 'auto' }}>{finding.original_response || 'N/A'}</pre>
                </div>
                <div>
                  <div className="diff-pane-label">🔴 Modified Request</div>
                  <pre className="code-block" style={{ maxHeight: 200, overflow: 'auto' }}>{finding.modified_request || 'N/A'}</pre>
                  <div className="diff-pane-label" style={{ marginTop: 14 }}>🔴 Modified Response</div>
                  <pre className="code-block" style={{ maxHeight: 200, overflow: 'auto', color: 'var(--critical)' }}>{finding.modified_response || 'N/A'}</pre>
                </div>
              </div>
              {finding.similarity_score != null && (
                <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Response Similarity:</span>
                  <div style={{ flex: 1, maxWidth: 200, height: 6, background: 'var(--border)', borderRadius: 100, overflow: 'hidden' }}>
                    <div style={{ width: `${(finding.similarity_score * 100).toFixed(0)}%`, height: '100%', background: 'var(--accent)', borderRadius: 100 }} />
                  </div>
                  <strong style={{ color: 'var(--accent)', fontFamily: 'JetBrains Mono', fontSize: 12 }}>
                    {(finding.similarity_score * 100).toFixed(1)}%
                  </strong>
                </div>
              )}
            </div>
          )}

          {tab === 'fix' && (
            <div style={{ paddingBottom: 28 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--low)' }}>🔧 Remediation Guidance</span>
                <span className="cyber-tag">OWASP Aligned</span>
              </div>
              <pre style={{
                fontFamily: 'JetBrains Mono, monospace', fontSize: 12, lineHeight: 1.8,
                whiteSpace: 'pre-wrap', color: 'var(--low)',
                background: 'rgba(52, 211, 153, 0.04)', padding: '20px 22px',
                borderRadius: 'var(--radius-sm)', border: '1px solid rgba(52, 211, 153, 0.15)',
                position: 'relative',
              }}>
                {finding.fix_suggestion || 'No fix suggestion available.'}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ===================== Main Dashboard ===================== */
export default function DashboardPage() {
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState(null);
  const [findings, setFindings] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [filter, setFilter] = useState('ALL');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const navigate = useNavigate();

  // Load projects on mount
  useEffect(() => {
    projectsAPI.list().then(r => {
      setProjects(r.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  // Load findings when project selected — Fetch all results for the project from backend
  const loadFindingsForProject = useCallback(async (project) => {
    if (!project) {
      setFindings([]);
      return;
    }
    setFindingsLoading(true);
    try {
      const res = await scansAPI.listByProject(project.id);
      setFindings(res.data);
      // Update localStorage to stay in sync
      localStorage.setItem('bac_last_findings', JSON.stringify(res.data));
      localStorage.setItem('bac_last_project_id', String(project.id));
    } catch (e) {
      console.error("Failed to load project findings:", e);
      // Fallback to local storage only if it matches
      const stored = localStorage.getItem('bac_last_findings');
      const storedProject = localStorage.getItem('bac_last_project_id');
      if (stored && storedProject === String(project.id)) {
        setFindings(JSON.parse(stored));
      } else {
        setFindings([]);
      }
    }
    setFindingsLoading(false);
  }, []);

  // Auto-select first project or clean up stale storage
  useEffect(() => {
    if (projects.length > 0 && !selectedProject) {
      const storedProject = localStorage.getItem('bac_last_project_id');
      const found = projects.find(p => String(p.id) === storedProject);
      setSelectedProject(found || projects[0]);
    } else if (projects.length === 0) {
      localStorage.removeItem('bac_last_findings');
      localStorage.removeItem('bac_last_project_id');
    }
  }, [projects, selectedProject]);

  // Load findings when project changes
  useEffect(() => {
    loadFindingsForProject(selectedProject);
  }, [selectedProject, loadFindingsForProject]);

  const stats = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
    INFO: findings.filter(f => f.severity === 'INFO').length,
    total: findings.length,
  };

  const avgRiskScore = findings.length > 0
    ? Math.round(findings.reduce((acc, f) => acc + (f.ai_risk_score || 0), 0) / findings.length)
    : 0;
  const maxRiskScore = findings.length > 0 ? Math.max(...findings.map(f => f.ai_risk_score || 0)) : 0;
  const topSeverity = findings.some(f => f.ai_severity === 'CRITICAL') ? 'CRITICAL'
    : findings.some(f => f.ai_severity === 'HIGH') ? 'HIGH'
    : findings.some(f => f.ai_severity === 'MEDIUM') ? 'MEDIUM' : null;

  const filtered = filter === 'ALL' ? findings : findings.filter(f => f.severity === filter);

  return (
    <div className="fade-in">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <div className="page-title">
            <span>Vulnerability Dashboard</span>
            <span className="ai-enhanced-tag">✨ AI Enhanced</span>
          </div>
          <div className="page-subtitle">AI-powered access control analysis with real-time risk scoring</div>
        </div>
        <div className="page-header-actions">
          <button 
            className="btn btn-secondary" 
            onClick={() => loadFindingsForProject(selectedProject)}
            disabled={findingsLoading || !selectedProject}
            style={{ position: 'relative' }}
          >
            {findingsLoading ? <span className="spinner" style={{ width: 12, height: 12, marginRight: 8 }} /> : '🔄'} Sync
          </button>
          {findings.length > 0 && (
            <PDFExportButton findings={findings} projectName={selectedProject?.name || 'Project'} />
          )}
          <button className="btn btn-primary" onClick={() => navigate('/scanner')}>
            + New Scan
          </button>
        </div>
      </div>

      {/* AI Banner */}
      <AIIntroBanner />

      {/* Stats Grid */}
      <div className="stats-grid">
        <StatCard label="Total Findings" value={stats.total} severity="total" icon="📋" />
        <StatCard label="Critical" value={stats.CRITICAL} severity="critical" icon="🔴" />
        <StatCard label="High" value={stats.HIGH} severity="high" icon="🟠" />
        <StatCard label="Medium" value={stats.MEDIUM} severity="medium" icon="🟡" />
        <StatCard label="Low / Info" value={stats.LOW + stats.INFO} severity="low" icon="🟢" />
      </div>

      {/* Score Summary (only when data) */}
      {findings.length > 0 && (
        <>
          <ScoreSummary
            avgScore={avgRiskScore}
            maxScore={maxRiskScore}
            topSeverity={topSeverity}
            total={findings.length}
          />
          <AIRiskRow findings={findings} />
        </>
      )}

      {/* Project Selector */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <div className="card-title">📁 Projects</div>
          <button className="btn btn-secondary btn-sm" onClick={() => navigate('/scanner')}>+ New Project</button>
        </div>
        {loading ? (
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
            <span className="spinner" /> Loading projects...
          </div>
        ) : projects.length === 0 ? (
          <div className="empty-state" style={{ padding: '32px 0' }}>
            <span className="empty-state-icon">📁</span>
            <div className="empty-state-title">No projects yet</div>
            <div className="empty-state-desc">Create a project in the Scanner to start finding vulnerabilities.</div>
          </div>
        ) : (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {projects.map(p => (
              <button
                key={p.id}
                className={`btn ${selectedProject?.id === p.id ? 'btn-primary' : 'btn-secondary'} btn-sm`}
                onClick={() => setSelectedProject(p)}
              >
                {selectedProject?.id === p.id ? '✓ ' : ''}{p.name}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Findings Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            🐛 Findings
            {findings.length > 0 && (
              <span className="cyber-tag">{findings.length} total</span>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {['ALL', ...SEVERITY_ORDER.slice(0, 4)].map(s => (
              <button
                key={s}
                className={`btn btn-sm ${filter === s ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setFilter(s)}
              >
                {s === 'ALL' ? 'All' : `${SEVERITY_ICONS[s]} ${s}`}
              </button>
            ))}
          </div>
        </div>

        {findingsLoading ? (
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', color: 'var(--text-muted)', fontSize: 13, padding: '20px 0' }}>
            <span className="spinner" /> Loading findings...
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <span className="empty-state-icon" style={{ fontSize: 48 }}>🎯</span>
            <div className="empty-state-title">No findings to display</div>
            <div className="empty-state-desc">
              {findings.length === 0
                ? 'Run a scan from the Scanner page. Results will appear here automatically.'
                : `No ${filter} severity findings.`}
            </div>
            {findings.length === 0 && (
              <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={() => navigate('/scanner')}>
                🚀 Go to Scanner
              </button>
            )}
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Severity</th>
                  <th>Vulnerability Type</th>
                  <th>Endpoint</th>
                  <th>Method</th>
                  <th>AI Risk Score</th>
                  <th>AI Reasoning</th>
                  <th>CWE</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((f, i) => (
                  <tr key={f.id || i}>
                    <td style={{ color: 'var(--text-muted)', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
                      {i + 1}
                    </td>
                    <td><span className={`badge ${f.severity}`}>{SEVERITY_ICONS[f.severity]} {f.severity}</span></td>
                    <td><span className="vuln-chip">{f.vuln_type?.replace(/_/g, ' ')}</span></td>
                    <td style={{
                      fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5,
                      color: 'var(--info)', maxWidth: 200,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>
                      {f.endpoint}
                    </td>
                    <td>
                      <span style={{
                        fontFamily: 'JetBrains Mono, monospace', fontSize: 10.5, fontWeight: 700,
                        padding: '2px 8px', borderRadius: 4,
                        background: f.method === 'GET' ? 'rgba(52,211,153,0.08)' : f.method === 'DELETE' ? 'rgba(244,63,94,0.08)' : 'rgba(56,189,248,0.08)',
                        color: f.method === 'GET' ? 'var(--low)' : f.method === 'DELETE' ? 'var(--critical)' : 'var(--info)',
                      }}>
                        {f.method}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <RiskScoreMeter score={f.ai_risk_score || 0} severity={f.ai_severity || 'LOW'} size={40} animate={false} />
                        <span className="risk-score-num" style={{ color: getRiskColor(f.ai_risk_score) }}>
                          {f.ai_risk_score ? `${f.ai_risk_score}/100` : '—'}
                        </span>
                      </div>
                    </td>
                    <td>
                      {f.ai_reasoning ? (
                        <span style={{ fontSize: 10.5, color: 'var(--text-secondary)', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden', maxWidth: 260, lineHeight: 1.4 }}>
                          🤖 {f.ai_reasoning}
                        </span>
                      ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                    </td>
                    <td>
                      {f.cwe_id ? (
                        <a href={`https://cwe.mitre.org/data/definitions/${f.cwe_id.replace('CWE-', '')}.html`}
                          target="_blank" rel="noreferrer"
                          style={{ fontSize: 11.5, color: 'var(--accent)', fontFamily: 'JetBrains Mono', textDecoration: 'none', fontWeight: 600 }}>
                          {f.cwe_id}
                        </a>
                      ) : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>}
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => setSelectedFinding(f)}
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal */}
      {selectedFinding && (
        <FindingModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
