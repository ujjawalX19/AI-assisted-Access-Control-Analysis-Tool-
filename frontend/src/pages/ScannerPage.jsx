import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { projectsAPI, requestsAPI, scansAPI, demoAPI } from '../services/api';
import RiskScoreMeter from '../components/RiskScoreMeter';
import PDFExportButton from '../components/PDFExport';

const MODULES = [
  { key: 'idor', label: 'IDOR Detection', icon: '🎯', desc: 'Mutates IDs to access other users\' resources', risk: 'HIGH' },
  { key: 'auth_bypass', label: 'Auth Bypass', icon: '🔓', desc: 'Tests missing/null/invalid tokens', risk: 'CRITICAL' },
  { key: 'privilege_escalation', label: 'Privilege Escalation', icon: '⬆️', desc: 'Tests low-priv access to admin endpoints', risk: 'CRITICAL' },
  { key: 'method_manipulation', label: 'Method Manipulation', icon: '🔄', desc: 'Tests unexpected HTTP methods', risk: 'MEDIUM' },
];

const DEMO_REQUEST = `GET /api/users/2/profile HTTP/1.1
Host: localhost:8001
Authorization: Bearer YOUR_TOKEN_HERE
Accept: application/json`;

const RISK_COLORS = { CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)' };

function getRiskColor(score) {
  if (!score) return 'var(--text-muted)';
  if (score >= 85) return 'var(--critical)';
  if (score >= 68) return 'var(--high)';
  if (score >= 45) return 'var(--medium)';
  return 'var(--low)';
}

export default function ScannerPage() {
  const [step, setStep] = useState(1);
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState(null);
  const [newProjectName, setNewProjectName] = useState('');
  const [rawRequest, setRawRequest] = useState('');
  const [requestName, setRequestName] = useState('');
  const [tokens, setTokens] = useState([{ label: '', token: '' }]);
  const [enabledModules, setEnabledModules] = useState(MODULES.map(m => m.key));
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressMsg, setProgressMsg] = useState('');
  const [results, setResults] = useState([]);
  const [error, setError] = useState('');
  const [demoTokens, setDemoTokens] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const pollRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    projectsAPI.list().then(r => setProjects(r.data)).catch(() => {});
    demoAPI.tokens().then(r => setDemoTokens(r.data.demo_tokens || [])).catch(() => {});
  }, []);

  const createProject = async () => {
    if (!newProjectName.trim()) return;
    const r = await projectsAPI.create({ name: newProjectName });
    setProjects(p => [r.data, ...p]);
    setSelectedProject(r.data);
    setNewProjectName('');
  };

  const addToken = () => setTokens(t => [...t, { label: '', token: '' }]);
  const removeToken = (i) => setTokens(t => t.filter((_, idx) => idx !== i));
  const updateToken = (i, field, val) => setTokens(t => t.map((tok, idx) => idx === i ? { ...tok, [field]: val } : tok));

  const loadDemoTokens = () => {
    setTokens(demoTokens.map(dt => ({ label: dt.label, token: dt.token })));
  };

  const handleAutoConfigure = async () => {
    setError('');
    try {
      // 1. Create a project
      const projName = `Analysis: Demo Target (${new Date().toLocaleTimeString()})`;
      const r = await projectsAPI.create({ name: projName });
      setProjects(p => [r.data, ...p]);
      setSelectedProject(r.data);
      
      // 2. Set the request data
      setRawRequest(DEMO_REQUEST);
      setRequestName("Demo Profile Scan");
      
      // 3. Load tokens
      setTokens(demoTokens.map(dt => ({ label: dt.label, token: dt.token })));
      
      // 4. Pre-enable all modules
      setEnabledModules(MODULES.map(m => m.key));
      
      // 5. Jump to Step 2
      setStep(2);
      
      // Success feedback (internal)
      console.log("Auto-configuration completed successfully.");
    } catch (e) {
      setError("Auto-configuration failed. Ensure the backend and demo-target are running.");
    }
  };

  const toggleModule = (key) => {
    setEnabledModules(m => m.includes(key) ? m.filter(k => k !== key) : [...m, key]);
  };

  const startScan = async () => {
    setError('');
    if (!selectedProject) return setError('Please select or create a project first.');
    if (!rawRequest.trim()) return setError('Please paste an HTTP request to scan.');
    if (tokens.filter(t => t.token).length === 0) return setError('Add at least one user token (or use demo tokens).');

    try {
      console.log("Creating API request for project:", selectedProject.id);
      const reqRes = await requestsAPI.create({
        project_id: selectedProject.id,
        name: requestName || 'Unnamed Request',
        raw_request: rawRequest,
        user_tokens: tokens.filter(tok => tok.token && tok.label),
      });

      console.log("Starting scan task...");
      const scanRes = await scansAPI.start({
        api_request_id: reqRes.data.id,
        enabled_modules: enabledModules,
      });

      const sid = scanRes.data.scan_id;
      if (!sid) throw new Error("No scan ID received from server.");
      
      setScanning(true);
      setProgress(0);
      setProgressMsg('Warming up AI engine...');
      setResults([]);

      if (pollRef.current) clearInterval(pollRef.current);
      
      pollRef.current = setInterval(async () => {
        try {
          const statusRes = await scansAPI.status(sid);
          const { status, progress: prog, message } = statusRes.data;
          
          console.log(`Scan Status: ${status} (${prog}%) - ${message}`);
          setProgress(prog);
          setProgressMsg(message);

          // Celery states: SUCCESS, FAILURE, REVOKED, etc.
          if (status === 'SUCCESS' || status === 'COMPLETED' || prog >= 100) {
            console.log("Scan finished. Fetching results...");
            clearInterval(pollRef.current);
            
            // Small delay to ensure DB persistence is fully committed
            setTimeout(async () => {
              try {
                const resultsRes = await scansAPI.results(sid);
                const findings = resultsRes.data;
                console.log(`Received ${findings.length} findings.`);
                setResults(findings);
                setScanning(false);
                setStep(3);
                
                localStorage.setItem('bac_last_findings', JSON.stringify(findings));
                localStorage.setItem('bac_last_project_id', String(selectedProject.id));
                localStorage.setItem('bac_last_scan_id', sid);
              } catch (err) {
                console.error("Failed to fetch scan results:", err);
                setError("Scan finished but failed to retrieve results. Check dashboard.");
                setScanning(false);
              }
            }, 800);
          } else if (status === 'FAILURE' || status === 'REVOKED') {
            clearInterval(pollRef.current);
            setScanning(false);
            setError(`Scan task failed server-side (${status}). Ensure Worker is running.`);
          }
        } catch (e) {
          console.error("Polling error:", e);
          // Don't clear interval immediately, might be a transient network blip
          setProgressMsg('Retrying connection...');
        }
      }, 2000);

    } catch (e) {
      console.error("Start scan failed:", e);
      setError(e.response?.data?.detail || e.message || 'Failed to start scan. Is the backend running?');
    }
  };

  useEffect(() => () => clearInterval(pollRef.current), []);

  return (
    <div className="fade-in">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <div className="page-title">
            🔍 Scanner
            <span className="ai-enhanced-tag">🤖 AI Scoring</span>
          </div>
          <div className="page-subtitle">Configure and launch access control vulnerability scans</div>
        </div>
        <div className="page-header-actions">
          <button 
            className="btn btn-primary" 
            style={{ 
              background: 'linear-gradient(135deg, #10b981, #059669)',
              border: 'none',
              boxShadow: '0 0 20px rgba(16, 185, 129, 0.3)'
            }}
            onClick={handleAutoConfigure}
          >
            ➕ Magic Auto-Configure
          </button>
          {results.length > 0 && (
            <>
              <PDFExportButton findings={results} projectName={selectedProject?.name || 'Project'} />
              <button className="btn btn-secondary" onClick={() => navigate('/dashboard')}>
                📊 View Dashboard
              </button>
            </>
          )}
        </div>
      </div>

      <div className="ai-intro-banner" style={{ border: '1px solid rgba(16, 185, 129, 0.2)', background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.08), rgba(6, 78, 59, 0.05))', marginBottom: 24 }}>
        <div className="ai-intro-icon" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#10b981' }}>⚡</div>
        <div className="ai-intro-content">
          <div className="ai-intro-title" style={{ color: '#10b981' }}>New to BAC Scanner?</div>
          <div className="ai-intro-text">
            Use the <strong>Magic Auto-Configure</strong> button to instantly set up a demo project, load persona tokens, and populate a vulnerable target request. Perfect for exploring AI-powered risk scoring.
          </div>
        </div>
        <button 
          className="btn btn-sm btn-primary" 
          onClick={handleAutoConfigure}
          style={{ background: '#10b981', marginLeft: 'auto' }}
        >
          Auto-Configure Now
        </button>
      </div>

      {error && (
        <div className="alert error">
          <span>⚠️</span>
          <div>{error}</div>
        </div>
      )}

      {/* Step indicators */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 24 }}>
        {['Project', 'Request & Config', 'Results'].map((label, idx) => (
          <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{
              width: 24, height: 24, borderRadius: '50%', display: 'flex', alignItems: 'center',
              justifyContent: 'center', fontSize: 11, fontWeight: 800, flexShrink: 0,
              background: step > idx + 1 ? 'var(--low)' : step === idx + 1 ? 'linear-gradient(135deg, var(--accent), var(--accent-2))' : 'rgba(255,255,255,0.06)',
              color: step >= idx + 1 ? 'white' : 'var(--text-muted)',
              boxShadow: step === idx + 1 ? '0 0 15px rgba(124,109,248,0.4)' : 'none',
            }}>
              {step > idx + 1 ? '✓' : idx + 1}
            </div>
            <span style={{ fontSize: 12, fontWeight: 600, color: step === idx + 1 ? 'var(--accent)' : step > idx + 1 ? 'var(--low)' : 'var(--text-muted)' }}>
              {label}
            </span>
            {idx < 2 && <div style={{ width: 24, height: 1, background: step > idx + 1 ? 'var(--low)' : 'var(--border)', flexShrink: 0 }} />}
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20, alignItems: 'start' }}>
        {/* Left column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Step 1: Project */}
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
              <div style={{ width: 22, height: 22, borderRadius: '50%', background: selectedProject ? 'var(--low)' : 'linear-gradient(135deg, var(--accent), var(--accent-2))', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 800, color: 'white' }}>
                {selectedProject ? '✓' : '1'}
              </div>
              <div className="card-title">Select or Create Project</div>
            </div>

            <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
              {projects.map(p => (
                <button key={p.id}
                  className={`btn btn-sm ${selectedProject?.id === p.id ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => setSelectedProject(p)}>
                  {selectedProject?.id === p.id ? '✓ ' : ''}{p.name}
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="input" placeholder="New project name..." value={newProjectName}
                onChange={e => setNewProjectName(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && createProject()} />
              <button className="btn btn-secondary" onClick={createProject} style={{ flexShrink: 0 }}>+ Create</button>
            </div>
            {selectedProject && (
              <div className="alert info" style={{ marginTop: 10, marginBottom: 0 }}>
                ✅ Active project: <strong>{selectedProject.name}</strong>
              </div>
            )}
          </div>

          {/* Step 2: HTTP Request */}
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
              <div style={{ width: 22, height: 22, borderRadius: '50%', background: 'linear-gradient(135deg, var(--accent), var(--accent-2))', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 800, color: 'white' }}>2</div>
              <div className="card-title">Paste Raw HTTP Request</div>
              <span className="cyber-tag">Burp Suite format</span>
            </div>

            <div className="form-group">
              <label className="form-label">Request Name (optional)</label>
              <input className="input" placeholder="e.g. Get User Profile"
                value={requestName} onChange={e => setRequestName(e.target.value)} />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">HTTP Request</label>
              <textarea className="textarea code-input" placeholder={DEMO_REQUEST}
                value={rawRequest} onChange={e => setRawRequest(e.target.value)} />
            </div>
          </div>

          {/* Attack Modules */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">⚙️ Attack Modules</div>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {enabledModules.length}/{MODULES.length} enabled
              </span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              {MODULES.map(m => {
                const active = enabledModules.includes(m.key);
                return (
                  <div key={m.key}
                    className={`module-card ${active ? 'active' : ''}`}
                    onClick={() => toggleModule(m.key)}>
                    <span style={{ fontSize: 20, flexShrink: 0 }}>{m.icon}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                        <div style={{ fontSize: 12.5, fontWeight: 700, color: active ? '#b8adff' : 'var(--text-secondary)' }}>
                          {m.label}
                        </div>
                        <span style={{ fontSize: 9, fontWeight: 800, padding: '1px 6px', borderRadius: 100, background: `${RISK_COLORS[m.risk]}18`, color: RISK_COLORS[m.risk], border: `1px solid ${RISK_COLORS[m.risk]}40` }}>
                          {m.risk}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>{m.desc}</div>
                    </div>
                    <div style={{ width: 18, height: 18, borderRadius: '50%', border: `2px solid ${active ? 'var(--accent)' : 'var(--border)'}`, background: active ? 'var(--accent)' : 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, transition: 'all 0.2s' }}>
                      {active && <span style={{ color: 'white', fontSize: 10 }}>✓</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

          {/* Tokens */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">👥 User Tokens</div>
            </div>

            {demoTokens.length > 0 && (
              <button className="btn btn-secondary btn-sm" style={{ marginBottom: 14, width: '100%', justifyContent: 'center' }} onClick={loadDemoTokens}>
                🎯 Load Demo Target Tokens
              </button>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 340, overflowY: 'auto' }}>
              {tokens.map((tok, i) => (
                <div key={i} style={{
                  padding: '12px 14px', background: 'rgba(255,255,255,0.02)',
                  borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{ width: 20, height: 20, borderRadius: '50%', background: `hsl(${i * 60 + 240}, 70%, 65%)`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 800, color: '#0a0810' }}>
                        {i + 1}
                      </div>
                      <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Persona {i + 1}</span>
                    </div>
                    {tokens.length > 1 && (
                      <button className="btn btn-danger btn-sm" style={{ padding: '2px 8px', fontSize: 10 }} onClick={() => removeToken(i)}>✕</button>
                    )}
                  </div>
                  <input className="input" placeholder="Label (e.g. Admin, Alice, Bob)"
                    style={{ marginBottom: 6, fontSize: 12 }}
                    value={tok.label} onChange={e => updateToken(i, 'label', e.target.value)} />
                  <input className="input" placeholder="Bearer token (empty = no auth test)"
                    value={tok.token} onChange={e => updateToken(i, 'token', e.target.value)}
                    style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10.5 }} />
                </div>
              ))}
            </div>

            <button className="btn btn-secondary" style={{ width: '100%', justifyContent: 'center', marginTop: 10 }} onClick={addToken}>
              + Add Persona
            </button>
          </div>

          {/* Launch Panel */}
          <div className="card">
            {scanning ? (
              <div>
                <div style={{ textAlign: 'center', marginBottom: 20 }}>
                  <div style={{ fontSize: 40, marginBottom: 10 }} className="pulse">🔍</div>
                  <div style={{ fontWeight: 800, color: 'var(--text-primary)', fontSize: 15, marginBottom: 4 }}>Scanning...</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{progressMsg}</div>
                </div>
                <div className="progress-bar" style={{ marginBottom: 10, height: 8 }}>
                  <div className="progress-fill" style={{ width: `${progress}%` }} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)' }}>
                  <span>Running AI risk analysis...</span>
                  <span style={{ color: 'var(--accent)', fontWeight: 800, fontFamily: 'JetBrains Mono' }}>{progress}%</span>
                </div>
              </div>
            ) : step === 3 && results.length >= 0 ? (
              <div>
                <div className="alert success" style={{ marginBottom: 14 }}>
                  ✅ Scan complete! <strong>{results.length}</strong> findings detected.
                </div>
                <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', marginBottom: 8 }}
                  onClick={() => navigate('/dashboard')}>
                  📊 View Dashboard
                </button>
                <button className="btn btn-secondary" style={{ width: '100%', justifyContent: 'center' }}
                  onClick={() => { setStep(1); setResults([]); }}>
                  + New Scan
                </button>
              </div>
            ) : (
              <div>
                <div style={{ marginBottom: 16, padding: '12px 14px', background: 'rgba(124,109,248,0.05)', borderRadius: 8, border: '1px solid rgba(124,109,248,0.1)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 3, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>Ready to scan?</div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                    {enabledModules.length} modules · {tokens.filter(t => t.token).length} token{tokens.filter(t => t.token).length !== 1 ? 's' : ''}
                  </div>
                </div>
                <button id="start-scan-btn" className="btn btn-primary btn-xl"
                  style={{ width: '100%', justifyContent: 'center' }}
                  onClick={startScan}>
                  🚀 Start AI Scan
                </button>
              </div>
            )}
          </div>

          {/* Quick Stats (after scan) */}
          {results.length > 0 && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 14 }}>🐛 Quick Results</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 12 }}>
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                  const count = results.filter(r => r.severity === sev).length;
                  return (
                    <div key={sev} style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: 8, border: `1px solid ${count > 0 ? `rgba(244,63,94,0.15)` : 'var(--border)'}`, textAlign: 'center' }}>
                      <div style={{ fontSize: 20, fontWeight: 900, color: `var(--${sev.toLowerCase()})`, fontFamily: 'Outfit' }}>{count}</div>
                      <div style={{ fontSize: 9.5, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5 }}>{sev}</div>
                    </div>
                  );
                })}
              </div>

              <div style={{ maxHeight: 320, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                {results.length === 0 ? (
                  <div className="empty-state" style={{ padding: '20px 0' }}>
                    <div style={{ fontSize: 24, marginBottom: 8 }}>🛡️</div>
                    <div style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 700 }}>No Vulnerabilities Found</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>The AI analysis suggests this endpoint is properly protected.</div>
                  </div>
                ) : (
                  results.map((r, i) => (
                    <div key={i}
                      onClick={() => setSelectedFinding(r)}
                      style={{
                        padding: '11px 13px', background: 'rgba(255,255,255,0.02)',
                        borderRadius: 8,
                        border: `1px solid ${r.ai_severity === 'CRITICAL' ? 'rgba(244,63,94,0.25)' : r.ai_severity === 'HIGH' ? 'rgba(251,146,60,0.2)' : 'var(--border)'}`,
                        cursor: 'pointer', transition: 'all 0.15s',
                      }}
                      onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(124,109,248,0.3)'}
                      onMouseLeave={e => e.currentTarget.style.borderColor = r.ai_severity === 'CRITICAL' ? 'rgba(244,63,94,0.25)' : r.ai_severity === 'HIGH' ? 'rgba(251,146,60,0.2)' : 'var(--border)'}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 6 }}>
                        <span className={`badge ${r.severity || 'INFO'}`} style={{ fontSize: 9 }}>{r.severity || 'INFO'}</span>
                        <span className="vuln-chip" style={{ fontSize: 10 }}>{r.vuln_type?.replace(/_/g, ' ')}</span>
                        {r.ai_risk_score != null && (
                          <span style={{ marginLeft: 'auto', fontSize: 11, fontWeight: 800, color: getRiskColor(r.ai_risk_score), fontFamily: 'JetBrains Mono' }}>
                            {r.ai_risk_score}/100
                          </span>
                        )}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <RiskScoreMeter score={r.ai_risk_score || 0} severity={r.ai_severity || r.severity || 'LOW'} size={36} animate={false} />
                        <div style={{ flex: 1, overflow: 'hidden' }}>
                          <div style={{ fontSize: 10.5, fontFamily: 'JetBrains Mono', color: 'var(--info)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {r.endpoint}
                          </div>
                          {r.ai_reasoning && (
                            <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 4, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden', lineHeight: 1.4 }}>
                              🤖 <strong style={{ color: 'var(--accent)' }}>Logic:</strong> {r.ai_reasoning}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Finding Quick View Modal */}
      {selectedFinding && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 1000, padding: 24, backdropFilter: 'blur(10px)',
        }} onClick={e => e.target === e.currentTarget && setSelectedFinding(null)}>
          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border-light)',
            borderRadius: 'var(--radius-xl)', width: '100%', maxWidth: 640,
            padding: 28, boxShadow: 'var(--shadow)', animation: 'fadeInUp 0.2s ease',
            position: 'relative',
          }}>
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: 'linear-gradient(90deg, var(--accent), var(--accent-2))', borderRadius: '20px 20px 0 0' }} />
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 18, alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className={`badge ${selectedFinding.severity}`}>{selectedFinding.severity}</span>
                <span className="vuln-chip">{selectedFinding.vuln_type?.replace(/_/g, ' ')}</span>
              </div>
              <button className="btn btn-ghost btn-sm" onClick={() => setSelectedFinding(null)}>✕</button>
            </div>
            <div style={{ display: 'flex', gap: 20, marginBottom: 20 }}>
              <RiskScoreMeter score={selectedFinding.ai_risk_score || 0} severity={selectedFinding.ai_severity || 'LOW'} size={90} />
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6, fontWeight: 700 }}>AI Reasoning</div>
                <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                  {selectedFinding.ai_reasoning || 'No AI reasoning available.'}
                </p>
              </div>
            </div>
            <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.7, background: 'rgba(0,0,0,0.2)', padding: '14px 16px', borderRadius: 8 }}>
              {selectedFinding.explanation?.substring(0, 300)}...
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
