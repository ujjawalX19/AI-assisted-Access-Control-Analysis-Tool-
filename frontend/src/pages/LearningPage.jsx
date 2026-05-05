import { useState } from 'react';

const LEARNING_ENTRIES = [
  {
    key: 'IDOR',
    icon: '🎯',
    title: 'Insecure Direct Object Reference (IDOR)',
    cwe: 'CWE-639',
    owasp: 'OWASP A01:2021',
    severity: 'CRITICAL',
    explanation: `IDOR occurs when an application uses user-supplied input to access objects directly without proper authorization checks. An attacker can manipulate resource identifiers (IDs, UUIDs) to access other users' data.`,
    example: `GET /api/users/42/profile → attacker changes 42 to 43 and gets another user's sensitive profile data including SSN, credit card, etc.`,
    fix: `// BAD: directly uses user-supplied ID
const user = await db.findUser(userId);

// GOOD: enforce ownership check
const user = await db.findUserWhere({ 
  id: userId,
  ownerId: currentUser.id  // ← ownership check!
});
if (!user) throw new ForbiddenError();`,
    testTip: 'Paste the vulnerable profile endpoint and add two user tokens (Admin + Alice). The scanner will try accessing Alice\'s profile with Admin token and vice versa.',
  },
  {
    key: 'AUTH_BYPASS',
    icon: '🔓',
    title: 'Authentication Bypass',
    cwe: 'CWE-306',
    owasp: 'OWASP A01:2021',
    severity: 'CRITICAL',
    explanation: `Authentication bypass occurs when an endpoint that should require a valid token can be accessed without one. Common causes: missing middleware, incorrect route ordering, or trusting the presence of any Authorization header value.`,
    example: `GET /api/admin/stats with NO Authorization header → returns 200 OK with sensitive data. Expected: 401 Unauthorized.`,
    fix: `// FastAPI: Never use optional auth on protected routes
@router.get("/admin/stats")
async def stats(user = Depends(get_current_user)):  # ← required!
    return ...

// Express: Apply auth middleware globally
app.use('/api', authMiddleware);  # ← not route-by-route`,
    testTip: 'Paste the admin endpoint. The scanner automatically tests with no token, "Bearer null", "Bearer undefined", and header injection techniques.',
  },
  {
    key: 'PRIVILEGE_ESCALATION',
    icon: '⬆️',
    title: 'Privilege Escalation',
    cwe: 'CWE-269',
    owasp: 'OWASP A01:2021',
    severity: 'CRITICAL',
    explanation: `Privilege escalation happens when a lower-privileged user can access admin-only endpoints. Often caused by trusting role information from request headers (X-Role, X-Admin) instead of the validated JWT payload.`,
    example: `GET /api/admin/users with Alice's token + "X-Role: admin" header → returns full user list. Only the JWT role should be trusted.`,
    fix: `# Python: Extract role from validated JWT ONLY
@router.get("/admin/users")
async def list_users(current_user = Depends(require_admin)):
    # require_admin reads role from JWT, not headers
    return await db.get_all_users()

# NEVER DO THIS:
role = request.headers.get("X-Role")  # ← attacker-controlled!`,
    testTip: 'Add an Admin token and a regular User token. The scanner tests the endpoint with the user token and tries X-Role header injection.',
  },
  {
    key: 'METHOD_MANIPULATION',
    icon: '🔄',
    title: 'HTTP Method Manipulation',
    cwe: 'CWE-650',
    owasp: 'OWASP A01:2021',
    severity: 'MEDIUM',
    explanation: `Some APIs apply access control only to specific HTTP methods (e.g., only protect POST but leave GET/DELETE open). Attackers switch the HTTP method to bypass restrictions on the same endpoint.`,
    example: `GET /api/documents/101 → 403 (protected)\nDELETE /api/documents/101 → 200 (no auth check on DELETE!)`,
    fix: `// Express: Explicitly define and protect each method
router.get('/documents/:id', auth, getDoc);
router.put('/documents/:id', auth, ownerOnly, updateDoc);
router.delete('/documents/:id', auth, ownerOnly, deleteDoc);
// Don't use: router.all('/documents/:id', handler)`,
    testTip: 'Paste a GET endpoint. The scanner automatically tests GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD on the same path.',
  },
];

export default function LearningPage() {
  const [selected, setSelected] = useState(LEARNING_ENTRIES[0]);
  const [tab, setTab] = useState('explanation');

  const SEVERITY_MAP = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">📚 Learning Mode</div>
          <div className="page-subtitle">Understand vulnerabilities, see real examples, and learn how to fix them</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 20 }}>
        {/* Left: Vulnerability list */}
        <div>
          {LEARNING_ENTRIES.map(entry => (
            <div key={entry.key}
              onClick={() => { setSelected(entry); setTab('explanation'); }}
              style={{
                padding: '14px 16px', marginBottom: 8, borderRadius: 'var(--radius)',
                border: `1px solid ${selected.key === entry.key ? 'rgba(124,109,248,0.4)' : 'var(--border)'}`,
                background: selected.key === entry.key ? 'var(--accent-glow)' : 'var(--bg-card)',
                cursor: 'pointer', transition: 'all 0.15s',
              }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
                <span style={{ fontSize: 18 }}>{entry.icon}</span>
                <span className={`badge ${entry.severity}`} style={{ fontSize: 10 }}>{entry.severity}</span>
              </div>
              <div style={{ fontSize: 13, fontWeight: 600, color: selected.key === entry.key ? 'var(--accent)' : 'var(--text-primary)', lineHeight: 1.4 }}>
                {entry.title}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                {entry.cwe} · {entry.owasp}
              </div>
            </div>
          ))}
        </div>

        {/* Right: Detail */}
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, paddingBottom: 16, borderBottom: '1px solid var(--border)' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span style={{ fontSize: 24 }}>{selected.icon}</span>
                <span className={`badge ${selected.severity}`} style={{ fontSize: 11 }}>{selected.severity}</span>
              </div>
              <h2 style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 4 }}>
                {selected.title}
              </h2>
              <div style={{ display: 'flex', gap: 8 }}>
                <a href={`https://cwe.mitre.org/data/definitions/${selected.cwe.replace('CWE-','')}.html`}
                  target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm">
                  🔗 {selected.cwe}
                </a>
                <span className="btn btn-secondary btn-sm" style={{ cursor: 'default' }}>📋 {selected.owasp}</span>
              </div>
            </div>
          </div>

          <div className="tabs">
            {[
              { key: 'explanation', label: '💡 Explanation' },
              { key: 'example', label: '⚡ Example' },
              { key: 'fix', label: '🔧 Fix' },
              { key: 'test', label: '🧪 How to Test' },
            ].map(t => (
              <div key={t.key} className={`tab ${tab === t.key ? 'active' : ''}`} onClick={() => setTab(t.key)}>
                {t.label}
              </div>
            ))}
          </div>

          {tab === 'explanation' && (
            <div style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.8, paddingBottom: 16 }}>
              {selected.explanation}
            </div>
          )}

          {tab === 'example' && (
            <div style={{ paddingBottom: 16 }}>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>Real-world attack scenario:</div>
              <pre className="code-block" style={{ whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.7 }}>
                {selected.example}
              </pre>
            </div>
          )}

          {tab === 'fix' && (
            <div style={{ paddingBottom: 16 }}>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>Secure code example:</div>
              <pre className="code-block" style={{ whiteSpace: 'pre-wrap' }}>
                {selected.fix}
              </pre>
            </div>
          )}

          {tab === 'test' && (
            <div style={{ paddingBottom: 16 }}>
              <div className="alert info" style={{ marginBottom: 16 }}>
                💡 {selected.testTip}
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                Use the <strong style={{ color: 'var(--accent)' }}>Scanner page</strong> to test this vulnerability against the demo target API (running on localhost:8001). The scanner will automatically apply the appropriate attack module.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
