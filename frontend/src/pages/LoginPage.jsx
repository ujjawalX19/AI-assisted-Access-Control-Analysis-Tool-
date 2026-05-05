import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import useAuthStore from '../store/authStore';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { login, isLoading, error } = useAuthStore();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await login(email, password);
    if (result.success) navigate('/dashboard');
  };

  return (
    <div className="auth-page">
      {/* Floating grid dots decoration */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none',
        backgroundImage: `radial-gradient(circle, rgba(124,109,248,0.15) 1px, transparent 1px)`,
        backgroundSize: '40px 40px',
        maskImage: 'radial-gradient(ellipse at center, black 0%, transparent 70%)',
        WebkitMaskImage: 'radial-gradient(ellipse at center, black 0%, transparent 70%)',
      }} />

      <div className="auth-card fade-in">
        {/* Logo */}
        <div className="auth-logo">
          <div className="auth-logo-icon">🛡️</div>
          <div className="auth-title">BAC Scanner</div>
          <div className="auth-subtitle">AI-Enhanced Access Control Analysis</div>
        </div>

        {/* Feature pills */}
        <div style={{ display: 'flex', gap: 6, justifyContent: 'center', marginBottom: 24, flexWrap: 'wrap' }}>
          {['🤖 AI Scoring', '📄 PDF Reports', '🔐 OWASP A01'].map(tag => (
            <span key={tag} style={{
              fontSize: 10, fontWeight: 700, padding: '3px 10px', borderRadius: 100,
              background: 'rgba(124,109,248,0.08)', border: '1px solid rgba(124,109,248,0.2)',
              color: 'var(--accent)', letterSpacing: 0.3,
            }}>{tag}</span>
          ))}
        </div>

        {/* Divider */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 22 }}>
          <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: 0.5 }}>SIGN IN</span>
          <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
        </div>

        {error && (
          <div className="alert error" style={{ marginBottom: 16 }}>
            <span>⚠️</span> {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Email Address</label>
            <div style={{ position: 'relative' }}>
              <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', fontSize: 15, pointerEvents: 'none' }}>✉️</span>
              <input
                id="login-email"
                className="input"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
                style={{ paddingLeft: 36 }}
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <div style={{ position: 'relative' }}>
              <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', fontSize: 14, pointerEvents: 'none' }}>🔒</span>
              <input
                id="login-password"
                className="input"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                style={{ paddingLeft: 36 }}
              />
            </div>
          </div>

          <button
            id="login-submit"
            type="submit"
            className="btn btn-primary btn-lg"
            style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}
            disabled={isLoading}
          >
            {isLoading ? (
              <><span className="spinner" style={{ width: 16, height: 16 }} /> Authenticating...</>
            ) : (
              <> Sign In →</>
            )}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 22, fontSize: 13, color: 'var(--text-muted)' }}>
          No account?{' '}
          <Link to="/register" style={{ color: 'var(--accent)', fontWeight: 700, textDecoration: 'none' }}>
            Create one free →
          </Link>
        </p>

        <div style={{
          marginTop: 24, padding: '12px 16px',
          background: 'rgba(45, 212, 191, 0.05)', border: '1px solid rgba(45, 212, 191, 0.15)',
          borderRadius: 'var(--radius-sm)', fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6,
        }}>
          <span style={{ color: 'var(--teal)', fontWeight: 700 }}>ℹ️ Demo Mode:</span> No Docker required.
          Register an account and run a scan against the demo target on port 8001.
        </div>
      </div>
    </div>
  );
}
