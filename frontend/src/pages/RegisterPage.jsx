import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import useAuthStore from '../store/authStore';

export default function RegisterPage() {
  const [form, setForm] = useState({ full_name: '', email: '', password: '', confirm: '' });
  const [success, setSuccess] = useState(false);
  const { register, isLoading, error } = useAuthStore();
  const navigate = useNavigate();

  const handleChange = (e) => setForm(f => ({ ...f, [e.target.name]: e.target.value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (form.password !== form.confirm) return alert('Passwords do not match');
    const result = await register(form.email, form.password, form.full_name);
    if (result.success) {
      setSuccess(true);
      setTimeout(() => navigate('/login'), 1500);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card fade-in">
        <div className="auth-logo">
          <div className="auth-logo-icon">🔍</div>
          <div className="auth-title">Create Account</div>
          <div className="auth-subtitle">Start scanning for access control vulnerabilities</div>
        </div>

        {success && (
          <div className="alert success">✅ Account created! Redirecting to login...</div>
        )}
        {error && <div className="alert error">⚠️ {error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Full Name</label>
            <input id="reg-name" className="input" name="full_name" placeholder="Your Name"
              value={form.full_name} onChange={handleChange} />
          </div>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input id="reg-email" className="input" type="email" name="email" placeholder="you@example.com"
              value={form.email} onChange={handleChange} required />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input id="reg-password" className="input" type="password" name="password" placeholder="Min. 8 characters"
              value={form.password} onChange={handleChange} required minLength={8} />
          </div>
          <div className="form-group">
            <label className="form-label">Confirm Password</label>
            <input id="reg-confirm" className="input" type="password" name="confirm" placeholder="Repeat password"
              value={form.confirm} onChange={handleChange} required />
          </div>

          <button id="reg-submit" type="submit" className="btn btn-primary btn-lg"
            style={{ width: '100%', justifyContent: 'center', marginTop: '8px' }} disabled={isLoading}>
            {isLoading ? <><span className="spinner" style={{width:16,height:16}} /> Creating...</> : '→ Create Account'}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: '20px', fontSize: '13px', color: 'var(--text-muted)' }}>
          Already have an account?{' '}
          <Link to="/login" style={{ color: 'var(--accent)', fontWeight: 600, textDecoration: 'none' }}>Sign in</Link>
        </p>
      </div>
    </div>
  );
}
