import { useNavigate, NavLink, Outlet } from 'react-router-dom';
import useAuthStore from '../store/authStore';

const navItems = [
  { to: '/dashboard', icon: '📊', label: 'Dashboard', badge: null },
  { to: '/scanner', icon: '🔍', label: 'Scanner', badge: 'AI' },
  { to: '/matrix', icon: '🗺️', label: 'Access Matrix', badge: null },
  { to: '/learning', icon: '📚', label: 'Learning Mode', badge: null },
];

export default function AppLayout() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const initials = user?.email?.slice(0, 2).toUpperCase() || '??';
  const emailShort = user?.email?.split('@')[0] || 'Unknown';

  return (
    <div className="app-layout">
      <aside className="sidebar">
        {/* Brand */}
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">🛡️</div>
          <div>
            <div className="sidebar-logo-text">BAC Scanner</div>
            <div className="sidebar-logo-sub">AI-Powered Security</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="sidebar-nav">
          <div className="nav-section-label">Tools</div>
          {navItems.map(({ to, icon, label, badge }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <span className="nav-item-icon">{icon}</span>
              <span>{label}</span>
              {badge && <span className="nav-item-badge">{badge}</span>}
            </NavLink>
          ))}

          <div className="nav-section-label" style={{ marginTop: 20 }}>Info</div>
          <div
            className="nav-item"
            onClick={() => window.open('https://owasp.org/Top10/A01_2021-Broken_Access_Control/', '_blank')}
          >
            <span className="nav-item-icon">📖</span>
            <span>OWASP Docs</span>
          </div>
        </nav>

        {/* Bottom status dot */}
        <div style={{ padding: '0 24px 12px', display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--low)', boxShadow: '0 0 8px rgba(52,211,153,0.6)', animation: 'pulse 2s ease-in-out infinite' }} />
          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: 0.5 }}>Backend Online</span>
        </div>

        {/* User footer */}
        <div className="sidebar-footer">
          <div className="user-badge" onClick={handleLogout} title="Click to logout">
            <div className="avatar">{initials}</div>
            <div className="user-info">
              <div className="user-name">{emailShort}</div>
              <div className="user-role">
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--low)', display: 'inline-block', flexShrink: 0 }} />
                {user?.role || 'user'} · click to logout
              </div>
            </div>
          </div>
        </div>
      </aside>

      <main className="main-content fade-in">
        <Outlet />
      </main>
    </div>
  );
}
