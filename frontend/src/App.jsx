import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  LayoutDashboard, List, Bell, Settings as SettingsIcon,
  Database, BookOpen, LogOut, FileText, User,
  Shield, ShieldCheck, Smartphone, Key, Copy, CheckCircle
} from 'lucide-react';
import QRCode from 'qrcode';
import KallixLogo from './components/KallixLogo';
import Dashboard from './pages/Dashboard';
import DashboardBuilder from './pages/DashboardBuilder';
import Events from './pages/Events';
import Alerts from './pages/Alerts';
import Rules from './pages/Rules';
import Reports from './pages/Reports';
import DataSources from './pages/DataSources';
import Settings from './pages/Settings';
import Login from './pages/Login';
import ResetPassword from './pages/ResetPassword';
import { api } from './api';
import './App.css';

function App() {
  const [user, setUser]                         = useState(null);
  const [mfaSetupRequired, setMfaSetupRequired] = useState(false);
  const [health, setHealth]                     = useState(null);
  const [checkingAuth, setCheckingAuth]         = useState(true);

  // Check for a valid session on mount — the HttpOnly cookie is sent automatically
  useEffect(() => {
    api.me()
      .then(data => {
        setUser(data);
        if (!data.mfa_enabled) setMfaSetupRequired(true);
      })
      .catch(() => {})
      .finally(() => setCheckingAuth(false));
  }, []);

  // Health polling (only when logged in)
  useEffect(() => {
    if (!user) return;
    const check = () => api.health().then(setHealth).catch(() => setHealth(null));
    check();
    const id = setInterval(check, 10000);
    return () => clearInterval(id);
  }, [user]);

  // ── Idle auto-logout (30 min) ──
  const IDLE_TIMEOUT = 30 * 60 * 1000;
  const idleTimer = useRef(null);

  const resetIdleTimer = useCallback(() => {
    if (idleTimer.current) clearTimeout(idleTimer.current);
    idleTimer.current = setTimeout(() => {
      // Don't logout if globe is in fullscreen
      if (document.querySelector('.globe-fullscreen')) return resetIdleTimer();
      handleLogout();
    }, IDLE_TIMEOUT);
  }, []);

  useEffect(() => {
    if (!user) return;
    const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'];
    events.forEach(e => window.addEventListener(e, resetIdleTimer, { passive: true }));
    resetIdleTimer();
    return () => {
      events.forEach(e => window.removeEventListener(e, resetIdleTimer));
      if (idleTimer.current) clearTimeout(idleTimer.current);
    };
  }, [user, resetIdleTimer]);

  function handleLogin(data) {
    setUser({ username: data.username, role: data.role });
    if (data.mfa_setup_required) setMfaSetupRequired(true);
  }

  function handleLogout() {
    if (idleTimer.current) clearTimeout(idleTimer.current);
    api.logout().catch(() => {});  // server clears the HttpOnly cookie
    setUser(null);
    setHealth(null);
  }

  if (checkingAuth) return (
    <div className="login-container">
      <div className="loading"><div className="loading-spinner" /></div>
    </div>
  );

  if (!user) return (
    <BrowserRouter>
      <Routes>
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="*" element={<Login onLogin={handleLogin} />} />
      </Routes>
    </BrowserRouter>
  );

  if (mfaSetupRequired) return (
    <ForcedMfaSetup onComplete={() => setMfaSetupRequired(false)} />
  );

  return (
    <BrowserRouter>
      <div className="app">
        <nav className="sidebar">
          <div className="sidebar-logo">
            <div className="logo-icon"><KallixLogo size={32} /></div>
            <div>
              <h1>Kallix</h1>
              <span className="version">SIEM v0.3.0</span>
            </div>
          </div>

          <div className="sidebar-section">Monitor</div>
          <div className="sidebar-nav">
            <NavLink to="/" end><LayoutDashboard size={16} /> <span>Dashboard</span></NavLink>
            <NavLink to="/events"><List size={16} /> <span>Events</span></NavLink>
            <NavLink to="/alerts"><Bell size={16} /> <span>Alerts</span></NavLink>
            <NavLink to="/reports"><FileText size={16} /> <span>Reports</span></NavLink>
          </div>

          <div className="sidebar-section">Manage</div>
          <div className="sidebar-nav">
            <NavLink to="/sources"><Database size={16} /> <span>Connectors</span></NavLink>
            <NavLink to="/rules"><BookOpen size={16} /> <span>Rules</span></NavLink>
            <NavLink to="/settings"><SettingsIcon size={16} /> <span>Settings</span></NavLink>
          </div>

          <div className="sidebar-footer">
            <div className="sidebar-user">
              <span className="sidebar-user-icon"><User size={16} /></span>
              <span className="sidebar-username">{user.username}</span>
              <button className="btn-logout" onClick={handleLogout} title="Sign out">
                <LogOut size={14} />
              </button>
            </div>
            <div className="sidebar-status">
              <span className={`pulse ${health ? '' : 'error'}`} />
              {health ? 'System Online' : 'Disconnected'}
            </div>
          </div>
        </nav>

        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard/edit" element={<DashboardBuilder />} />
            <Route path="/events" element={<Events />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/sources" element={<DataSources />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/login" element={<Navigate to="/" />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;

// ── Forced MFA setup gate ────────────────────────────────────────────────────
// Shown instead of the app whenever mfa_enabled = false. No skip/cancel.

function ForcedMfaSetup({ onComplete }) {
  const [step, setStep]               = useState('intro'); // intro | setup | backup
  const [qrDataUrl, setQrDataUrl]     = useState('');
  const [secret, setSecret]           = useState('');
  const [code, setCode]               = useState('');
  const [backupCodes, setBackupCodes] = useState([]);
  const [error, setError]             = useState('');
  const [loading, setLoading]         = useState(false);
  const [copied, setCopied]           = useState(false);

  async function startSetup() {
    setError(''); setLoading(true);
    try {
      const d = await api.mfaSetup();
      setSecret(d.secret);
      const url = await QRCode.toDataURL(d.uri, {
        width: 200, margin: 2,
        color: { dark: '#e6edf3', light: '#0d1117' }
      });
      setQrDataUrl(url);
      setStep('setup');
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function verifyEnable() {
    setError(''); setLoading(true);
    try {
      const d = await api.mfaEnable(code);
      setBackupCodes(d.backup_codes);
      setStep('backup');
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  function copyBackupCodes() {
    navigator.clipboard.writeText(backupCodes.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-brand">
          <div className="login-brand-icon" style={{ color: 'var(--accent)' }}>
            <Shield size={44} />
          </div>
          <h1 className="login-screen-title">
            {step === 'backup' ? 'Save Your Backup Codes' : 'Set Up Two-Factor Authentication'}
          </h1>
        </div>

        {step === 'intro' && (
          <>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, textAlign: 'center', lineHeight: 1.6 }}>
              Two-factor authentication is required. Set it up now to access Kallix SIEM.
            </p>
            {error && <div className="login-error">{error}</div>}
            <button className="btn-primary login-btn" onClick={startSetup} disabled={loading}>
              <Smartphone size={14} /> {loading ? 'Loading…' : 'Set Up Authenticator App'}
            </button>
          </>
        )}

        {step === 'setup' && (
          <>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12, textAlign: 'center', lineHeight: 1.6 }}>
              Scan with <strong style={{ color: 'var(--text)' }}>Microsoft Authenticator</strong>, Authy, or any TOTP app.
            </p>
            <div style={{ textAlign: 'center', marginBottom: 12 }}>
              {qrDataUrl && <img src={qrDataUrl} alt="MFA QR Code" style={{ borderRadius: 8 }} />}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--mono)',
                          background: 'var(--bg-tertiary)', padding: '8px 12px', borderRadius: 6,
                          wordBreak: 'break-all', marginBottom: 12, textAlign: 'center' }}>
              {secret}
            </div>
            {error && <div className="login-error" style={{ marginBottom: 12 }}>{error}</div>}
            <div className="login-field">
              <label>Enter the 6-digit code to confirm</label>
              <input type="text" inputMode="numeric" maxLength={6} value={code}
                     onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
                     placeholder="000000" autoFocus
                     style={{ letterSpacing: '0.25em', fontSize: 22, textAlign: 'center' }} />
            </div>
            <button className="btn-primary login-btn" onClick={verifyEnable}
                    disabled={loading || code.length !== 6}>
              <ShieldCheck size={14} /> {loading ? 'Verifying…' : 'Enable MFA'}
            </button>
          </>
        )}

        {step === 'backup' && (
          <>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 14,
                          padding: '10px 14px', background: 'rgba(240, 136, 62, 0.12)',
                          border: '1px solid rgba(240,136,62,0.3)', borderRadius: 8 }}>
              <Key size={14} style={{ color: '#f0883e', flexShrink: 0, marginTop: 1 }} />
              <span style={{ fontSize: 12, color: '#f0883e', lineHeight: 1.5 }}>
                Save these backup codes — they won't be shown again. Each can only be used once.
              </span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 16 }}>
              {backupCodes.map((c, i) => (
                <div key={i} style={{ fontFamily: 'var(--mono)', fontSize: 13, fontWeight: 600,
                                      padding: '6px 10px', background: 'var(--bg-tertiary)',
                                      borderRadius: 6, textAlign: 'center', letterSpacing: '0.1em' }}>
                  {c}
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={copyBackupCodes}>
                <Copy size={13} /> {copied ? 'Copied!' : 'Copy All'}
              </button>
              <button className="btn-primary" style={{ flex: 1 }} onClick={onComplete}>
                <CheckCircle size={13} /> Done
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
