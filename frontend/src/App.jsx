import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  LayoutDashboard, List, Bell, Settings as SettingsIcon,
  Database, BookOpen, LogOut, FileText, User
} from 'lucide-react';
import FirewatchLogo from './components/FirewatchLogo';
import Dashboard from './pages/Dashboard';
import DashboardBuilder from './pages/DashboardBuilder';
import Events from './pages/Events';
import Alerts from './pages/Alerts';
import Rules from './pages/Rules';
import Reports from './pages/Reports';
import DataSources from './pages/DataSources';
import Settings from './pages/Settings';
import Login from './pages/Login';
import { api } from './api';
import './App.css';

function App() {
  const [user, setUser] = useState(null);
  const [health, setHealth] = useState(null);
  const [checkingAuth, setCheckingAuth] = useState(true);

  // Check if we have a valid session on mount
  useEffect(() => {
    const token = localStorage.getItem('outpost_token');
    if (!token) { setCheckingAuth(false); return; }
    api.me()
      .then(data => setUser(data))
      .catch(() => localStorage.removeItem('outpost_token'))
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
  }

  function handleLogout() {
    if (idleTimer.current) clearTimeout(idleTimer.current);
    api.logout().catch(() => {});
    localStorage.removeItem('outpost_token');
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
        <Route path="*" element={<Login onLogin={handleLogin} />} />
      </Routes>
    </BrowserRouter>
  );

  return (
    <BrowserRouter>
      <div className="app">
        <nav className="sidebar">
          <div className="sidebar-logo">
            <div className="logo-icon"><FirewatchLogo size={18} /></div>
            <div>
              <h1>Firewatch</h1>
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
