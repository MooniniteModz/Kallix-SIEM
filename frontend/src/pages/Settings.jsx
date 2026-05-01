import { useState, useEffect, useRef } from 'react';
import {
  Save, RefreshCw, Cloud, Shield, CheckCircle, Users, Plus, X, Trash2, Edit3, Key,
  ShieldCheck, ShieldOff, Copy, Smartphone, LogOut, RotateCcw, Mail
} from 'lucide-react';
import QRCode from 'qrcode';
import { api, postJson } from '../api';

const EMPTY = { enabled: false, tenant_id: '', client_id: '', client_secret: '', poll_interval_sec: 60 };
const ROLES = ['admin', 'analyst', 'viewer'];

export default function Settings() {
  const [tab, setTab] = useState('users');

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Settings</h1>
          <div className="subtitle">User management and platform configuration</div>
        </div>
      </div>

      <div className="filter-tabs" style={{marginBottom: 20}}>
        <button className={tab === 'users' ? 'active' : ''} onClick={() => setTab('users')}>
          <Users size={14} /> User Management
        </button>
        <button className={tab === 'security' ? 'active' : ''} onClick={() => setTab('security')}>
          <Shield size={14} /> Security
        </button>
        <button className={tab === 'integrations' ? 'active' : ''} onClick={() => setTab('integrations')}>
          <Cloud size={14} /> Integrations
        </button>
      </div>

      {tab === 'users'        && <UserManagement />}
      {tab === 'security'     && <SecurityPanel />}
      {tab === 'integrations' && <IntegrationsPanel />}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// USER MANAGEMENT
// ════════════════════════════════════════════════════════════════

function displayName(u) {
  const full = [u.first_name, u.last_name].filter(Boolean).join(' ');
  return full || u.email || u.username;
}

function UserManagement() {
  const [users, setUsers]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [showAdd, setShowAdd]   = useState(false);
  const [editUser, setEditUser] = useState(null);
  const [error, setError]       = useState('');
  const [success, setSuccess]   = useState('');

  // Create form fields
  const [formEmail,     setFormEmail]     = useState('');
  const [formFirstName, setFormFirstName] = useState('');
  const [formLastName,  setFormLastName]  = useState('');
  const [formRole,      setFormRole]      = useState('analyst');
  // Edit form fields (allow changing role only; email changes are rare)
  const [formEditRole,  setFormEditRole]  = useState('analyst');

  async function loadUsers() {
    try { setUsers(await api.listUsers()); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }

  useEffect(() => { loadUsers(); }, []);

  function openAdd() {
    setFormEmail(''); setFormFirstName(''); setFormLastName(''); setFormRole('analyst');
    setEditUser(null); setShowAdd(true); setError(''); setSuccess('');
  }

  function openEdit(user) {
    setFormEditRole(user.role);
    setEditUser(user); setShowAdd(true); setError(''); setSuccess('');
  }

  async function handleSave() {
    setError(''); setSuccess('');
    try {
      if (editUser) {
        await api.updateUser({ user_id: editUser.user_id, email: editUser.email, role: formEditRole,
                               first_name: editUser.first_name, last_name: editUser.last_name });
        setSuccess(`${displayName(editUser)} updated`);
      } else {
        if (!formEmail || !formFirstName || !formLastName) {
          setError('Email, first name, and last name are required'); return;
        }
        await api.createUser({ email: formEmail, first_name: formFirstName, last_name: formLastName, role: formRole });
        setSuccess(`Account created for ${formFirstName} ${formLastName} — welcome email sent to ${formEmail}`);
      }
      setShowAdd(false);
      await loadUsers();
    } catch (e) { setError(e.message); }
  }

  async function handleDelete(user) {
    if (!confirm(`Delete ${displayName(user)}? This cannot be undone.`)) return;
    setError(''); setSuccess('');
    try {
      await api.deleteUser(user.user_id);
      setSuccess(`${displayName(user)} deleted`);
      await loadUsers();
    } catch (e) { setError(e.message); }
  }

  async function handleAdminAction(action, user, label) {
    if (!confirm(`${label} for ${displayName(user)}?`)) return;
    setError(''); setSuccess('');
    try {
      await action(user.user_id);
      setSuccess(`${label} completed for ${displayName(user)}`);
    } catch (e) { setError(e.message); }
  }

  if (loading) return <div className="loading"><div className="loading-spinner" /><div>Loading users...</div></div>;

  return (
    <div>
      {success && <div className="status-banner success"><CheckCircle size={16} /> {success}</div>}
      {error && !showAdd && <div className="status-banner error">Error: {error}</div>}

      <div style={{marginBottom: 16}}>
        <button className="btn-secondary" onClick={openAdd}><Plus size={14} /> Create User</button>
      </div>

      {showAdd && (
        <div className="connector-modal" style={{marginBottom: 16}}>
          <div className="connector-modal-header">
            <h3>{editUser ? `Edit: ${displayName(editUser)}` : 'Create New User'}</h3>
            <button className="btn-icon" onClick={() => setShowAdd(false)}><X size={16} /></button>
          </div>
          <div className="connector-form">
            {error && <div className="status-banner error" style={{marginBottom: 12}}>Error: {error}</div>}

            {!editUser ? (
              <>
                <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12}}>
                  <div className="field">
                    <label>First Name</label>
                    <input type="text" value={formFirstName} onChange={e => setFormFirstName(e.target.value)}
                           placeholder="Jane" autoFocus />
                  </div>
                  <div className="field">
                    <label>Last Name</label>
                    <input type="text" value={formLastName} onChange={e => setFormLastName(e.target.value)}
                           placeholder="Smith" />
                  </div>
                </div>
                <div className="field">
                  <label>Email (used to log in)</label>
                  <input type="email" value={formEmail} onChange={e => setFormEmail(e.target.value)}
                         placeholder="jane.smith@company.com" />
                </div>
                <div className="field">
                  <label>Role</label>
                  <select value={formRole} onChange={e => setFormRole(e.target.value)}>
                    {ROLES.map(r => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
                  </select>
                </div>
                <p style={{fontSize: 12, color: 'var(--text-muted)', marginTop: 4}}>
                  A temporary password will be auto-generated and emailed to the user.
                  They will be required to set a new password and configure MFA on first login.
                </p>
              </>
            ) : (
              <div className="field">
                <label>Role</label>
                <select value={formEditRole} onChange={e => setFormEditRole(e.target.value)}>
                  {ROLES.map(r => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
                </select>
              </div>
            )}

            <div style={{display: 'flex', gap: 8, marginTop: 12}}>
              <button className="btn-primary" onClick={handleSave}>
                {editUser ? 'Update User' : 'Create User'}
              </button>
              <button className="btn-secondary" onClick={() => setShowAdd(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>MFA</th>
              <th>Created</th>
              <th style={{width: 200}}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.user_id}>
                <td style={{fontWeight: 500}}>{displayName(u)}</td>
                <td style={{color: 'var(--text-muted)', fontSize: 12}}>{u.email || '--'}</td>
                <td>
                  <span className={`severity-badge ${u.role === 'admin' ? 'critical' : u.role === 'analyst' ? 'medium' : 'info'}`}>
                    {u.role}
                  </span>
                </td>
                <td>
                  <span style={{fontSize: 11, color: u.mfa_enabled ? 'var(--green)' : 'var(--text-muted)'}}>
                    {u.mfa_enabled ? 'Enabled' : 'Not set'}
                  </span>
                </td>
                <td style={{color: 'var(--text-muted)', fontSize: 12}}>
                  {u.created_at ? new Date(u.created_at).toLocaleDateString() : '--'}
                </td>
                <td>
                  <div style={{display: 'flex', gap: 4, flexWrap: 'wrap'}}>
                    <button className="btn-icon-sm" title="Edit role" onClick={() => openEdit(u)}>
                      <Edit3 size={12} />
                    </button>
                    <button className="btn-icon-sm" title="Send password reset email"
                            onClick={() => handleAdminAction(api.sendAdminReset, u, 'Send password reset')}>
                      <Mail size={12} />
                    </button>
                    <button className="btn-icon-sm" title="Force log off (terminate all sessions)"
                            onClick={() => handleAdminAction(api.forceLogoff, u, 'Force log off')}>
                      <LogOut size={12} />
                    </button>
                    <button className="btn-icon-sm" title="Force MFA re-registration"
                            onClick={() => handleAdminAction(api.forceMfaReset, u, 'Force MFA re-registration')}>
                      <RotateCcw size={12} />
                    </button>
                    <button className="btn-icon-sm danger" title="Delete user" onClick={() => handleDelete(u)}>
                      <Trash2 size={12} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr><td colSpan={6} className="empty">No users found</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// INTEGRATIONS PANEL (moved from old Settings)
// ════════════════════════════════════════════════════════════════

function IntegrationsPanel() {
  const [m365, setM365] = useState({ ...EMPTY });
  const [azure, setAzure] = useState({ ...EMPTY, subscription_id: '' });
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.integrations().then(data => {
      if (data.m365) setM365(prev => ({ ...prev, ...data.m365 }));
      if (data.azure) setAzure(prev => ({ ...prev, ...data.azure }));
      setStatus(data); setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  async function handleSave() {
    setSaving(true); setStatus(null);
    try {
      await api.saveIntegrations({ m365, azure });
      const updated = await api.integrations();
      setStatus({ ...updated, saved: true });
    } catch (e) { setStatus({ error: e.message }); }
    setSaving(false);
  }

  if (loading) return <div className="loading"><div className="loading-spinner" /><div>Loading...</div></div>;

  return (
    <div>
      {status?.saved && (
        <div className="status-banner success">
          <CheckCircle size={16} /> Configuration saved and applied successfully.
        </div>
      )}
      {status?.error && (
        <div className="status-banner error">Error: {status.error}</div>
      )}

      <div className="settings-grid">
        <IntegrationCard
          title="Microsoft 365"
          icon={<Cloud size={20} />}
          description="Office 365 Management Activity API -- pulls audit logs from Azure AD, Exchange, SharePoint, and General."
          config={m365} onChange={setM365}
          eventsCollected={status?.m365?.events_collected}
          fields={[
            { key: 'tenant_id', label: 'Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
            { key: 'client_id', label: 'Client ID (App Registration)', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
            { key: 'client_secret', label: 'Client Secret', placeholder: 'Enter client secret', type: 'password' },
            { key: 'poll_interval_sec', label: 'Poll Interval (seconds)', type: 'number' },
          ]}
        />
        <IntegrationCard
          title="Azure Monitor"
          icon={<Shield size={20} />}
          description="Azure Monitor &amp; Entra ID -- pulls management plane events and sign-in logs (with geolocation for the globe) from your Azure tenant."
          config={azure} onChange={setAzure}
          eventsCollected={status?.azure?.events_collected}
          signinEvents={status?.azure?.signin_events}
          fields={[
            { key: 'tenant_id', label: 'Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
            { key: 'client_id', label: 'Client ID (App Registration)', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
            { key: 'client_secret', label: 'Client Secret', placeholder: 'Enter client secret', type: 'password' },
            { key: 'subscription_id', label: 'Subscription ID (optional -- only for Activity Log)', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
            { key: 'poll_interval_sec', label: 'Poll Interval (seconds)', type: 'number' },
          ]}
        />
      </div>

      <div className="settings-actions">
        <button className="btn-primary" onClick={handleSave} disabled={saving}>
          {saving
            ? <><RefreshCw size={14} className="spin" /> Saving...</>
            : <><Save size={14} /> Save & Apply</>
          }
        </button>
      </div>
    </div>
  );
}

function IntegrationCard({ title, icon, description, config, onChange, eventsCollected, signinEvents, fields }) {
  function update(key, value) {
    onChange(prev => ({ ...prev, [key]: value }));
  }

  return (
    <div className="integration-card">
      <div className="integration-header">
        <div className="integration-title">{icon}<h3>{title}</h3></div>
        <label className="toggle">
          <input type="checkbox" checked={config.enabled} onChange={e => update('enabled', e.target.checked)} />
          <span className="toggle-slider" />
          <span className="toggle-label">{config.enabled ? 'Enabled' : 'Disabled'}</span>
        </label>
      </div>
      <p className="integration-desc">{description}</p>
      {eventsCollected !== undefined && (
        <div className="integration-status">
          Events collected this session: <strong>{eventsCollected}</strong>
          {signinEvents > 0 && <span style={{marginLeft: 12, opacity: 0.7}}>(incl. {signinEvents} sign-ins)</span>}
        </div>
      )}
      <div className={`integration-fields ${!config.enabled ? 'fields-disabled' : ''}`}>
        {fields.map(f => (
          <div className="field" key={f.key}>
            <label>{f.label}</label>
            <input
              type={f.type || 'text'} placeholder={f.placeholder || ''}
              value={config[f.key] ?? ''}
              onChange={e => update(f.key, f.type === 'number' ? parseInt(e.target.value) || 0 : e.target.value)}
              disabled={!config.enabled}
            />
          </div>
        ))}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// SECURITY — MFA
// ════════════════════════════════════════════════════════════════

function SecurityPanel() {
  const [mfaEnabled, setMfaEnabled]   = useState(null);
  const [step, setStep]               = useState('idle'); // idle | setup | backup | disable | reregister
  const [qrDataUrl, setQrDataUrl]     = useState('');
  const [secret, setSecret]           = useState('');
  const [code, setCode]               = useState('');
  const [backupCodes, setBackupCodes] = useState([]);
  const [password, setPassword]       = useState('');
  const [error, setError]             = useState('');
  const [loading, setLoading]         = useState(false);
  const [copied, setCopied]           = useState(false);
  const canvasRef = useRef();

  useEffect(() => {
    api.mfaStatus().then(d => setMfaEnabled(d.mfa_enabled)).catch(() => {});
  }, []);

  async function startSetup() {
    setError(''); setLoading(true);
    try {
      const d = await api.mfaSetup();
      setSecret(d.secret);
      const url = await QRCode.toDataURL(d.uri, { width: 200, margin: 2, color: { dark: '#e6edf3', light: '#0d1117' } });
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
      setMfaEnabled(true);
      setStep('backup');
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function confirmDisable() {
    setError(''); setLoading(true);
    try {
      await api.mfaDisable(password);
      setMfaEnabled(false);
      setStep('idle');
      setPassword('');
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  async function confirmReregister() {
    setError(''); setLoading(true);
    try {
      await api.mfaDisable(password);
      setPassword('');
      setMfaEnabled(false);
      const d = await api.mfaSetup();
      setSecret(d.secret);
      const url = await QRCode.toDataURL(d.uri, { width: 200, margin: 2, color: { dark: '#e6edf3', light: '#0d1117' } });
      setQrDataUrl(url);
      setCode('');
      setStep('setup');
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  function copyBackupCodes() {
    navigator.clipboard.writeText(backupCodes.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  if (mfaEnabled === null) return <div style={{ color: 'var(--text-muted)', padding: 32 }}>Loading…</div>;

  return (
    <div style={{ maxWidth: 520 }}>
      <div className="card" style={{ padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
          {mfaEnabled
            ? <ShieldCheck size={22} style={{ color: 'var(--green)' }} />
            : <ShieldOff   size={22} style={{ color: 'var(--text-muted)' }} />}
          <div>
            <div style={{ fontWeight: 600, fontSize: 15 }}>Two-Factor Authentication</div>
            <div style={{ fontSize: 12, color: mfaEnabled ? 'var(--green)' : 'var(--text-muted)' }}>
              {mfaEnabled ? 'Enabled — your account is protected' : 'Not enabled'}
            </div>
          </div>
        </div>

        {/* ── Idle state ── */}
        {step === 'idle' && !mfaEnabled && (
          <>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.6 }}>
              Add a second layer of security. After enabling, you'll need your authenticator
              app each time you sign in.
            </p>
            {error && <div className="login-error" style={{ marginBottom: 12 }}>{error}</div>}
            <button className="btn-primary" onClick={startSetup} disabled={loading}>
              <Smartphone size={14} /> {loading ? 'Loading…' : 'Set Up Authenticator App'}
            </button>
          </>
        )}

        {/* ── QR scan step ── */}
        {step === 'setup' && (
          <>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.6 }}>
              Scan this QR code with <strong style={{ color: 'var(--text)' }}>Microsoft Authenticator</strong>,
              Authy, Google Authenticator, or any TOTP app.
            </p>
            <div style={{ textAlign: 'center', marginBottom: 16 }}>
              {qrDataUrl && <img src={qrDataUrl} alt="MFA QR Code" style={{ borderRadius: 8 }} />}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--mono)',
                          background: 'var(--bg-tertiary)', padding: '8px 12px', borderRadius: 6,
                          wordBreak: 'break-all', marginBottom: 16 }}>
              {secret}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
              Can't scan? Enter the code above manually in your app.
            </div>
            {error && <div className="login-error" style={{ marginBottom: 12 }}>{error}</div>}
            <div className="login-field" style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 12 }}>Enter the 6-digit code to confirm</label>
              <input type="text" inputMode="numeric" maxLength={6} value={code}
                     onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
                     placeholder="000000" autoFocus
                     style={{ letterSpacing: '0.2em', fontSize: 20, textAlign: 'center' }} />
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-primary" onClick={verifyEnable} disabled={loading || code.length !== 6}>
                <ShieldCheck size={14} /> {loading ? 'Verifying…' : 'Enable MFA'}
              </button>
              <button className="btn-secondary" onClick={() => { setStep('idle'); setError(''); }}>Cancel</button>
            </div>
          </>
        )}

        {/* ── Backup codes ── */}
        {step === 'backup' && (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12,
                          padding: '10px 14px', background: 'rgba(240, 136, 62, 0.12)',
                          border: '1px solid rgba(240,136,62,0.3)', borderRadius: 8 }}>
              <Key size={14} style={{ color: '#f0883e', flexShrink: 0 }} />
              <span style={{ fontSize: 12, color: '#f0883e' }}>
                Save these backup codes now — they won't be shown again.
                Each code can only be used once.
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
              <button className="btn-secondary" onClick={copyBackupCodes}>
                <Copy size={13} /> {copied ? 'Copied!' : 'Copy All'}
              </button>
              <button className="btn-primary" onClick={() => setStep('idle')}>
                <CheckCircle size={13} /> Done
              </button>
            </div>
          </>
        )}

        {/* ── MFA management when enabled ── */}
        {step === 'idle' && mfaEnabled && (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn-secondary" onClick={() => { setStep('reregister'); setError(''); }}>
              <RefreshCw size={14} /> Re-register Authenticator
            </button>
            <button className="btn-secondary" style={{ color: 'var(--red)', borderColor: 'var(--red)' }}
                    onClick={() => { setStep('disable'); setError(''); }}>
              <ShieldOff size={14} /> Disable MFA
            </button>
          </div>
        )}

        {step === 'reregister' && (
          <>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12, lineHeight: 1.5 }}>
              Confirm your password to reset your authenticator and scan a new QR code.
            </p>
            {error && <div className="login-error" style={{ marginBottom: 12 }}>{error}</div>}
            <div className="login-field" style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 12 }}>Current Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                     autoFocus placeholder="Enter your password" />
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-primary" onClick={confirmReregister} disabled={loading || !password}>
                <RefreshCw size={14} /> {loading ? 'Resetting…' : 'Reset & Re-register'}
              </button>
              <button className="btn-secondary" onClick={() => { setStep('idle'); setError(''); setPassword(''); }}>
                Cancel
              </button>
            </div>
          </>
        )}

        {step === 'disable' && (
          <>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>
              Confirm your password to disable two-factor authentication.
            </p>
            {error && <div className="login-error" style={{ marginBottom: 12 }}>{error}</div>}
            <div className="login-field" style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 12 }}>Current Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                     autoFocus placeholder="Enter your password" />
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-primary" style={{ background: 'var(--red)', borderColor: 'var(--red)' }}
                      onClick={confirmDisable} disabled={loading || !password}>
                <ShieldOff size={14} /> {loading ? 'Disabling…' : 'Disable MFA'}
              </button>
              <button className="btn-secondary" onClick={() => { setStep('idle'); setError(''); setPassword(''); }}>
                Cancel
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
