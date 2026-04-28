import { useState, useEffect } from 'react';
import {
  Save, RefreshCw, Cloud, Shield, CheckCircle, Users, Plus, X, Trash2, Edit3, Key
} from 'lucide-react';
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
        <button className={tab === 'integrations' ? 'active' : ''} onClick={() => setTab('integrations')}>
          <Cloud size={14} /> Integrations
        </button>
      </div>

      {tab === 'users' && <UserManagement />}
      {tab === 'integrations' && <IntegrationsPanel />}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// USER MANAGEMENT
// ════════════════════════════════════════════════════════════════

function UserManagement() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [editUser, setEditUser] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Add/edit form
  const [formUsername, setFormUsername] = useState('');
  const [formEmail, setFormEmail] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formRole, setFormRole] = useState('analyst');

  async function loadUsers() {
    try {
      const data = await api.listUsers();
      setUsers(data);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  useEffect(() => { loadUsers(); }, []);

  function openAdd() {
    setFormUsername(''); setFormEmail(''); setFormPassword(''); setFormRole('analyst');
    setEditUser(null); setShowAdd(true); setError(''); setSuccess('');
  }

  function openEdit(user) {
    setFormUsername(user.username);
    setFormEmail(user.email || '');
    setFormPassword('');
    setFormRole(user.role);
    setEditUser(user); setShowAdd(true); setError(''); setSuccess('');
  }

  async function handleSave() {
    setError(''); setSuccess('');
    try {
      if (editUser) {
        await api.updateUser({
          user_id: editUser.user_id,
          email: formEmail,
          role: formRole,
          ...(formPassword ? { password: formPassword } : {}),
        });
        setSuccess(`User "${editUser.username}" updated`);
      } else {
        if (!formUsername || !formPassword) { setError('Username and password are required'); return; }
        await api.createUser({
          username: formUsername,
          email: formEmail,
          password: formPassword,
          role: formRole,
        });
        setSuccess(`User "${formUsername}" created`);
      }
      setShowAdd(false);
      await loadUsers();
    } catch (e) { setError(e.message); }
  }

  async function handleDelete(user) {
    if (!confirm(`Delete user "${user.username}"? This cannot be undone.`)) return;
    setError(''); setSuccess('');
    try {
      await api.deleteUser(user.user_id);
      setSuccess(`User "${user.username}" deleted`);
      await loadUsers();
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
            <h3>{editUser ? `Edit: ${editUser.username}` : 'Create New User'}</h3>
            <button className="btn-icon" onClick={() => setShowAdd(false)}><X size={16} /></button>
          </div>
          <div className="connector-form">
            {error && <div className="status-banner error" style={{marginBottom: 12}}>Error: {error}</div>}

            {!editUser && (
              <div className="field">
                <label>Username</label>
                <input type="text" value={formUsername} onChange={e => setFormUsername(e.target.value)}
                       placeholder="jsmith" autoFocus />
              </div>
            )}
            <div className="field">
              <label>Email</label>
              <input type="email" value={formEmail} onChange={e => setFormEmail(e.target.value)}
                     placeholder="user@company.com" autoFocus={!!editUser} />
            </div>
            <div className="field">
              <label>{editUser ? 'New Password (leave blank to keep current)' : 'Password'}</label>
              <input type="password" value={formPassword} onChange={e => setFormPassword(e.target.value)}
                     placeholder={editUser ? 'Leave blank to keep current' : 'Min 12 characters'} />
            </div>
            <div className="field">
              <label>Role</label>
              <select value={formRole} onChange={e => setFormRole(e.target.value)}>
                {ROLES.map(r => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
              </select>
            </div>
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
              <th>Username</th>
              <th>Email</th>
              <th>Role</th>
              <th>Created</th>
              <th style={{width: 120}}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.user_id}>
                <td style={{fontWeight: 500}}>{u.username}</td>
                <td style={{color: u.email ? 'var(--text)' : 'var(--text-muted)'}}>
                  {u.email || '--'}
                </td>
                <td>
                  <span className={`severity-badge ${u.role === 'admin' ? 'critical' : u.role === 'analyst' ? 'medium' : 'info'}`}>
                    {u.role}
                  </span>
                </td>
                <td style={{color: 'var(--text-muted)', fontSize: 12}}>
                  {u.created_at ? new Date(u.created_at).toLocaleDateString() : '--'}
                </td>
                <td>
                  <div style={{display: 'flex', gap: 4}}>
                    <button className="btn-icon-sm" title="Edit user" onClick={() => openEdit(u)}>
                      <Edit3 size={12} />
                    </button>
                    <button className="btn-icon-sm danger" title="Delete user" onClick={() => handleDelete(u)}>
                      <Trash2 size={12} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr><td colSpan={5} className="empty">No users found</td></tr>
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
