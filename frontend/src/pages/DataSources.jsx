import { useState, useEffect } from 'react';
import {
  Plus, Terminal, Cloud, Server, FileText, Database as DbIcon,
  CheckCircle, XCircle, Trash2, Edit3, X, Activity
} from 'lucide-react';
import { api } from '../api';

const TYPE_META = {
  syslog:   { icon: <Terminal size={20} />,  color: 'var(--green)',  bg: 'var(--green-muted)',  label: 'Syslog' },
  rest_api: { icon: <Cloud size={20} />,     color: 'var(--purple)', bg: 'var(--purple-muted)', label: 'REST API' },
  webhook:  { icon: <Server size={20} />,    color: 'var(--blue)',   bg: 'var(--blue-muted)',   label: 'Webhook' },
  file_log: { icon: <FileText size={20} />,  color: 'var(--yellow)', bg: 'var(--yellow-muted)', label: 'File / Log' },
  kafka:    { icon: <DbIcon size={20} />,    color: 'var(--orange)', bg: 'var(--orange-muted)', label: 'Kafka' },
};

const STATUS_COLORS = {
  running: 'var(--green)', stopped: 'var(--text-muted)', error: 'var(--red)',
};

// Type-specific default settings
const DEFAULT_SETTINGS = {
  syslog:   { bind_address: '0.0.0.0', udp_port: 5514, tcp_port: 5514, format: 'auto' },
  rest_api: { url: '', auth_type: 'oauth2', poll_interval_sec: 60, tenant_id: '', client_id: '', client_secret: '' },
  webhook:  { listen_port: 9090, path: '/webhook', secret: '' },
  file_log: { path: '/var/log/messages', format: 'syslog', tail: true },
  kafka:    { brokers: '', topic: '', group_id: 'outpost', sasl_enabled: false, sasl_username: '', sasl_password: '', ssl: false },
};

export default function DataSources() {
  const [connectors, setConnectors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [addStep, setAddStep] = useState(1);
  const [newType, setNewType] = useState('');
  const [newName, setNewName] = useState('');
  const [newSettings, setNewSettings] = useState({});
  const [editId, setEditId] = useState(null);
  const [health, setHealth] = useState(null);

  async function load() {
    try {
      const [data, h] = await Promise.all([api.connectors(), api.health().catch(() => null)]);
      setConnectors(data.connectors || []);
      setHealth(h);
    } catch { setConnectors([]); }
    setLoading(false);
  }

  useEffect(() => { load(); const id = setInterval(load, 15000); return () => clearInterval(id); }, []);

  function startAdd() {
    setShowAdd(true); setAddStep(1); setNewType(''); setNewName(''); setNewSettings({});
  }

  function selectType(type) {
    setNewType(type);
    setNewName(TYPE_META[type]?.label || type);
    setNewSettings({ ...DEFAULT_SETTINGS[type] });
    setAddStep(2);
  }

  async function saveConnector() {
    if (editId) {
      await api.updateConnector({ id: editId, name: newName, type: newType, settings: newSettings });
    } else {
      await api.createConnector({ name: newName, type: newType, enabled: false, settings: newSettings });
    }
    setShowAdd(false); setEditId(null); load();
  }

  async function handleDelete(id) {
    await api.deleteConnector(id); load();
  }

  function startEdit(c) {
    setEditId(c.id);
    setNewType(c.type);
    setNewName(c.name);
    setNewSettings(c.settings || {});
    setShowAdd(true);
    setAddStep(2);
  }

  async function toggleEnabled(c) {
    await api.updateConnector({ id: c.id, enabled: !c.enabled, status: !c.enabled ? 'running' : 'stopped' });
    load();
  }

  if (loading) return (
    <div className="loading"><div className="loading-spinner" /><div>Loading connectors...</div></div>
  );

  const activeCount = connectors.filter(c => c.enabled).length;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Connectors</h1>
          <div className="subtitle">Manage data source connections and ingestion pipelines</div>
        </div>
        <button className="btn-primary" onClick={startAdd}><Plus size={14} /> Add Connector</button>
      </div>

      <div className="stats-grid" style={{gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', marginBottom: 24}}>
        <div className="stat-card">
          <div className="label">Active</div>
          <div className="value green">{activeCount}</div>
        </div>
        <div className="stat-card">
          <div className="label">Total</div>
          <div className="value">{connectors.length}</div>
        </div>
        <div className="stat-card">
          <div className="label">Events Today</div>
          <div className="value accent">{(health?.events_stored_today ?? 0).toLocaleString()}</div>
        </div>
      </div>

      {/* Add/Edit modal */}
      {showAdd && (
        <div className="connector-modal">
          <div className="connector-modal-header">
            <h3>{editId ? 'Edit Connector' : 'Add Connector'}</h3>
            <button className="btn-icon" onClick={() => { setShowAdd(false); setEditId(null); }}><X size={16} /></button>
          </div>

          {addStep === 1 && (
            <div className="connector-type-grid">
              {Object.entries(TYPE_META).map(([type, meta]) => (
                <button key={type} className="connector-type-card" onClick={() => selectType(type)}>
                  <div className="connector-type-icon" style={{background: meta.bg, color: meta.color}}>
                    {meta.icon}
                  </div>
                  <span>{meta.label}</span>
                </button>
              ))}
            </div>
          )}

          {addStep === 2 && (
            <div className="connector-form">
              <div className="field">
                <label>Connector Name</label>
                <input type="text" value={newName} onChange={e => setNewName(e.target.value)} />
              </div>

              {/* Type-specific fields */}
              {newType === 'syslog' && <SyslogForm settings={newSettings} onChange={setNewSettings} />}
              {newType === 'rest_api' && <RestApiForm settings={newSettings} onChange={setNewSettings} />}
              {newType === 'webhook' && <WebhookForm settings={newSettings} onChange={setNewSettings} />}
              {newType === 'file_log' && <FileLogForm settings={newSettings} onChange={setNewSettings} />}
              {newType === 'kafka' && <KafkaForm settings={newSettings} onChange={setNewSettings} />}

              <div style={{display: 'flex', gap: 8, marginTop: 16}}>
                <button className="btn-primary" onClick={saveConnector}>
                  {editId ? 'Update' : 'Create'} Connector
                </button>
                {!editId && <button className="btn-secondary" onClick={() => setAddStep(1)}>Back</button>}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Connector list */}
      {connectors.length === 0 && !showAdd ? (
        <div className="table-container">
          <div className="empty">
            <div className="empty-icon"><Activity size={40} /></div>
            <p style={{ fontSize: 15, color: 'var(--text-primary)', marginBottom: 6 }}>No connectors configured</p>
            <p>Click "Add Connector" to set up your first data source.</p>
          </div>
        </div>
      ) : (
        <div style={{display: 'grid', gap: 12}}>
          {connectors.map(c => {
            const meta = TYPE_META[c.type] || TYPE_META.syslog;
            return (
              <div key={c.id} className="integration-card" style={{padding: 16}}>
                <div style={{display: 'flex', alignItems: 'center', justifyContent: 'space-between'}}>
                  <div style={{display: 'flex', alignItems: 'center', gap: 14}}>
                    <div style={{
                      width: 40, height: 40, borderRadius: 'var(--radius-md)',
                      background: meta.bg, color: meta.color,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>{meta.icon}</div>
                    <div>
                      <div style={{display: 'flex', alignItems: 'center', gap: 8}}>
                        <span style={{fontSize: 14, fontWeight: 600, color: 'var(--text-primary)'}}>{c.name}</span>
                        <span style={{
                          fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                          padding: '1px 8px', borderRadius: 10,
                          background: meta.bg, color: meta.color,
                        }}>{meta.label}</span>
                      </div>
                      <div style={{fontSize: 12, color: 'var(--text-muted)', marginTop: 2}}>
                        Events: <strong style={{color: 'var(--text-primary)', fontFamily: 'var(--mono)'}}>{(c.event_count || 0).toLocaleString()}</strong>
                      </div>
                    </div>
                  </div>

                  <div style={{display: 'flex', alignItems: 'center', gap: 12}}>
                    <span style={{color: STATUS_COLORS[c.status] || 'var(--text-muted)', fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4}}>
                      {c.enabled ? <CheckCircle size={14} /> : <XCircle size={14} />}
                      {c.enabled ? 'Active' : 'Stopped'}
                    </span>
                    <label className="toggle" style={{margin: 0}}>
                      <input type="checkbox" checked={c.enabled} onChange={() => toggleEnabled(c)} />
                      <span className="toggle-slider" />
                    </label>
                    <button className="btn-icon" onClick={() => startEdit(c)} title="Edit"><Edit3 size={14} /></button>
                    <button className="btn-icon danger" onClick={() => handleDelete(c.id)} title="Delete"><Trash2 size={14} /></button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Type-specific config forms ──

function SettingsField({ label, value, onChange, type = 'text', placeholder = '' }) {
  return (
    <div className="field">
      <label>{label}</label>
      <input type={type} value={value ?? ''} placeholder={placeholder}
             onChange={e => onChange(type === 'number' ? parseInt(e.target.value) || 0 : e.target.value)} />
    </div>
  );
}

function SyslogForm({ settings, onChange }) {
  const set = (k, v) => onChange({ ...settings, [k]: v });
  return (<>
    <SettingsField label="Bind Address" value={settings.bind_address} onChange={v => set('bind_address', v)} placeholder="0.0.0.0" />
    <SettingsField label="UDP Port" value={settings.udp_port} onChange={v => set('udp_port', v)} type="number" />
    <SettingsField label="TCP Port" value={settings.tcp_port} onChange={v => set('tcp_port', v)} type="number" />
    <div className="field">
      <label>Format</label>
      <select value={settings.format || 'auto'} onChange={e => set('format', e.target.value)}>
        <option value="auto">Auto-detect</option>
        <option value="rfc3164">RFC 3164</option>
        <option value="rfc5424">RFC 5424</option>
      </select>
    </div>
  </>);
}

function RestApiForm({ settings, onChange }) {
  const set = (k, v) => onChange({ ...settings, [k]: v });
  return (<>
    <SettingsField label="Endpoint URL" value={settings.url} onChange={v => set('url', v)} placeholder="https://api.example.com/events" />
    <div className="field">
      <label>Authentication Type</label>
      <select value={settings.auth_type || 'oauth2'} onChange={e => set('auth_type', e.target.value)}>
        <option value="oauth2">OAuth2 Client Credentials</option>
        <option value="apikey">API Key</option>
        <option value="basic">Basic Auth</option>
        <option value="none">None</option>
      </select>
    </div>
    {settings.auth_type === 'oauth2' && (<>
      <SettingsField label="Tenant ID" value={settings.tenant_id} onChange={v => set('tenant_id', v)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
      <SettingsField label="Client ID" value={settings.client_id} onChange={v => set('client_id', v)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
      <SettingsField label="Client Secret" value={settings.client_secret} onChange={v => set('client_secret', v)} type="password" />
    </>)}
    {settings.auth_type === 'apikey' && (
      <SettingsField label="API Key" value={settings.api_key} onChange={v => set('api_key', v)} type="password" />
    )}
    {settings.auth_type === 'basic' && (<>
      <SettingsField label="Username" value={settings.username} onChange={v => set('username', v)} />
      <SettingsField label="Password" value={settings.password} onChange={v => set('password', v)} type="password" />
    </>)}
    <SettingsField label="Poll Interval (seconds)" value={settings.poll_interval_sec} onChange={v => set('poll_interval_sec', v)} type="number" />
  </>);
}

function WebhookForm({ settings, onChange }) {
  const set = (k, v) => onChange({ ...settings, [k]: v });
  return (<>
    <SettingsField label="Listen Port" value={settings.listen_port} onChange={v => set('listen_port', v)} type="number" />
    <SettingsField label="Path" value={settings.path} onChange={v => set('path', v)} placeholder="/webhook/source" />
    <SettingsField label="Shared Secret" value={settings.secret} onChange={v => set('secret', v)} type="password" />
  </>);
}

function FileLogForm({ settings, onChange }) {
  const set = (k, v) => onChange({ ...settings, [k]: v });
  return (<>
    <SettingsField label="File Path" value={settings.path} onChange={v => set('path', v)} placeholder="/var/log/messages" />
    <div className="field">
      <label>Format</label>
      <select value={settings.format || 'syslog'} onChange={e => set('format', e.target.value)}>
        <option value="syslog">Syslog</option>
        <option value="json">JSON (line-delimited)</option>
        <option value="csv">CSV</option>
      </select>
    </div>
    <div className="field" style={{display: 'flex', alignItems: 'center', gap: 8}}>
      <label style={{marginBottom: 0}}>Tail Mode</label>
      <label className="toggle" style={{margin: 0}}>
        <input type="checkbox" checked={settings.tail ?? true} onChange={e => set('tail', e.target.checked)} />
        <span className="toggle-slider" />
      </label>
    </div>
  </>);
}

function KafkaForm({ settings, onChange }) {
  const set = (k, v) => onChange({ ...settings, [k]: v });
  return (<>
    <SettingsField label="Bootstrap Brokers" value={settings.brokers} onChange={v => set('brokers', v)} placeholder="broker1:9092,broker2:9092" />
    <SettingsField label="Topic" value={settings.topic} onChange={v => set('topic', v)} placeholder="security-events" />
    <SettingsField label="Consumer Group ID" value={settings.group_id} onChange={v => set('group_id', v)} placeholder="outpost" />
    <div className="field" style={{display: 'flex', alignItems: 'center', gap: 8}}>
      <label style={{marginBottom: 0}}>SASL Authentication</label>
      <label className="toggle" style={{margin: 0}}>
        <input type="checkbox" checked={settings.sasl_enabled ?? false} onChange={e => set('sasl_enabled', e.target.checked)} />
        <span className="toggle-slider" />
      </label>
    </div>
    {settings.sasl_enabled && (<>
      <SettingsField label="SASL Username" value={settings.sasl_username} onChange={v => set('sasl_username', v)} />
      <SettingsField label="SASL Password" value={settings.sasl_password} onChange={v => set('sasl_password', v)} type="password" />
    </>)}
    <div className="field" style={{display: 'flex', alignItems: 'center', gap: 8}}>
      <label style={{marginBottom: 0}}>SSL/TLS</label>
      <label className="toggle" style={{margin: 0}}>
        <input type="checkbox" checked={settings.ssl ?? false} onChange={e => set('ssl', e.target.checked)} />
        <span className="toggle-slider" />
      </label>
    </div>
  </>);
}
