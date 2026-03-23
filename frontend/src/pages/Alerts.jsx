import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronRight } from 'lucide-react';
import { api } from '../api';

const SEVERITY_CLASS = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info',
  informational: 'info', warning: 'medium', error: 'high', unknown: 'info',
};

function formatTs(ms) {
  if (!ms) return '';
  const d = new Date(ms);
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
         d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function Alerts() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [expanded, setExpanded] = useState(null);

  async function load() {
    try {
      const data = await api.alerts();
      setAlerts(data.alerts || []);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  async function handleAcknowledge(alertId) {
    await api.acknowledgeAlert(alertId);
    load();
  }

  async function handleClose(alertId) {
    await api.closeAlert(alertId);
    load();
  }

  if (error && !alerts.length) return (
    <div className="loading"><div className="loading-spinner" /><div>Connecting...</div></div>
  );

  if (loading) return (
    <div className="loading"><div className="loading-spinner" /><div>Loading alerts...</div></div>
  );

  const filtered = alerts.filter(a => {
    if (statusFilter === 'open') return !a.acknowledged;
    if (statusFilter === 'acknowledged') return a.acknowledged;
    return true;
  });

  const openCount = alerts.filter(a => !a.acknowledged).length;
  const ackedCount = alerts.filter(a => a.acknowledged).length;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Alerts</h1>
          <div className="subtitle">
            {alerts.length > 0
              ? `${alerts.length} alert${alerts.length !== 1 ? 's' : ''}, ${openCount} open`
              : 'Detection rule alerts appear here'}
          </div>
        </div>
      </div>

      {/* Status filter tabs */}
      {alerts.length > 0 && (
        <div className="filter-tabs">
          <button className={statusFilter === 'all' ? 'active' : ''} onClick={() => setStatusFilter('all')}>
            All ({alerts.length})
          </button>
          <button className={statusFilter === 'open' ? 'active' : ''} onClick={() => setStatusFilter('open')}>
            <AlertTriangle size={12} /> Open ({openCount})
          </button>
          <button className={statusFilter === 'acknowledged' ? 'active' : ''} onClick={() => setStatusFilter('acknowledged')}>
            <CheckCircle size={12} /> Acknowledged ({ackedCount})
          </button>
        </div>
      )}

      <div className="table-container">
        {filtered.length === 0 ? (
          <div className="empty">
            <div className="empty-icon"><Bell size={40} /></div>
            <p style={{ fontSize: 15, color: 'var(--text-primary)', marginBottom: 6 }}>
              {alerts.length === 0 ? 'No alerts triggered yet' : 'No alerts match filter'}
            </p>
            <p>Alerts will appear here when detection rules fire against incoming events.</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th style={{width: 28}}></th>
                <th>Time</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Description</th>
                <th>Events</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => (
                <tr key={a.alert_id}>
                  <td style={{padding: '8px 4px 8px 12px', color: 'var(--text-muted)', cursor: 'pointer'}}
                      onClick={() => setExpanded(expanded === a.alert_id ? null : a.alert_id)}>
                    {expanded === a.alert_id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </td>
                  <td className="time-cell">{formatTs(a.created_at)}</td>
                  <td style={{color: 'var(--text-primary)', fontWeight: 500}}>{a.rule_name}</td>
                  <td>
                    <span className={`badge ${SEVERITY_CLASS[a.severity?.toLowerCase()] || 'info'}`}>
                      {a.severity}
                    </span>
                  </td>
                  <td style={{maxWidth: 300}}>{a.description}</td>
                  <td className="mono">{a.event_ids?.length || 0}</td>
                  <td>
                    {a.acknowledged
                      ? <span style={{color: 'var(--green)', display: 'flex', alignItems: 'center', gap: 4}}>
                          <CheckCircle size={14} /> Acked
                        </span>
                      : <span style={{color: 'var(--yellow)', display: 'flex', alignItems: 'center', gap: 4}}>
                          <AlertTriangle size={14} /> Open
                        </span>
                    }
                  </td>
                  <td>
                    <div style={{display: 'flex', gap: 6}}>
                      {!a.acknowledged && (
                        <button className="btn-small" onClick={() => handleAcknowledge(a.alert_id)}>
                          <CheckCircle size={12} /> Ack
                        </button>
                      )}
                      <button className="btn-small danger" onClick={() => handleClose(a.alert_id)}>
                        <XCircle size={12} /> Close
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
