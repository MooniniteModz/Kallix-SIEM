import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area
} from 'recharts';
import { Activity, AlertTriangle, Database, Zap, TrendingUp, Pencil } from 'lucide-react';
import { api } from '../api';

const SEVERITY_COLORS = {
  critical: '#f85149', error: '#f85149', high: '#db6d28',
  warning: '#d29922', medium: '#d29922', low: '#3fb950',
  info: '#58a6ff', informational: '#58a6ff', debug: '#8b949e',
};

const SOURCE_COLORS = {
  Azure: '#58a6ff', M365: '#bc8cff', FortiGate: '#db6d28',
  Windows: '#79c0ff', Syslog: '#3fb950', Unknown: '#8b949e',
};

const CHART_COLORS = ['#00d4aa', '#58a6ff', '#bc8cff', '#db6d28', '#d29922', '#f85149', '#3fb950', '#79c0ff'];

function formatUptime(ms) {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function formatTime(ms) {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatNumber(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return n.toLocaleString();
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [health, setHealth] = useState(null);
  const [severity, setSeverity] = useState([]);
  const [sources, setSources] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [topIps, setTopIps] = useState([]);
  const [topUsers, setTopUsers] = useState([]);
  const [topActions, setTopActions] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [h, sev, src, tl, ips, users, actions] = await Promise.all([
          api.health(), api.severity(), api.sources(),
          api.timeline(24), api.topIps(8), api.topUsers(8), api.topActions(8),
        ]);
        if (cancelled) return;
        setHealth(h);
        setSeverity(sev.map(([name, value]) => ({ name, value })));
        setSources(src.map(([name, value]) => ({ name, value })));
        setTimeline(tl.map(([time, count]) => ({ time, count })));
        setTopIps(ips);
        setTopUsers(users);
        setTopActions(actions);
        setError(null);
      } catch (e) {
        if (!cancelled) setError(e.message);
      }
    }
    load();
    const interval = setInterval(load, 15000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  if (error && !health) return (
    <div className="loading">
      <div className="loading-spinner" />
      <div>Connecting to Outpost backend...</div>
      <div style={{ fontSize: 12, marginTop: 8, color: 'var(--text-muted)' }}>{error}</div>
    </div>
  );

  if (!health) return (
    <div className="loading"><div className="loading-spinner" /><div>Loading dashboard...</div></div>
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Dashboard</h1>
          <div className="subtitle">Real-time security monitoring overview</div>
        </div>
        <button className="btn-secondary" onClick={() => navigate('/dashboard/edit')}>
          <Pencil size={14} /> Customize
        </button>
      </div>

      {/* Stat cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="label">Events Today</div>
          <div className="value accent">{formatNumber(health.events_stored_today ?? 0)}</div>
        </div>
        <div className="stat-card">
          <div className="label">Total Ingested</div>
          <div className="value">{formatNumber(health.total_events_inserted ?? 0)}</div>
        </div>
        <div className="stat-card">
          <div className="label">Buffer Usage</div>
          <div className="value">{health.buffer_usage}<span style={{fontSize:14,color:'var(--text-muted)'}}> / {health.buffer_capacity}</span></div>
        </div>
        <div className="stat-card">
          <div className="label">Drops</div>
          <div className="value" style={{color: health.buffer_drops > 0 ? 'var(--red)' : 'var(--green)'}}>
            {formatNumber(health.buffer_drops ?? 0)}
          </div>
        </div>
        <div className="stat-card">
          <div className="label">Uptime</div>
          <div className="value">{formatUptime(health.uptime_ms)}</div>
        </div>
      </div>

      {/* Timeline - full width, clickable */}
      <div className="charts-grid" style={{gridTemplateColumns: '1fr'}}>
        <div className="chart-panel">
          <h3><Activity size={14} /> Event Timeline (24h) <span className="click-hint">Click a point to investigate</span></h3>
          {timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timeline} onClick={(e) => {
                if (e?.activePayload?.[0]) {
                  const t = e.activePayload[0].payload.time;
                  navigate(`/events?start=${t}&end=${t + 3600000}`);
                }
              }} style={{cursor: 'pointer'}}>
                <defs>
                  <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00d4aa" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00d4aa" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tickFormatter={formatTime} stroke="#30363d" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#30363d" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8, fontSize: 12 }}
                  labelFormatter={formatTime}
                />
                <Area type="monotone" dataKey="count" stroke="#00d4aa" strokeWidth={2} fill="url(#colorCount)" />
              </AreaChart>
            </ResponsiveContainer>
          ) : <div className="empty">No timeline data yet</div>}
        </div>
      </div>

      {/* Severity + Sources row — clickable */}
      <div className="dashboard-row even">
        <div className="chart-panel">
          <h3><AlertTriangle size={14} /> Events by Severity <span className="click-hint">Click to filter</span></h3>
          {severity.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={severity} dataKey="value" nameKey="name" cx="50%" cy="50%"
                     innerRadius={50} outerRadius={85} paddingAngle={2}
                     label={({ name, value }) => `${name} (${value})`} labelLine={false}
                     style={{fontSize: 11, cursor: 'pointer'}}
                     onClick={(_, index) => navigate(`/events?severity=${severity[index].name}`)}>
                  {severity.map((entry, i) => (
                    <Cell key={i} fill={SEVERITY_COLORS[entry.name.toLowerCase()] || CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8, fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <div className="empty">No severity data</div>}
        </div>

        <div className="chart-panel">
          <h3><Database size={14} /> Events by Source <span className="click-hint">Click to filter</span></h3>
          {sources.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={sources} layout="vertical" margin={{left: 10}}>
                <XAxis type="number" stroke="#30363d" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="name" stroke="#30363d" fontSize={11} width={80} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20} style={{cursor: 'pointer'}}
                     onClick={(data) => navigate(`/events?source_type=${data.name}`)}>
                  {sources.map((entry, i) => (
                    <Cell key={i} fill={SOURCE_COLORS[entry.name] || CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="empty">No source data</div>}
        </div>
      </div>

      {/* Top lists row — clickable */}
      <div className="charts-grid" style={{gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))'}}>
        <div className="chart-panel">
          <h3><Zap size={14} /> Top Source IPs</h3>
          {topIps.length > 0 ? (
            <ul className="top-list">
              {topIps.map(([ip, count]) => (
                <li key={ip} className="clickable" onClick={() => navigate(`/events?src_ip=${ip}`)}>
                  <span className="ip">{ip}</span><span className="count">{count}</span>
                </li>
              ))}
            </ul>
          ) : <div className="empty">No data</div>}
        </div>

        <div className="chart-panel">
          <h3><TrendingUp size={14} /> Top Users</h3>
          {topUsers.length > 0 ? (
            <ul className="top-list">
              {topUsers.map(([user, count]) => (
                <li key={user} className="clickable" onClick={() => navigate(`/events?user_name=${user}`)}>
                  <span className="name">{user}</span><span className="count">{count}</span>
                </li>
              ))}
            </ul>
          ) : <div className="empty">No user data</div>}
        </div>

        <div className="chart-panel">
          <h3><Activity size={14} /> Top Actions</h3>
          {topActions.length > 0 ? (
            <ul className="top-list">
              {topActions.map(([action, count]) => (
                <li key={action} className="clickable" onClick={() => navigate(`/events?action=${action}`)}>
                  <span className="name">{action}</span><span className="count">{count}</span>
                </li>
              ))}
            </ul>
          ) : <div className="empty">No action data</div>}
        </div>
      </div>
    </div>
  );
}
