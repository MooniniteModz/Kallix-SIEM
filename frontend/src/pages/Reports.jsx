import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area
} from 'recharts';
import {
  FileText, TrendingUp, Shield, AlertTriangle, Activity, Clock,
  Database, Zap, Users, Globe, RefreshCw
} from 'lucide-react';
import { api } from '../api';

const SEVERITY_COLORS = {
  critical: '#f85149', high: '#db6d28', warning: '#d29922',
  medium: '#d29922', low: '#3fb950', info: '#58a6ff',
  informational: '#58a6ff', debug: '#8b949e',
};
const SOURCE_COLORS = {
  Azure: '#58a6ff', M365: '#bc8cff', FortiGate: '#db6d28',
  Windows: '#79c0ff', Syslog: '#3fb950', Unknown: '#8b949e',
};
const CHART_COLORS = ['#00d4aa', '#58a6ff', '#bc8cff', '#db6d28', '#d29922', '#f85149', '#3fb950', '#79c0ff'];
const tooltipStyle = { background: '#161b22', border: '1px solid #30363d', borderRadius: 8, fontSize: 12 };

function formatNumber(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return (n ?? 0).toLocaleString();
}
function formatUptime(ms) {
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  if (h > 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
function formatTime(ms) {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
function formatDate(ms) {
  return new Date(ms).toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export default function Reports() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('overview');

  async function loadData() {
    try {
      const d = await api.reportSummary();
      setData(d);
    } catch {}
    setLoading(false);
  }

  useEffect(() => { loadData(); }, []);

  if (loading) return (
    <div className="loading"><div className="loading-spinner" /><div>Loading reports...</div></div>
  );
  if (!data) return (
    <div className="loading"><div>Failed to load report data</div></div>
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <h1><FileText size={20} style={{verticalAlign: 'middle'}} /> Security Reports</h1>
          <div className="subtitle">KPIs, threat intelligence, and security posture overview</div>
        </div>
        <button className="btn-secondary" onClick={() => { setLoading(true); loadData(); }}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      <div className="filter-tabs" style={{marginBottom: 20}}>
        <button className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')}>
          <TrendingUp size={14} /> Executive Overview
        </button>
        <button className={tab === 'threats' ? 'active' : ''} onClick={() => setTab('threats')}>
          <AlertTriangle size={14} /> Threat Analysis
        </button>
        <button className={tab === 'operations' ? 'active' : ''} onClick={() => setTab('operations')}>
          <Activity size={14} /> Operations
        </button>
      </div>

      {tab === 'overview' && <OverviewReport data={data} navigate={navigate} />}
      {tab === 'threats' && <ThreatReport data={data} navigate={navigate} />}
      {tab === 'operations' && <OperationsReport data={data} navigate={navigate} />}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// EXECUTIVE OVERVIEW
// ════════════════════════════════════════════════════════════════

function OverviewReport({ data, navigate }) {
  const sevData = (data.by_severity || []).map(([name, value]) => ({ name, value }));
  const srcData = (data.by_source || []).map(([name, value]) => ({ name, value }));
  const totalEvents = sevData.reduce((sum, d) => sum + d.value, 0);
  const criticalHigh = sevData.filter(d => ['critical', 'high'].includes(d.name.toLowerCase()))
    .reduce((sum, d) => sum + d.value, 0);
  const critPercent = totalEvents > 0 ? ((criticalHigh / totalEvents) * 100).toFixed(1) : 0;

  return (
    <div>
      {/* KPI Row */}
      <div className="report-kpi-grid">
        <KpiCard icon={<Database size={20} />} label="Events Today"
                 value={formatNumber(data.events_today)} color="var(--accent)" />
        <KpiCard icon={<Zap size={20} />} label="Total Events"
                 value={formatNumber(data.total_events)} color="var(--blue)" />
        <KpiCard icon={<AlertTriangle size={20} />} label="Alerts Fired"
                 value={formatNumber(data.alerts_fired)} color="var(--yellow)" />
        <KpiCard icon={<Shield size={20} />} label="Active Rules"
                 value={data.rule_count} color="var(--green)" />
        <KpiCard icon={<Activity size={20} />} label="Uptime"
                 value={formatUptime(data.uptime_ms)} color="var(--text-muted)" />
        <KpiCard icon={<AlertTriangle size={20} />} label="Critical/High %"
                 value={`${critPercent}%`}
                 color={critPercent > 20 ? 'var(--red)' : critPercent > 10 ? 'var(--yellow)' : 'var(--green)'} />
      </div>

      {/* 7-Day Timeline */}
      <div className="chart-panel" style={{marginBottom: 16}}>
        <h3><TrendingUp size={14} /> Event Volume (7 Days)</h3>
        <TimelineChart data={data.timeline_7d} formatLabel={formatDate} height={220} />
      </div>

      {/* Severity + Source row */}
      <div className="dashboard-row even">
        <div className="chart-panel">
          <h3><AlertTriangle size={14} /> Events by Severity</h3>
          {sevData.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="name" cx="50%" cy="50%"
                     innerRadius={50} outerRadius={85} paddingAngle={2}
                     label={({ name, value }) => `${name} (${formatNumber(value)})`}
                     labelLine={false} style={{fontSize: 11, cursor: 'pointer'}}
                     onClick={(_, i) => navigate(`/events?severity=${sevData[i].name}`)}>
                  {sevData.map((e, i) => (
                    <Cell key={i} fill={SEVERITY_COLORS[e.name.toLowerCase()] || CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          ) : <div className="empty">No data</div>}
        </div>
        <div className="chart-panel">
          <h3><Database size={14} /> Events by Source</h3>
          {srcData.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={srcData} layout="vertical" margin={{left: 10}}>
                <XAxis type="number" stroke="#30363d" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="name" stroke="#30363d" fontSize={11} width={80} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20} style={{cursor: 'pointer'}}
                     onClick={(d) => navigate(`/events?source_type=${d.name}`)}>
                  {srcData.map((e, i) => (
                    <Cell key={i} fill={SOURCE_COLORS[e.name] || CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="empty">No data</div>}
        </div>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// THREAT ANALYSIS
// ════════════════════════════════════════════════════════════════

function ThreatReport({ data, navigate }) {
  const topIps = data.top_ips || [];
  const topUsers = data.top_users || [];
  const alerts = data.recent_alerts || [];

  const alertsBySev = {};
  alerts.forEach(a => {
    const s = a.severity?.toLowerCase() || 'info';
    alertsBySev[s] = (alertsBySev[s] || 0) + 1;
  });

  return (
    <div>
      {/* Alert summary cards */}
      <div className="report-kpi-grid" style={{marginBottom: 20}}>
        <KpiCard icon={<AlertTriangle size={20} />} label="Total Alerts"
                 value={data.alert_count} color="var(--yellow)" />
        <KpiCard icon={<Shield size={20} />} label="Critical Alerts"
                 value={alertsBySev.critical || 0}
                 color={alertsBySev.critical > 0 ? 'var(--red)' : 'var(--green)'} />
        <KpiCard icon={<Shield size={20} />} label="High Alerts"
                 value={alertsBySev.high || 0}
                 color={alertsBySev.high > 0 ? 'var(--orange)' : 'var(--green)'} />
        <KpiCard icon={<Shield size={20} />} label="Medium/Low"
                 value={(alertsBySev.medium || 0) + (alertsBySev.low || 0)}
                 color="var(--text-muted)" />
      </div>

      {/* Recent alerts table */}
      <div className="chart-panel" style={{marginBottom: 16}}>
        <h3><AlertTriangle size={14} /> Recent Alerts</h3>
        {alerts.length > 0 ? (
          <div className="table-container" style={{maxHeight: 300, overflowY: 'auto'}}>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Target</th>
                  <th>Events</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => (
                  <tr key={a.alert_id} style={{cursor: 'pointer'}} onClick={() => navigate('/alerts')}>
                    <td style={{fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap'}}>
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                    <td style={{fontWeight: 500, fontSize: 12}}>{a.rule_name}</td>
                    <td>
                      <span className={`badge ${a.severity?.toLowerCase()}`}>{a.severity}</span>
                    </td>
                    <td style={{fontSize: 12, fontFamily: 'var(--mono)'}}>{a.group_key}</td>
                    <td style={{textAlign: 'center'}}>{a.event_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty">No alerts generated yet</div>}
      </div>

      {/* Top IPs + Users row */}
      <div className="dashboard-row even">
        <div className="chart-panel">
          <h3><Globe size={14} /> Top Source IPs (Threat Surface)</h3>
          {topIps.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={topIps.map(([name, value]) => ({name, value}))} layout="vertical" margin={{left: 10}}>
                <XAxis type="number" stroke="#30363d" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="name" stroke="#30363d" fontSize={10} width={110} tickLine={false} axisLine={false}
                       style={{fontFamily: 'var(--mono)'}} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="value" fill="#f85149" radius={[0, 4, 4, 0]} barSize={14} style={{cursor: 'pointer'}}
                     onClick={(d) => navigate(`/events?src_ip=${d.name}`)} />
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="empty">No data</div>}
        </div>
        <div className="chart-panel">
          <h3><Users size={14} /> Top Users (Activity Volume)</h3>
          {topUsers.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={topUsers.map(([name, value]) => ({name, value}))} layout="vertical" margin={{left: 10}}>
                <XAxis type="number" stroke="#30363d" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="name" stroke="#30363d" fontSize={10} width={110} tickLine={false} axisLine={false}
                       style={{fontFamily: 'var(--mono)'}} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="value" fill="#58a6ff" radius={[0, 4, 4, 0]} barSize={14} style={{cursor: 'pointer'}}
                     onClick={(d) => navigate(`/events?user_name=${d.name}`)} />
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="empty">No data</div>}
        </div>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// OPERATIONS REPORT
// ════════════════════════════════════════════════════════════════

function OperationsReport({ data, navigate }) {
  const catData = (data.by_category || []).map(([name, value]) => ({ name, value }));
  const topActions = data.top_actions || [];

  const eps = data.uptime_ms > 0 ? ((data.total_events / (data.uptime_ms / 1000))).toFixed(2) : '0';
  const dropRate = data.total_events > 0
    ? ((data.buffer_drops / data.total_events) * 100).toFixed(3) : '0';

  return (
    <div>
      {/* Operational KPIs */}
      <div className="report-kpi-grid" style={{marginBottom: 20}}>
        <KpiCard icon={<TrendingUp size={20} />} label="Events/Second (avg)"
                 value={eps} color="var(--accent)" />
        <KpiCard icon={<Database size={20} />} label="Buffer Usage"
                 value={formatNumber(data.buffer_usage)} color="var(--blue)" />
        <KpiCard icon={<AlertTriangle size={20} />} label="Buffer Drops"
                 value={formatNumber(data.buffer_drops)}
                 color={data.buffer_drops > 0 ? 'var(--red)' : 'var(--green)'} />
        <KpiCard icon={<Activity size={20} />} label="Drop Rate"
                 value={`${dropRate}%`}
                 color={parseFloat(dropRate) > 1 ? 'var(--red)' : 'var(--green)'} />
      </div>

      {/* 24h Timeline */}
      <div className="chart-panel" style={{marginBottom: 16}}>
        <h3><Clock size={14} /> Event Ingestion (24h)</h3>
        <TimelineChart data={data.timeline_24h} formatLabel={formatTime} height={200} />
      </div>

      {/* Category + Actions row */}
      <div className="dashboard-row even">
        <div className="chart-panel">
          <h3><Shield size={14} /> Events by Category</h3>
          {catData.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={catData} dataKey="value" nameKey="name" cx="50%" cy="50%"
                     innerRadius={50} outerRadius={85} paddingAngle={2}
                     label={({ name, value }) => `${name} (${formatNumber(value)})`}
                     labelLine={false} style={{fontSize: 11}}>
                  {catData.map((_, i) => (
                    <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          ) : <div className="empty">No data</div>}
        </div>
        <div className="chart-panel">
          <h3><Zap size={14} /> Top Event Actions</h3>
          {topActions.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={topActions.map(([name, value]) => ({name, value}))} layout="vertical" margin={{left: 10}}>
                <XAxis type="number" stroke="#30363d" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="name" stroke="#30363d" fontSize={10} width={130} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={14}>
                  {topActions.map((_, i) => (
                    <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="empty">No data</div>}
        </div>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// SHARED COMPONENTS
// ════════════════════════════════════════════════════════════════

function KpiCard({ icon, label, value, color }) {
  return (
    <div className="report-kpi-card">
      <div className="report-kpi-icon" style={{color}}>{icon}</div>
      <div>
        <div className="report-kpi-value" style={{color}}>{value}</div>
        <div className="report-kpi-label">{label}</div>
      </div>
    </div>
  );
}

function TimelineChart({ data, formatLabel, height = 200 }) {
  if (!Array.isArray(data) || data.length === 0) return <div className="empty">No timeline data</div>;
  const chartData = data.map(([time, count]) => ({ time, count }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={chartData}>
        <defs>
          <linearGradient id="reportGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#00d4aa" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#00d4aa" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis dataKey="time" tickFormatter={formatLabel} stroke="#30363d" fontSize={10} tickLine={false} axisLine={false} />
        <YAxis stroke="#30363d" fontSize={10} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} labelFormatter={formatLabel} />
        <Area type="monotone" dataKey="count" stroke="#00d4aa" strokeWidth={2} fill="url(#reportGrad)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}
