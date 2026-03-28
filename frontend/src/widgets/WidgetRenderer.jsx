import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area, Legend
} from 'recharts';
import Globe3D from '../components/Globe3D';

const SEVERITY_COLORS = {
  critical: '#c93c37', error: '#c93c37', high: '#a85620',
  warning: '#a67a1a', medium: '#a67a1a', low: '#2d8a3e',
  info: '#3d7ec7', informational: '#3d7ec7', debug: '#636c76',
};

const SOURCE_COLORS = {
  Azure: '#58a6ff', azure: '#58a6ff',
  M365: '#bc8cff', m365: '#bc8cff',
  FortiGate: '#db6d28', fortigate: '#db6d28',
  Windows: '#79c0ff', windows: '#79c0ff',
  UniFi: '#00d4aa', unifi: '#00d4aa',
  Syslog: '#3fb950', syslog: '#3fb950',
  Unknown: '#8b949e', unknown: '#8b949e',
};

const CHART_COLORS = ['#00d4aa', '#58a6ff', '#bc8cff', '#db6d28', '#d29922', '#f85149', '#3fb950', '#79c0ff'];

const tooltipStyle = { background: '#161b22', border: '1px solid #30363d', borderRadius: 8, fontSize: 12 };

function formatTime(ms) {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatNumber(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return (n ?? 0).toLocaleString();
}

function formatUptime(ms) {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

export default function WidgetRenderer({ type, data, config }) {
  if (type === 'geo_map') return <GeoMapRenderer config={config} />;
  if (!data) return <div className="empty" style={{padding: 20}}>Loading...</div>;

  switch (type) {
    case 'stat_card': return <StatRenderer data={data} config={config} />;
    case 'area_chart': return <AreaChartRenderer data={data} />;
    case 'bar_chart': return <BarChartRenderer data={data} config={config} />;
    case 'pie_chart': return <PieChartRenderer data={data} config={config} />;
    case 'top_list': return <TopListRenderer data={data} config={config} />;
    default: return <div className="empty">Unknown widget type</div>;
  }
}

function GeoMapRenderer({ config }) {
  const height = config?.height || 520;
  return (
    <div style={{ height: height - 40, display: 'flex', flexDirection: 'column' }}>
      <Globe3D />
    </div>
  );
}

function StatRenderer({ data, config }) {
  const field = config?.params?.field || 'events_stored_today';
  const value = data[field] ?? 0;
  const display = field === 'uptime_ms' ? formatUptime(value) : formatNumber(value);

  return (
    <div style={{textAlign: 'center', padding: '12px 0'}}>
      <div style={{fontSize: 32, fontWeight: 700, color: 'var(--accent)', fontVariantNumeric: 'tabular-nums'}}>
        {display}
      </div>
    </div>
  );
}

function AreaChartRenderer({ data }) {
  const navigate = useNavigate();
  if (!Array.isArray(data) || data.length === 0) return <div className="empty">No data</div>;
  const chartData = data.map(([time, count]) => ({ time, count }));
  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={chartData} onClick={(e) => {
        if (e?.activePayload?.[0]) {
          const t = e.activePayload[0].payload.time;
          navigate(`/events?start=${t}&end=${t + 3600000}`);
        }
      }} style={{cursor: 'pointer'}}>
        <defs>
          <linearGradient id="wColorCount" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#00d4aa" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#00d4aa" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis dataKey="time" tickFormatter={formatTime} stroke="#30363d" fontSize={10} tickLine={false} axisLine={false} />
        <YAxis stroke="#30363d" fontSize={10} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} labelFormatter={formatTime} />
        <Area type="monotone" dataKey="count" stroke="#00d4aa" strokeWidth={2} fill="url(#wColorCount)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function BarChartRenderer({ data, config }) {
  const navigate = useNavigate();
  if (!Array.isArray(data) || data.length === 0) return <div className="empty">No data</div>;
  const chartData = data.map(([name, value]) => ({ name, value }));
  const colors = config?.dataSource === 'sources' ? SOURCE_COLORS : SEVERITY_COLORS;
  const filterKey = config?.dataSource === 'sources' ? 'source_type' : 'severity';
  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={chartData} layout="vertical" margin={{left: 10}}>
        <XAxis type="number" stroke="#30363d" fontSize={10} tickLine={false} axisLine={false} />
        <YAxis type="category" dataKey="name" stroke="#30363d" fontSize={10} width={70} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={18} style={{cursor: 'pointer'}}
             onClick={(d) => navigate(`/events?${filterKey}=${d.name}`)}>
          {chartData.map((entry, i) => (
            <Cell key={i} fill={colors[entry.name] || colors[entry.name?.toLowerCase()] || CHART_COLORS[i % CHART_COLORS.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function PieChartRenderer({ data, config }) {
  const navigate = useNavigate();
  if (!Array.isArray(data) || data.length === 0) return <div className="empty">No data</div>;
  const chartData = data.map(([name, value]) => ({ name, value }));
  const colors = config?.dataSource === 'sources' ? SOURCE_COLORS : SEVERITY_COLORS;
  const filterKey = config?.dataSource === 'sources' ? 'source_type' : 'severity';
  return (
    <ResponsiveContainer width="100%" height={280}>
      <PieChart>
        <Pie data={chartData} dataKey="value" nameKey="name" cx="50%" cy="45%"
             innerRadius="35%" outerRadius="60%" paddingAngle={2}
             style={{cursor: 'pointer'}}
             onClick={(_, index) => navigate(`/events?${filterKey}=${chartData[index].name}`)}
             label={({ cx, cy, midAngle, innerRadius: ir, outerRadius: or, percent }) => {
               const RADIAN = Math.PI / 180;
               const radius = ir + (or - ir) * 0.5;
               const x = cx + radius * Math.cos(-midAngle * RADIAN);
               const y = cy + radius * Math.sin(-midAngle * RADIAN);
               if (percent < 0.05) return null;
               return (
                 <text x={x} y={y} fill="#fff" textAnchor="middle" dominantBaseline="central"
                       style={{ fontSize: 14, fontWeight: 700, cursor: 'pointer', textShadow: '0 1px 3px rgba(0,0,0,0.6)' }}>
                   {(percent * 100).toFixed(1)}%
                 </text>
               );
             }}
             labelLine={false}>
          {chartData.map((entry, i) => (
            <Cell key={i} fill={colors[entry.name] || colors[entry.name?.toLowerCase()] || CHART_COLORS[i % CHART_COLORS.length]} stroke="#0d1117" strokeWidth={2} />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
        <Legend
          verticalAlign="bottom" height={28} iconType="circle" iconSize={8}
          formatter={(value) => <span style={{ color: '#8b949e', fontSize: 11 }}>{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}

function TopListRenderer({ data, config }) {
  const navigate = useNavigate();
  if (!Array.isArray(data) || data.length === 0) return <div className="empty">No data</div>;
  const filterKey = config?.dataSource === 'topIps' ? 'src_ip'
    : config?.dataSource === 'topUsers' ? 'user_name' : 'action';
  return (
    <ul className="top-list" style={{maxHeight: 200, overflowY: 'auto'}}>
      {data.map(([name, count]) => (
        <li key={name} className="clickable" onClick={() => navigate(`/events?${filterKey}=${name}`)}>
          <span className="name" style={{fontFamily: 'var(--mono)', fontSize: 12}}>{name}</span>
          <span className="count">{count}</span>
        </li>
      ))}
    </ul>
  );
}
