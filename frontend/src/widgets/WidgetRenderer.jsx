import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area
} from 'recharts';

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
  if (!data) return <div className="empty" style={{padding: 20}}>Loading...</div>;

  switch (type) {
    case 'stat_card': return <StatRenderer data={data} config={config} />;
    case 'area_chart': return <AreaChartRenderer data={data} />;
    case 'bar_chart': return <BarChartRenderer data={data} config={config} />;
    case 'pie_chart': return <PieChartRenderer data={data} config={config} />;
    case 'top_list': return <TopListRenderer data={data} />;
    default: return <div className="empty">Unknown widget type</div>;
  }
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
  if (!Array.isArray(data) || data.length === 0) return <div className="empty">No data</div>;
  const chartData = data.map(([time, count]) => ({ time, count }));
  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={chartData}>
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
  if (!Array.isArray(data) || data.length === 0) return <div className="empty">No data</div>;
  const chartData = data.map(([name, value]) => ({ name, value }));
  const colors = config?.dataSource === 'sources' ? SOURCE_COLORS : SEVERITY_COLORS;
  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={chartData} layout="vertical" margin={{left: 10}}>
        <XAxis type="number" stroke="#30363d" fontSize={10} tickLine={false} axisLine={false} />
        <YAxis type="category" dataKey="name" stroke="#30363d" fontSize={10} width={70} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={18}>
          {chartData.map((entry, i) => (
            <Cell key={i} fill={colors[entry.name] || colors[entry.name?.toLowerCase()] || CHART_COLORS[i % CHART_COLORS.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function PieChartRenderer({ data, config }) {
  if (!Array.isArray(data) || data.length === 0) return <div className="empty">No data</div>;
  const chartData = data.map(([name, value]) => ({ name, value }));
  const colors = config?.dataSource === 'sources' ? SOURCE_COLORS : SEVERITY_COLORS;
  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie data={chartData} dataKey="value" nameKey="name" cx="50%" cy="50%"
             innerRadius={40} outerRadius={70} paddingAngle={2}
             label={({ name, value }) => `${name} (${value})`} labelLine={false}
             style={{fontSize: 10}}>
          {chartData.map((entry, i) => (
            <Cell key={i} fill={colors[entry.name] || colors[entry.name?.toLowerCase()] || CHART_COLORS[i % CHART_COLORS.length]} />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
      </PieChart>
    </ResponsiveContainer>
  );
}

function TopListRenderer({ data }) {
  if (!Array.isArray(data) || data.length === 0) return <div className="empty">No data</div>;
  return (
    <ul className="top-list" style={{maxHeight: 200, overflowY: 'auto'}}>
      {data.map(([name, count]) => (
        <li key={name}>
          <span className="name" style={{fontFamily: 'var(--mono)', fontSize: 12}}>{name}</span>
          <span className="count">{count}</span>
        </li>
      ))}
    </ul>
  );
}
