import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Pencil } from 'lucide-react';
import WidgetRenderer from '../widgets/WidgetRenderer';
import { DEFAULT_DASHBOARD } from '../widgets/WidgetRegistry';
import { api } from '../api';

function loadDashboard() {
  try {
    const stored = localStorage.getItem('outpost_dashboard');
    if (stored) return JSON.parse(stored);
  } catch {}
  return DEFAULT_DASHBOARD;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [dashboard] = useState(loadDashboard);
  const [widgetData, setWidgetData] = useState({});
  const [error, setError] = useState(null);
  const [loaded, setLoaded] = useState(false);

  // Fetch data for all widget data sources
  useEffect(() => {
    let cancelled = false;
    async function fetchAll() {
      try {
        const data = {};
        const needed = new Set(
          dashboard.widgets.filter(w => w.dataSource !== '_self').map(w => w.dataSource)
        );
        const fetchers = {
          health: () => api.health(),
          timeline: () => api.timeline(24),
          sources: () => api.sources(),
          severity: () => api.severity(),
          categories: () => api.categories(),
          topIps: () => api.topIps(8),
          topUsers: () => api.topUsers(8),
          topActions: () => api.topActions(8),
        };
        await Promise.all([...needed].map(async ds => {
          try { data[ds] = await fetchers[ds]?.(); } catch {}
        }));
        if (!cancelled) {
          setWidgetData(data);
          setLoaded(true);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e.message);
      }
    }
    fetchAll();
    const interval = setInterval(fetchAll, 15000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [dashboard.widgets]);

  if (error && !loaded) return (
    <div className="loading">
      <div className="loading-spinner" />
      <div>Connecting to Firewatch backend...</div>
      <div style={{ fontSize: 12, marginTop: 8, color: 'var(--text-muted)' }}>{error}</div>
    </div>
  );

  if (!loaded && dashboard.widgets.some(w => w.dataSource !== '_self')) return (
    <div className="loading"><div className="loading-spinner" /><div>Loading dashboard...</div></div>
  );

  const sorted = [...dashboard.widgets].sort((a, b) => a.order - b.order);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1><span style={{ color: 'var(--accent)', fontWeight: 800, letterSpacing: '0.5px' }}>FIREWATCH</span> Dashboard</h1>
          <div className="subtitle">Real-time security monitoring overview</div>
        </div>
        <button className="btn-secondary" onClick={() => navigate('/dashboard/edit')}>
          <Pencil size={14} /> Customize
        </button>
      </div>

      <div className="widget-grid">
        {sorted.map(widget => {
          const isStat = widget.type === 'stat_card';
          const sizeClass = `widget-${widget.size || 'half'}`;
          const heightStyle = widget.height ? { height: widget.height, overflow: 'hidden' } : {};

          return (
            <div key={widget.id} className={`${isStat ? 'stat-card' : 'chart-panel'} ${sizeClass}`} style={heightStyle}>
              {isStat && <div className="label">{widget.title}</div>}
              {!isStat && widget.type !== 'geo_map' && (
                <h3 style={{ margin: '0 0 8px 0', fontSize: 13 }}>{widget.title}</h3>
              )}
              <WidgetRenderer type={widget.type} data={widgetData[widget.dataSource]} config={widget} />
            </div>
          );
        })}
      </div>
    </div>
  );
}
