import { useState, useEffect, useMemo, useCallback, memo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ComposableMap, Geographies, Geography, Marker, ZoomableGroup
} from 'react-simple-maps';
import { api } from '../api';
import {
  Globe, RefreshCw, MapPin, Circle, ChevronDown, ChevronUp, Layers,
  Maximize2, Minimize2
} from 'lucide-react';

const GEO_URL = 'https://cdn.jsdelivr.net/npm/us-atlas@3/states-10m.json';

// ── Dynamic color system ──
// Rotating palette that assigns colors to ANY source type on first encounter.
// Well-known sources get stable colors; everything else gets the next available.
const KNOWN_COLORS = {
  Azure:       '#58a6ff',
  Entra:       '#58a6ff',
  M365:        '#d29922',
  UniFi:       '#3fb950',
  Meraki:      '#00d4aa',
  FortiGate:   '#db6d28',
  Fortinet:    '#db6d28',
  PaloAlto:    '#f0883e',
  Windows:     '#79c0ff',
  CrowdStrike: '#f85149',
  SentinelOne: '#bc8cff',
  Syslog:      '#bc8cff',
  Okta:        '#6e40c9',
  Duo:         '#3fb950',
  Sophos:      '#e3b341',
  Cisco:       '#00b4d8',
  AWS:         '#ff9800',
  GCP:         '#4285f4',
};
const FALLBACK_PALETTE = [
  '#00d4aa', '#58a6ff', '#bc8cff', '#db6d28', '#d29922',
  '#f85149', '#3fb950', '#79c0ff', '#6e40c9', '#e3b341',
  '#f0883e', '#00b4d8', '#ff9800', '#4285f4', '#a371f7',
];
const _dynamicMap = {};
let _nextIdx = 0;
function colorForSource(source) {
  if (!source) return '#8b949e';
  if (KNOWN_COLORS[source]) return KNOWN_COLORS[source];
  if (_dynamicMap[source]) return _dynamicMap[source];
  _dynamicMap[source] = FALLBACK_PALETTE[_nextIdx % FALLBACK_PALETTE.length];
  _nextIdx++;
  return _dynamicMap[source];
}

const STATUS_COLOR = {
  online:  '#3fb950',
  offline: '#f85149',
  alert:   '#d29922',
};

// ── Demo data ──
// Shown when no real geo-tagged events exist. Covers several source types
// so the user can see how different integrations render on the map.
const DEMO_POINTS = [
  // Entra ID / Azure AD sign-in locations
  { lat: 40.7128, lng: -74.0060, label: 'New York, NY',     source: 'Entra',     type: 'login',  status: 'online', count: 47 },
  { lat: 34.0522, lng: -118.2437, label: 'Los Angeles, CA', source: 'Entra',     type: 'login',  status: 'online', count: 31 },
  { lat: 41.8781, lng: -87.6298, label: 'Chicago, IL',      source: 'Entra',     type: 'login',  status: 'online', count: 22 },
  { lat: 29.7604, lng: -95.3698, label: 'Houston, TX',      source: 'Entra',     type: 'login',  status: 'online', count: 18 },
  { lat: 47.6062, lng: -122.3321, label: 'Seattle, WA',     source: 'Entra',     type: 'login',  status: 'alert',  count: 8 },
  { lat: 25.7617, lng: -80.1918, label: 'Miami, FL',        source: 'Entra',     type: 'login',  status: 'online', count: 15 },
  { lat: 39.7392, lng: -104.9903, label: 'Denver, CO',      source: 'Entra',     type: 'login',  status: 'online', count: 9 },
  { lat: 33.4484, lng: -112.0740, label: 'Phoenix, AZ',     source: 'Entra',     type: 'login',  status: 'online', count: 12 },

  // Meraki network devices
  { lat: 37.7749, lng: -122.4194, label: 'SF HQ — MR46',         source: 'Meraki', type: 'device', status: 'online',  count: 1, details: { device_type: 'ap', model: 'MR46', ip: '10.10.1.10' } },
  { lat: 37.7820, lng: -122.3915, label: 'SF HQ — MS390-48',     source: 'Meraki', type: 'device', status: 'online',  count: 1, details: { device_type: 'switch', model: 'MS390-48', ip: '10.10.1.1' } },
  { lat: 34.0195, lng: -118.4912, label: 'LA Office — MX250',    source: 'Meraki', type: 'device', status: 'online',  count: 1, details: { device_type: 'gateway', model: 'MX250', ip: '10.10.2.1' } },
  { lat: 30.2672, lng: -97.7431, label: 'Austin — MR56',         source: 'Meraki', type: 'device', status: 'offline', count: 1, details: { device_type: 'ap', model: 'MR56', ip: '10.10.3.10' } },

  // UniFi network devices
  { lat: 40.7589, lng: -73.9851, label: 'NYC HQ — USW-Pro-48',   source: 'UniFi', type: 'device', status: 'online',  count: 1, details: { device_type: 'switch', model: 'USW-Pro-48-PoE', ip: '10.0.1.1' } },
  { lat: 40.7505, lng: -73.9934, label: 'NYC HQ — U6-LR AP',    source: 'UniFi', type: 'device', status: 'online',  count: 1, details: { device_type: 'ap', model: 'U6-LR', ip: '10.0.1.20' } },
  { lat: 41.8827, lng: -87.6233, label: 'Chicago DC — USW-Agg',  source: 'UniFi', type: 'device', status: 'online',  count: 1, details: { device_type: 'switch', model: 'USW-Aggregation', ip: '10.0.3.1' } },
  { lat: 29.7545, lng: -95.3632, label: 'Houston — U6-Pro AP',   source: 'UniFi', type: 'device', status: 'offline', count: 1, details: { device_type: 'ap', model: 'U6-Pro', ip: '10.0.4.10' } },
  { lat: 47.6205, lng: -122.3493, label: 'Seattle — USW-Pro-24', source: 'UniFi', type: 'device', status: 'online',  count: 1, details: { device_type: 'switch', model: 'USW-Pro-24-PoE', ip: '10.0.5.1' } },
  { lat: 39.7500, lng: -104.9995, label: 'Denver — U6-Mesh AP',  source: 'UniFi', type: 'device', status: 'alert',   count: 1, details: { device_type: 'ap', model: 'U6-Mesh', ip: '10.0.7.10' } },

  // FortiGate firewalls
  { lat: 40.7128, lng: -74.0260, label: 'NYC — FG-200F',     source: 'FortiGate', type: 'device', status: 'online', count: 342 },
  { lat: 34.0522, lng: -118.2837, label: 'LA — FG-100F',     source: 'FortiGate', type: 'device', status: 'online', count: 198 },
  { lat: 37.7749, lng: -122.3894, label: 'SF — FG-400F',     source: 'FortiGate', type: 'device', status: 'alert',  count: 56 },

  // CrowdStrike endpoints
  { lat: 40.7282, lng: -73.7949, label: 'NYC — 12 sensors',  source: 'CrowdStrike', type: 'endpoint', status: 'online', count: 12 },
  { lat: 34.0622, lng: -118.3037, label: 'LA — 8 sensors',   source: 'CrowdStrike', type: 'endpoint', status: 'online', count: 8 },
  { lat: 42.3601, lng: -71.0589, label: 'Boston — 5 sensors', source: 'CrowdStrike', type: 'endpoint', status: 'online', count: 5 },
  { lat: 38.9072, lng: -77.0369, label: 'DC — 6 sensors',    source: 'CrowdStrike', type: 'endpoint', status: 'online', count: 6 },

  // Syslog infrastructure
  { lat: 39.0997, lng: -94.5786, label: 'Kansas City DC',    source: 'Syslog', type: 'event', status: 'online', count: 89 },
  { lat: 36.1627, lng: -86.7816, label: 'Nashville DC',      source: 'Syslog', type: 'event', status: 'online', count: 45 },
  { lat: 35.2271, lng: -80.8431, label: 'Charlotte DC',      source: 'Syslog', type: 'event', status: 'online', count: 33 },
];

// ── Memoized map geography (static, never re-renders) ──
const MapGeographies = memo(function MapGeographies() {
  return (
    <Geographies geography={GEO_URL}>
      {({ geographies }) =>
        geographies.map((geo) => (
          <Geography
            key={geo.rpiGlobalProperties || geo.properties?.name || geo.id}
            geography={geo}
            fill="#161b22"
            stroke="#30363d"
            strokeWidth={0.5}
            style={{
              default: { outline: 'none' },
              hover: { fill: '#1c2128', outline: 'none' },
              pressed: { outline: 'none' },
            }}
          />
        ))
      }
    </Geographies>
  );
});

function MarkerDot({ point, isHovered, onHover, onLeave, onClick }) {
  const color = colorForSource(point.source);
  const statusColor = STATUS_COLOR[point.status] || '#8b949e';
  const size = Math.max(4, Math.min(14, 4 + Math.log2(point.count + 1) * 2));

  return (
    <Marker coordinates={[point.lng, point.lat]}>
      <g
        onMouseEnter={onHover}
        onMouseLeave={onLeave}
        onClick={onClick}
        style={{ cursor: 'pointer' }}
      >
        {point.status === 'alert' && (
          <circle r={size + 6} fill="none" stroke={STATUS_COLOR.alert} strokeWidth={1.5} opacity={0.6}>
            <animate attributeName="r" from={size + 2} to={size + 10} dur="1.5s" repeatCount="indefinite" />
            <animate attributeName="opacity" from="0.6" to="0" dur="1.5s" repeatCount="indefinite" />
          </circle>
        )}
        <circle r={size + 2} fill="none" stroke={statusColor} strokeWidth={1.5} opacity={0.7} />
        <circle r={size} fill={color} opacity={isHovered ? 1 : 0.85} />
        <circle r={size * 0.4} fill="#fff" opacity={isHovered ? 0.5 : 0.2} />
        {point.count > 5 && (
          <text
            textAnchor="middle"
            y={size + 14}
            style={{ fontSize: 9, fill: '#8b949e', fontFamily: 'var(--sans)', fontWeight: 600 }}
          >
            {point.count}
          </text>
        )}
      </g>
    </Marker>
  );
}

export default function GeoMap({ embeddedHeight, hideHeader } = {}) {
  const navigate = useNavigate();
  const [activeFilter, setActiveFilter] = useState('all');
  const [allPoints, setAllPoints] = useState([]);   // unfiltered dataset
  const [loading, setLoading] = useState(true);
  const [hoveredPoint, setHoveredPoint] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [expanded, setExpanded] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);
  const [usingDemo, setUsingDemo] = useState(false);

  // Fetch ALL points once, filter client-side so toggling is instant
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const data = await api.geoPoints('');
        if (cancelled) return;
        if (data.points && data.points.length > 0) {
          setAllPoints(data.points);
          setUsingDemo(false);
        } else {
          setAllPoints(DEMO_POINTS);
          setUsingDemo(true);
        }
      } catch {
        setAllPoints(DEMO_POINTS);
        setUsingDemo(true);
      }
      setLoading(false);
    }
    setLoading(true);
    load();
    const interval = setInterval(load, 30000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  // Client-side filter
  const points = useMemo(() => {
    if (activeFilter === 'all') return allPoints;
    return allPoints.filter(p => p.source === activeFilter);
  }, [allPoints, activeFilter]);

  // Dynamically discover all source types present in the data
  const sourceFilters = useMemo(() => {
    const seen = new Map(); // source → count
    for (const p of allPoints) {
      seen.set(p.source, (seen.get(p.source) || 0) + 1);
    }
    // Sort by count descending so the most active sources appear first
    const sorted = [...seen.entries()].sort((a, b) => b[1] - a[1]);
    return sorted.map(([name]) => ({
      id: name,
      label: name,
      color: colorForSource(name),
    }));
  }, [allPoints]);

  // Stats
  const stats = useMemo(() => {
    const bySource = {};
    const byStatus = { online: 0, offline: 0, alert: 0 };
    let total = 0;
    for (const p of points) {
      bySource[p.source] = (bySource[p.source] || 0) + 1;
      if (byStatus[p.status] !== undefined) byStatus[p.status]++;
      total += p.count || 1;
    }
    return { bySource, byStatus, totalEvents: total, totalPoints: points.length };
  }, [points]);

  // Legend: only sources visible on the map right now
  const legendSources = useMemo(() => {
    const seen = new Set();
    for (const p of points) seen.add(p.source);
    return [...seen].sort();
  }, [points]);

  const handleMarkerHover = useCallback((point, event) => {
    const rect = event.currentTarget.closest('.geo-map-container')?.getBoundingClientRect();
    if (rect) {
      setTooltipPos({ x: event.clientX - rect.left, y: event.clientY - rect.top });
    }
    setHoveredPoint(point);
  }, []);

  const handleMarkerLeave = useCallback(() => setHoveredPoint(null), []);

  const handleMarkerClick = useCallback((point) => {
    if (point.source) navigate(`/events?source_type=${point.source}`);
  }, [navigate]);

  return (
    <div className={`geo-dashboard ${embeddedHeight ? 'geo-embedded' : ''} ${fullscreen ? 'geo-fullscreen' : ''}`}
         style={embeddedHeight && !fullscreen ? { height: '100%', display: 'flex', flexDirection: 'column' } : {}}>
      {/* Header */}
      {!hideHeader && (
        <div className="geo-header">
          <div className="geo-title-row">
            <h3><Globe size={16} /> Geospatial Overview</h3>
            <div className="geo-header-actions">
              {usingDemo && <span className="geo-demo-badge">Demo Data</span>}
              <button className="geo-collapse-btn" onClick={() => setExpanded(e => !e)}>
                {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              </button>
            </div>
          </div>

          {/* Dynamic filter bar — built from whatever sources exist in the data */}
          {expanded && (
            <div className="geo-filter-bar">
              <button
                className={`geo-filter-btn ${activeFilter === 'all' ? 'active' : ''}`}
                onClick={() => setActiveFilter('all')}
                style={activeFilter === 'all' ? { borderColor: '#00d4aa', color: '#00d4aa' } : {}}
              >
                <Layers size={13} />
                <span>All Sources</span>
                <span className="geo-filter-count">{allPoints.length}</span>
              </button>
              {sourceFilters.map(f => (
                <button
                  key={f.id}
                  className={`geo-filter-btn ${activeFilter === f.id ? 'active' : ''}`}
                  onClick={() => setActiveFilter(f.id)}
                  style={activeFilter === f.id ? { borderColor: f.color, color: f.color } : {}}
                >
                  <span className="geo-filter-swatch" style={{ background: f.color }} />
                  <span>{f.label}</span>
                  <span className="geo-filter-count">
                    {activeFilter === 'all'
                      ? (stats.bySource[f.id] || 0)
                      : (activeFilter === f.id ? points.length : 0)}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Compact filter bar when header is hidden (embedded in widget) */}
      {hideHeader && expanded && (
        <div className="geo-filter-bar" style={{ padding: '4px 8px' }}>
          <button
            className={`geo-filter-btn ${activeFilter === 'all' ? 'active' : ''}`}
            onClick={() => setActiveFilter('all')}
            style={activeFilter === 'all' ? { borderColor: '#00d4aa', color: '#00d4aa' } : {}}
          >
            <Layers size={13} />
            <span>All</span>
            <span className="geo-filter-count">{allPoints.length}</span>
          </button>
          {sourceFilters.map(f => (
            <button
              key={f.id}
              className={`geo-filter-btn ${activeFilter === f.id ? 'active' : ''}`}
              onClick={() => setActiveFilter(f.id)}
              style={activeFilter === f.id ? { borderColor: f.color, color: f.color } : {}}
            >
              <span className="geo-filter-swatch" style={{ background: f.color }} />
              <span>{f.label}</span>
            </button>
          ))}
          {usingDemo && <span className="geo-demo-badge" style={{ marginLeft: 'auto' }}>Demo</span>}
        </div>
      )}

      {expanded && (
        <div className="geo-body" style={embeddedHeight ? { flex: 1, minHeight: 0, overflow: 'hidden' } : {}}>
          {/* Status bar */}
          <div className="geo-status-bar">
            <div className="geo-stat">
              <span className="geo-stat-dot" style={{ background: '#3fb950' }} />
              <span>{stats.byStatus.online} Online</span>
            </div>
            <div className="geo-stat">
              <span className="geo-stat-dot" style={{ background: '#f85149' }} />
              <span>{stats.byStatus.offline} Offline</span>
            </div>
            <div className="geo-stat">
              <span className="geo-stat-dot" style={{ background: '#d29922' }} />
              <span>{stats.byStatus.alert} Alerts</span>
            </div>
            <div className="geo-stat-separator" />
            <div className="geo-stat">
              <MapPin size={12} />
              <span>{stats.totalPoints} Locations</span>
            </div>
            <div className="geo-stat">
              <Circle size={12} />
              <span>{stats.totalEvents.toLocaleString()} Events</span>
            </div>
          </div>

          {/* Map */}
          <div className="geo-map-container" style={{ position: 'relative' }}>
            {loading && (
              <div className="geo-loading">
                <RefreshCw size={18} className="geo-spin" />
                <span>Loading geo data...</span>
              </div>
            )}

            <button
              className="geo-expand-btn"
              onClick={() => setFullscreen(f => !f)}
              title={fullscreen ? 'Collapse map' : 'Expand map'}
            >
              {fullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
            </button>

            <ComposableMap
              projection="geoAlbersUsa"
              projectionConfig={{ scale: 1000 }}
              style={{ width: '100%', height: '100%', background: 'transparent' }}
            >
              <ZoomableGroup>
                <MapGeographies />
                {points.map((point, i) => (
                  <MarkerDot
                    key={`${point.lat}-${point.lng}-${point.source}-${i}`}
                    point={point}
                    isHovered={hoveredPoint === point}
                    onHover={(e) => handleMarkerHover(point, e)}
                    onLeave={handleMarkerLeave}
                    onClick={() => handleMarkerClick(point)}
                  />
                ))}
              </ZoomableGroup>
            </ComposableMap>

            {/* Tooltip */}
            {hoveredPoint && (
              <div
                className="geo-tooltip"
                style={{ left: tooltipPos.x + 12, top: tooltipPos.y - 10 }}
              >
                <div className="geo-tooltip-header">
                  <span
                    className="geo-tooltip-dot"
                    style={{ background: colorForSource(hoveredPoint.source) }}
                  />
                  <strong>{hoveredPoint.label}</strong>
                </div>
                <div className="geo-tooltip-row">
                  <span className="geo-tooltip-label">Source</span>
                  <span>{hoveredPoint.source}</span>
                </div>
                <div className="geo-tooltip-row">
                  <span className="geo-tooltip-label">Type</span>
                  <span>{hoveredPoint.type}</span>
                </div>
                <div className="geo-tooltip-row">
                  <span className="geo-tooltip-label">Status</span>
                  <span style={{ color: STATUS_COLOR[hoveredPoint.status] || '#8b949e' }}>
                    {hoveredPoint.status}
                  </span>
                </div>
                {hoveredPoint.count > 1 && (
                  <div className="geo-tooltip-row">
                    <span className="geo-tooltip-label">Events</span>
                    <span>{hoveredPoint.count.toLocaleString()}</span>
                  </div>
                )}
                {hoveredPoint.details && (
                  <>
                    {hoveredPoint.details.model && (
                      <div className="geo-tooltip-row">
                        <span className="geo-tooltip-label">Model</span>
                        <span>{hoveredPoint.details.model}</span>
                      </div>
                    )}
                    {hoveredPoint.details.ip && (
                      <div className="geo-tooltip-row">
                        <span className="geo-tooltip-label">IP</span>
                        <span className="mono">{hoveredPoint.details.ip}</span>
                      </div>
                    )}
                    {hoveredPoint.details.device_type && (
                      <div className="geo-tooltip-row">
                        <span className="geo-tooltip-label">Device</span>
                        <span>{hoveredPoint.details.device_type}</span>
                      </div>
                    )}
                    {hoveredPoint.details.mac && (
                      <div className="geo-tooltip-row">
                        <span className="geo-tooltip-label">MAC</span>
                        <span className="mono">{hoveredPoint.details.mac}</span>
                      </div>
                    )}
                  </>
                )}
                <div className="geo-tooltip-hint">Click to view events</div>
              </div>
            )}
          </div>

          {/* Dynamic legend — auto-built from visible sources */}
          <div className="geo-legend">
            {legendSources.map(name => (
              <div key={name} className="geo-legend-item">
                <span className="geo-legend-dot" style={{ background: colorForSource(name) }} />
                <span>{name}</span>
              </div>
            ))}
            <div className="geo-legend-separator" />
            <div className="geo-legend-item">
              <span className="geo-legend-ring" style={{ borderColor: '#3fb950' }} />
              <span>Online</span>
            </div>
            <div className="geo-legend-item">
              <span className="geo-legend-ring" style={{ borderColor: '#f85149' }} />
              <span>Offline</span>
            </div>
            <div className="geo-legend-item">
              <span className="geo-legend-ring geo-legend-pulse" style={{ borderColor: '#d29922' }} />
              <span>Alert</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
