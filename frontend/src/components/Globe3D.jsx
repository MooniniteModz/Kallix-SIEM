import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Globe from 'react-globe.gl';
import * as THREE from 'three';
import { feature } from 'topojson-client';
import { api } from '../api';
import {
  Layers, Maximize2, Minimize2, X, ExternalLink
} from 'lucide-react';

// ── Color system (matches GeoMap) ──
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

const SEVERITY_BG = {
  critical: '#c93c37', error: '#c93c37', high: '#a85620',
  warning: '#a67a1a', medium: '#a67a1a',
  low: '#2d8a3e', info: '#3d7ec7', informational: '#3d7ec7',
};

// ── Demo data — global coverage ──
const DEMO_POINTS = [
  // Azure / Entra logins (global)
  { lat: 40.7128, lng: -74.0060, label: 'New York, NY',         source: 'Entra', type: 'login', status: 'online', count: 47 },
  { lat: 34.0522, lng: -118.2437, label: 'Los Angeles, CA',     source: 'Entra', type: 'login', status: 'online', count: 31 },
  { lat: 41.8781, lng: -87.6298, label: 'Chicago, IL',          source: 'Entra', type: 'login', status: 'online', count: 22 },
  { lat: 51.5074, lng: -0.1278, label: 'London, UK',            source: 'Entra', type: 'login', status: 'online', count: 14 },
  { lat: 48.8566, lng: 2.3522, label: 'Paris, France',          source: 'Entra', type: 'login', status: 'online', count: 8 },
  { lat: 55.7558, lng: 37.6173, label: 'Moscow, Russia',        source: 'Entra', type: 'login', status: 'alert',  count: 3 },
  { lat: 35.6762, lng: 139.6503, label: 'Tokyo, Japan',         source: 'Entra', type: 'login', status: 'online', count: 6 },
  { lat: 1.3521, lng: 103.8198, label: 'Singapore',             source: 'Entra', type: 'login', status: 'online', count: 4 },
  { lat: -33.8688, lng: 151.2093, label: 'Sydney, Australia',   source: 'Entra', type: 'login', status: 'online', count: 5 },
  { lat: 52.5200, lng: 13.4050, label: 'Berlin, Germany',       source: 'Entra', type: 'login', status: 'online', count: 7 },
  { lat: 39.9042, lng: 116.4074, label: 'Beijing, China',       source: 'Entra', type: 'login', status: 'alert',  count: 2 },
  { lat: -23.5505, lng: -46.6333, label: 'Sao Paulo, Brazil',   source: 'Entra', type: 'login', status: 'online', count: 9 },
  { lat: 28.6139, lng: 77.2090, label: 'New Delhi, India',      source: 'Entra', type: 'login', status: 'online', count: 11 },
  { lat: 25.2048, lng: 55.2708, label: 'Dubai, UAE',            source: 'Entra', type: 'login', status: 'online', count: 3 },
  { lat: 37.5665, lng: 126.9780, label: 'Seoul, South Korea',   source: 'Entra', type: 'login', status: 'online', count: 5 },

  // UniFi network devices (US)
  { lat: 40.7589, lng: -73.9851, label: 'NYC HQ — USW-Pro-48',   source: 'UniFi', type: 'device', status: 'online',  count: 1, details: { device_type: 'switch', model: 'USW-Pro-48-PoE', ip: '10.0.1.1' } },
  { lat: 40.7505, lng: -73.9934, label: 'NYC HQ — U6-LR AP',     source: 'UniFi', type: 'device', status: 'online',  count: 1, details: { device_type: 'ap', model: 'U6-LR', ip: '10.0.1.20' } },
  { lat: 41.8827, lng: -87.6233, label: 'Chicago DC — USW-Agg',   source: 'UniFi', type: 'device', status: 'online',  count: 1, details: { device_type: 'switch', model: 'USW-Aggregation', ip: '10.0.3.1' } },
  { lat: 29.7545, lng: -95.3632, label: 'Houston — U6-Pro AP',    source: 'UniFi', type: 'device', status: 'offline', count: 1, details: { device_type: 'ap', model: 'U6-Pro', ip: '10.0.4.10' } },
  { lat: 47.6205, lng: -122.3493, label: 'Seattle — USW-Pro-24',  source: 'UniFi', type: 'device', status: 'online',  count: 1, details: { device_type: 'switch', model: 'USW-Pro-24-PoE', ip: '10.0.5.1' } },
  { lat: 39.7500, lng: -104.9995, label: 'Denver — U6-Mesh AP',   source: 'UniFi', type: 'device', status: 'alert',   count: 1, details: { device_type: 'ap', model: 'U6-Mesh', ip: '10.0.7.10' } },

  // Meraki devices
  { lat: 37.7749, lng: -122.4194, label: 'SF HQ — MR46',       source: 'Meraki', type: 'device', status: 'online',  count: 1, details: { device_type: 'ap', model: 'MR46', ip: '10.10.1.10' } },
  { lat: 34.0195, lng: -118.4912, label: 'LA Office — MX250',   source: 'Meraki', type: 'device', status: 'online',  count: 1, details: { device_type: 'gateway', model: 'MX250', ip: '10.10.2.1' } },
  { lat: 30.2672, lng: -97.7431, label: 'Austin — MR56',        source: 'Meraki', type: 'device', status: 'offline', count: 1, details: { device_type: 'ap', model: 'MR56', ip: '10.10.3.10' } },

  // FortiGate firewalls
  { lat: 40.7128, lng: -74.0260, label: 'NYC — FG-200F',   source: 'FortiGate', type: 'device', status: 'online', count: 342 },
  { lat: 34.0522, lng: -118.2837, label: 'LA — FG-100F',   source: 'FortiGate', type: 'device', status: 'online', count: 198 },
  { lat: 37.7749, lng: -122.3894, label: 'SF — FG-400F',   source: 'FortiGate', type: 'device', status: 'alert',  count: 56 },

  // CrowdStrike endpoints
  { lat: 42.3601, lng: -71.0589, label: 'Boston — 5 sensors', source: 'CrowdStrike', type: 'endpoint', status: 'online', count: 5 },
  { lat: 38.9072, lng: -77.0369, label: 'DC — 6 sensors',    source: 'CrowdStrike', type: 'endpoint', status: 'online', count: 6 },

  // Syslog
  { lat: 39.0997, lng: -94.5786, label: 'Kansas City DC',  source: 'Syslog', type: 'event', status: 'online', count: 89 },
  { lat: 36.1627, lng: -86.7816, label: 'Nashville DC',    source: 'Syslog', type: 'event', status: 'online', count: 45 },
];

// Arc data — login connections from international origins to US HQ
const DEMO_ARCS = [
  { startLat: 55.7558, startLng: 37.6173, endLat: 40.7128, endLng: -74.0060, source: 'Entra', status: 'alert', label: 'Moscow → NYC' },
  { startLat: 39.9042, startLng: 116.4074, endLat: 34.0522, endLng: -118.2437, source: 'Entra', status: 'alert', label: 'Beijing → LA' },
  { startLat: 51.5074, startLng: -0.1278, endLat: 40.7128, endLng: -74.0060, source: 'Entra', status: 'online', label: 'London → NYC' },
  { startLat: 35.6762, startLng: 139.6503, endLat: 47.6062, endLng: -122.3321, source: 'Entra', status: 'online', label: 'Tokyo → Seattle' },
  { startLat: 48.8566, startLng: 2.3522, endLat: 41.8781, endLng: -87.6298, source: 'Entra', status: 'online', label: 'Paris → Chicago' },
  { startLat: -23.5505, startLng: -46.6333, endLat: 25.7617, endLng: -80.1918, source: 'Entra', status: 'online', label: 'Sao Paulo → Miami' },
  { startLat: 28.6139, startLng: 77.2090, endLat: 37.7749, endLng: -122.4194, source: 'Entra', status: 'online', label: 'Delhi → SF' },
];

// ── Major world cities (label markers) ──
const CITY_LABELS = [
  // North America
  { lat: 40.7128, lng: -74.0060, city: 'New York', size: 0.7 },
  { lat: 34.0522, lng: -118.2437, city: 'Los Angeles', size: 0.6 },
  { lat: 41.8781, lng: -87.6298, city: 'Chicago', size: 0.5 },
  { lat: 29.7604, lng: -95.3698, city: 'Houston', size: 0.45 },
  { lat: 47.6062, lng: -122.3321, city: 'Seattle', size: 0.45 },
  { lat: 37.7749, lng: -122.4194, city: 'San Francisco', size: 0.5 },
  { lat: 25.7617, lng: -80.1918, city: 'Miami', size: 0.45 },
  { lat: 38.9072, lng: -77.0369, city: 'Washington DC', size: 0.55 },
  { lat: 33.4484, lng: -112.0740, city: 'Phoenix', size: 0.4 },
  { lat: 39.7392, lng: -104.9903, city: 'Denver', size: 0.4 },
  { lat: 42.3601, lng: -71.0589, city: 'Boston', size: 0.4 },
  { lat: 30.2672, lng: -97.7431, city: 'Austin', size: 0.35 },
  { lat: 43.6532, lng: -79.3832, city: 'Toronto', size: 0.5 },
  { lat: 19.4326, lng: -99.1332, city: 'Mexico City', size: 0.5 },
  // Europe
  { lat: 51.5074, lng: -0.1278, city: 'London', size: 0.7 },
  { lat: 48.8566, lng: 2.3522, city: 'Paris', size: 0.6 },
  { lat: 52.5200, lng: 13.4050, city: 'Berlin', size: 0.5 },
  { lat: 55.7558, lng: 37.6173, city: 'Moscow', size: 0.6 },
  { lat: 41.9028, lng: 12.4964, city: 'Rome', size: 0.4 },
  { lat: 40.4168, lng: -3.7038, city: 'Madrid', size: 0.4 },
  { lat: 59.3293, lng: 18.0686, city: 'Stockholm', size: 0.35 },
  { lat: 52.3676, lng: 4.9041, city: 'Amsterdam', size: 0.35 },
  // Asia
  { lat: 35.6762, lng: 139.6503, city: 'Tokyo', size: 0.7 },
  { lat: 39.9042, lng: 116.4074, city: 'Beijing', size: 0.6 },
  { lat: 31.2304, lng: 121.4737, city: 'Shanghai', size: 0.55 },
  { lat: 1.3521, lng: 103.8198, city: 'Singapore', size: 0.5 },
  { lat: 22.3193, lng: 114.1694, city: 'Hong Kong', size: 0.5 },
  { lat: 37.5665, lng: 126.9780, city: 'Seoul', size: 0.5 },
  { lat: 28.6139, lng: 77.2090, city: 'New Delhi', size: 0.55 },
  { lat: 19.0760, lng: 72.8777, city: 'Mumbai', size: 0.5 },
  { lat: 25.2048, lng: 55.2708, city: 'Dubai', size: 0.45 },
  { lat: 13.7563, lng: 100.5018, city: 'Bangkok', size: 0.4 },
  // Oceania
  { lat: -33.8688, lng: 151.2093, city: 'Sydney', size: 0.55 },
  { lat: -37.8136, lng: 144.9631, city: 'Melbourne', size: 0.4 },
  // South America
  { lat: -23.5505, lng: -46.6333, city: 'Sao Paulo', size: 0.55 },
  { lat: -34.6037, lng: -58.3816, city: 'Buenos Aires', size: 0.45 },
  { lat: 4.7110, lng: -74.0721, city: 'Bogota', size: 0.35 },
  // Africa
  { lat: -1.2921, lng: 36.8219, city: 'Nairobi', size: 0.35 },
  { lat: 30.0444, lng: 31.2357, city: 'Cairo', size: 0.45 },
  { lat: -33.9249, lng: 18.4241, city: 'Cape Town', size: 0.35 },
  { lat: 6.5244, lng: 3.3792, city: 'Lagos', size: 0.4 },
];

// Auto-rotation speed (degrees per second)
const ROTATION_SPEED = 0.15;

export default function Globe3D() {
  const navigate = useNavigate();
  const globeRef = useRef();
  const containerRef = useRef();
  const [activeFilter, setActiveFilter] = useState('all');
  const [allPoints, setAllPoints] = useState([]);
  const [usingDemo, setUsingDemo] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [globeReady, setGlobeReady] = useState(false);
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const [countries, setCountries] = useState([]);

  // Popup state for click-to-load-alerts
  const [selectedPoint, setSelectedPoint] = useState(null);
  const [popupAlerts, setPopupAlerts] = useState([]);
  const [popupLoading, setPopupLoading] = useState(false);

  // Auto-rotation state
  const rotationRef = useRef({ active: true, angle: -100 });
  const interactionTimer = useRef(null);
  const animFrameRef = useRef(null);
  const savedScrollRef = useRef(0);

  // ── Fix fullscreen exit layout zoom: lock/unlock body scroll ──
  useEffect(() => {
    if (fullscreen) {
      savedScrollRef.current = window.scrollY;
      document.body.style.overflow = 'hidden';
      document.documentElement.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
      document.documentElement.style.overflow = '';
      requestAnimationFrame(() => window.scrollTo(0, savedScrollRef.current));
    }
    return () => {
      document.body.style.overflow = '';
      document.documentElement.style.overflow = '';
    };
  }, [fullscreen]);

  // Fetch world country boundaries + US states (TopoJSON → GeoJSON)
  useEffect(() => {
    Promise.all([
      fetch('https://unpkg.com/world-atlas@2.0.2/countries-110m.json').then(r => r.json()),
      fetch('https://cdn.jsdelivr.net/npm/us-atlas@3/states-10m.json').then(r => r.json()),
    ])
      .then(([worldTopo, usTopo]) => {
        const worldGeo = feature(worldTopo, worldTopo.objects.countries);
        const usGeo = feature(usTopo, usTopo.objects.states);
        const countriesNoUS = worldGeo.features.filter(f => f.id !== '840');
        setCountries([...countriesNoUS, ...usGeo.features]);
      })
      .catch(() => {});
  }, []);

  // Fetch data
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
    }
    load();
    const interval = setInterval(load, 30000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  // Resize observer
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver(entries => {
      for (const entry of entries) {
        setDimensions({
          width: entry.contentRect.width,
          height: entry.contentRect.height,
        });
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [fullscreen]);

  // Auto-rotation animation loop
  useEffect(() => {
    if (!globeReady || !globeRef.current) return;

    const controls = globeRef.current.controls();
    if (controls) {
      controls.autoRotate = false;
      controls.enableDamping = true;
      controls.dampingFactor = 0.1;
    }

    function animate() {
      if (rotationRef.current.active && globeRef.current) {
        const pov = globeRef.current.pointOfView();
        rotationRef.current.angle += ROTATION_SPEED;
        globeRef.current.pointOfView({ lng: rotationRef.current.angle, lat: pov.lat, altitude: pov.altitude }, 0);
      }
      animFrameRef.current = requestAnimationFrame(animate);
    }
    animFrameRef.current = requestAnimationFrame(animate);
    return () => { if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current); };
  }, [globeReady]);

  // Pause rotation on interaction, resume after 3s idle
  const handleInteractionStart = useCallback(() => {
    rotationRef.current.active = false;
    if (interactionTimer.current) clearTimeout(interactionTimer.current);
  }, []);

  const handleInteractionEnd = useCallback(() => {
    if (interactionTimer.current) clearTimeout(interactionTimer.current);
    interactionTimer.current = setTimeout(() => {
      if (globeRef.current) {
        const pov = globeRef.current.pointOfView();
        rotationRef.current.angle = pov.lng;
      }
      rotationRef.current.active = true;
    }, 3000);
  }, []);

  // ── Pause rotation when hovering a data point ──
  const handlePointHover = useCallback((point) => {
    if (point) {
      rotationRef.current.active = false;
      if (interactionTimer.current) clearTimeout(interactionTimer.current);
    } else {
      if (interactionTimer.current) clearTimeout(interactionTimer.current);
      interactionTimer.current = setTimeout(() => {
        if (globeRef.current) {
          const pov = globeRef.current.pointOfView();
          rotationRef.current.angle = pov.lng;
        }
        rotationRef.current.active = true;
      }, 3000);
    }
  }, []);

  // Set initial view once globe is ready
  const handleGlobeReady = useCallback(() => {
    setGlobeReady(true);
    if (globeRef.current) {
      globeRef.current.pointOfView({ lat: 34, lng: -95, altitude: fullscreen ? 2.0 : 1.5 }, 0);
    }
  }, [fullscreen]);

  // Adjust zoom when toggling fullscreen
  useEffect(() => {
    if (!globeReady || !globeRef.current) return;
    const pov = globeRef.current.pointOfView();
    globeRef.current.pointOfView({ lat: pov.lat, lng: pov.lng, altitude: fullscreen ? 2.0 : 1.5 }, 800);
  }, [fullscreen, globeReady]);

  // Filter points
  const points = useMemo(() => {
    if (activeFilter === 'all') return allPoints;
    return allPoints.filter(p => p.source === activeFilter);
  }, [allPoints, activeFilter]);

  // Filter arcs (only show for Entra login connections)
  const arcs = useMemo(() => {
    if (!usingDemo) return [];
    if (activeFilter !== 'all' && activeFilter !== 'Entra') return [];
    return DEMO_ARCS;
  }, [usingDemo, activeFilter]);

  // Discover source filters
  const sourceFilters = useMemo(() => {
    const seen = new Map();
    for (const p of allPoints) {
      seen.set(p.source, (seen.get(p.source) || 0) + 1);
    }
    return [...seen.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name]) => ({ id: name, label: name, color: colorForSource(name) }));
  }, [allPoints]);

  // Stats
  const stats = useMemo(() => {
    const byStatus = { online: 0, offline: 0, alert: 0 };
    let total = 0;
    for (const p of points) {
      if (byStatus[p.status] !== undefined) byStatus[p.status]++;
      total += p.count || 1;
    }
    return { byStatus, totalEvents: total, totalPoints: points.length };
  }, [points]);

  // Point accessors for react-globe.gl
  const pointColor = useCallback(p => colorForSource(p.source), []);
  const pointAlt = useCallback(p => Math.max(0.01, Math.min(0.08, 0.01 + Math.log2(p.count + 1) * 0.008)), []);
  const pointRadius = useCallback(p => Math.max(0.15, Math.min(0.6, 0.15 + Math.log2(p.count + 1) * 0.1)), []);

  // ── Group points by location for richer tooltips ──
  const locationGroups = useMemo(() => {
    const groups = new Map();
    for (const p of allPoints) {
      const key = `${Math.round(p.lat * 10) / 10},${Math.round(p.lng * 10) / 10}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(p);
    }
    return groups;
  }, [allPoints]);

  // ── Richer hover tooltip showing all services/devices at location ──
  const pointLabel = useCallback(p => {
    const key = `${Math.round(p.lat * 10) / 10},${Math.round(p.lng * 10) / 10}`;
    const group = locationGroups.get(key) || [p];

    const bySource = new Map();
    for (const pt of group) {
      if (!bySource.has(pt.source)) bySource.set(pt.source, []);
      bySource.get(pt.source).push(pt);
    }

    let servicesHtml = '';
    for (const [source, pts] of bySource) {
      const sColor = colorForSource(source);
      const devices = pts.map(pt => {
        const name = pt.details?.model || pt.label.split('—').pop()?.trim() || pt.type;
        const stColor = STATUS_COLOR[pt.status] || '#8b949e';
        return `<div style="display:flex;align-items:center;gap:6px;padding:2px 0">
          <span style="width:5px;height:5px;border-radius:50%;background:${stColor};flex-shrink:0"></span>
          <span style="color:#c9d1d9;font-size:11px">${name}</span>
          ${pt.count > 1 ? `<span style="color:#8b949e;font-size:10px;margin-left:auto">${pt.count} events</span>` : ''}
        </div>`;
      }).join('');

      servicesHtml += `
        <div style="margin-top:5px">
          <div style="display:flex;align-items:center;gap:5px;margin-bottom:2px">
            <span style="width:7px;height:7px;border-radius:50%;background:${sColor};flex-shrink:0"></span>
            <span style="color:#e6edf3;font-weight:600;font-size:11px">${source}</span>
            <span style="color:#8b949e;font-size:10px">(${pts.length})</span>
          </div>
          <div style="padding-left:12px">${devices}</div>
        </div>
      `;
    }

    const locationName = p.label.split('—')[0].trim();

    return `
      <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:10px 14px;font-size:12px;color:#e6edf3;min-width:200px;max-width:280px;font-family:-apple-system,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,0.4)">
        <div style="font-weight:700;font-size:13px;margin-bottom:2px">${locationName}</div>
        <div style="color:#8b949e;font-size:11px;margin-bottom:4px;border-bottom:1px solid #21262d;padding-bottom:5px">
          ${group.length} service${group.length !== 1 ? 's' : ''} &middot; ${[...bySource.keys()].length} source${[...bySource.keys()].length !== 1 ? 's' : ''}
        </div>
        ${servicesHtml}
        <div style="margin-top:6px;padding-top:5px;border-top:1px solid #21262d;color:#58a6ff;font-size:10px;text-align:center">
          Click to view alerts
        </div>
      </div>
    `;
  }, [locationGroups]);

  // Arc accessors
  const arcColor = useCallback(a => {
    const c = a.status === 'alert' ? STATUS_COLOR.alert : colorForSource(a.source);
    return [`${c}cc`, `${c}44`];
  }, []);
  const arcLabel = useCallback(a => {
    const sc = STATUS_COLOR[a.status] || '#8b949e';
    return `
      <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:6px 10px;font-size:11px;color:#e6edf3;font-family:-apple-system,sans-serif">
        <span style="color:${sc}">${a.status === 'alert' ? 'Suspicious' : 'Normal'}</span> — ${a.label}
      </div>
    `;
  }, []);

  // ── Click handler — open popup with alerts instead of navigating ──
  const handlePointClick = useCallback(p => {
    setSelectedPoint(p);
    setPopupAlerts([]);
    setPopupLoading(true);
    api.alerts({ source_type: p.source })
      .then(data => {
        const list = Array.isArray(data) ? data : data?.alerts || data?.data || [];
        setPopupAlerts(list.slice(0, 20));
      })
      .catch(() => setPopupAlerts([]))
      .finally(() => setPopupLoading(false));
  }, []);

  const closePopup = useCallback(() => {
    setSelectedPoint(null);
    setPopupAlerts([]);
    setPopupLoading(false);
  }, []);

  // Globe surface material
  const globeMaterial = useMemo(() => {
    return new THREE.MeshPhongMaterial({
      color: new THREE.Color('#0a0f18'),
      emissive: new THREE.Color('#040810'),
      emissiveIntensity: 0.3,
      shininess: 10,
    });
  }, []);


  return (
    <div className={`globe-dashboard ${fullscreen ? 'globe-fullscreen' : ''}`}>
      {/* Filter bar */}
      <div className="globe-filter-bar">
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
        {usingDemo && <span className="geo-demo-badge" style={{ marginLeft: 'auto' }}>Demo Data</span>}
      </div>

      {/* Status + expand */}
      <div className="globe-status-row">
        <div className="globe-stats">
          <span className="globe-stat"><span className="geo-stat-dot" style={{ background: '#3fb950' }} />{stats.byStatus.online} Online</span>
          <span className="globe-stat"><span className="geo-stat-dot" style={{ background: '#f85149' }} />{stats.byStatus.offline} Offline</span>
          <span className="globe-stat"><span className="geo-stat-dot" style={{ background: '#d29922' }} />{stats.byStatus.alert} Alerts</span>
          <span className="globe-stat-sep" />
          <span className="globe-stat">{stats.totalPoints} locations</span>
          <span className="globe-stat">{stats.totalEvents.toLocaleString()} events</span>
        </div>
        <button
          className="geo-expand-btn"
          onClick={() => setFullscreen(f => !f)}
          title={fullscreen ? 'Collapse' : 'Expand'}
          style={{ position: 'relative', top: 'auto', left: 'auto' }}
        >
          {fullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
        </button>
      </div>

      {/* Globe container */}
      <div
        className="globe-container"
        ref={containerRef}
        onMouseDown={handleInteractionStart}
        onMouseUp={handleInteractionEnd}
        onTouchStart={handleInteractionStart}
        onTouchEnd={handleInteractionEnd}
        onWheel={() => { handleInteractionStart(); handleInteractionEnd(); }}
      >
        {dimensions.width > 0 && (
          <Globe
            ref={globeRef}
            width={dimensions.width}
            height={dimensions.height}
            onGlobeReady={handleGlobeReady}
            backgroundColor="rgba(0,0,0,0)"
            globeImageUrl=""
            showGlobe={true}
            showAtmosphere={true}
            atmosphereColor="#1a6baa"
            atmosphereAltitude={0.18}

            globeMaterial={globeMaterial}

            polygonsData={countries}
            polygonCapColor={() => 'rgba(10, 20, 40, 0.6)'}
            polygonSideColor={() => 'rgba(20, 40, 80, 0.2)'}
            polygonStrokeColor={() => '#1a3a5c'}
            polygonAltitude={0.005}
            polygonLabel={() => null}

            pointsData={points}
            pointLat="lat"
            pointLng="lng"
            pointColor={pointColor}
            pointAltitude={pointAlt}
            pointRadius={pointRadius}
            pointLabel={pointLabel}
            onPointClick={handlePointClick}
            onPointHover={handlePointHover}
            pointsMerge={false}

            arcsData={arcs}
            arcStartLat="startLat"
            arcStartLng="startLng"
            arcEndLat="endLat"
            arcEndLng="endLng"
            arcColor={arcColor}
            arcDashLength={0.4}
            arcDashGap={0.2}
            arcDashAnimateTime={1500}
            arcStroke={0.5}
            arcLabel={arcLabel}

            labelsData={CITY_LABELS}
            labelLat="lat"
            labelLng="lng"
            labelText="city"
            labelSize={d => d.size * 1.2}
            labelDotRadius={d => d.size * 0.35}
            labelColor={() => 'rgba(180, 200, 220, 0.7)'}
            labelResolution={2}
            labelAltitude={0.007}
            labelDotOrientation={() => 'bottom'}
          />
        )}
      </div>

      {/* Legend */}
      <div className="globe-legend">
        {sourceFilters.map(f => (
          <div key={f.id} className="geo-legend-item">
            <span className="geo-legend-dot" style={{ background: f.color }} />
            <span>{f.label}</span>
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

      {/* ── Alert popup overlay (click-to-load) ── */}
      {selectedPoint && (
        <div className="globe-popup-overlay" onClick={closePopup}>
          <div className="globe-popup" onClick={e => e.stopPropagation()}>
            <div className="globe-popup-header">
              <div>
                <div className="globe-popup-title">
                  <span className="globe-popup-dot" style={{ background: colorForSource(selectedPoint.source) }} />
                  {selectedPoint.label}
                </div>
                <div className="globe-popup-subtitle">
                  {selectedPoint.source} &middot; {selectedPoint.type} &middot;{' '}
                  <span style={{ color: STATUS_COLOR[selectedPoint.status] || '#8b949e' }}>{selectedPoint.status}</span>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
                <button className="globe-popup-link" onClick={() => { closePopup(); navigate(`/events?source_type=${selectedPoint.source}`); }}>
                  <ExternalLink size={12} /> View All
                </button>
                <button className="globe-popup-close" onClick={closePopup}>
                  <X size={14} />
                </button>
              </div>
            </div>

            <div className="globe-popup-body">
              {popupLoading ? (
                <div className="globe-popup-loading">
                  <div className="loading-spinner" style={{ width: 18, height: 18 }} /> Loading alerts...
                </div>
              ) : popupAlerts.length === 0 ? (
                <div className="globe-popup-empty">No recent alerts for {selectedPoint.source}</div>
              ) : (
                <div className="globe-popup-alerts">
                  {popupAlerts.map((alert, i) => (
                    <div key={alert.id || i} className="globe-popup-alert">
                      <div className="globe-popup-alert-sev" style={{
                        background: SEVERITY_BG[alert.severity?.toLowerCase()] || '#3d7ec7'
                      }} />
                      <div className="globe-popup-alert-content">
                        <div className="globe-popup-alert-name">{alert.rule_name || alert.name || 'Alert'}</div>
                        <div className="globe-popup-alert-meta">
                          {alert.severity || 'info'} &middot;{' '}
                          {alert.timestamp ? new Date(typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : alert.timestamp).toLocaleString() : ''}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
