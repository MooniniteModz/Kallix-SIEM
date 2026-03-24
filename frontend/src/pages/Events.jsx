import { useState, useEffect, useCallback, Fragment } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Search, ChevronDown, ChevronRight, Filter, Save, X } from 'lucide-react';
import { api } from '../api';

const SEVERITY_CLASS = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info',
  informational: 'info', warning: 'medium', error: 'high', emergency: 'critical',
  debug: 'info', unknown: 'info',
};

const SOURCE_CLASS = {
  azure: 'azure', m365: 'm365', fortigate: 'fortigate',
  windows: 'windows', unifi: 'unifi', syslog: 'syslog', unknown: 'unknown',
};

function formatTs(ms) {
  if (!ms) return '';
  const d = new Date(ms);
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
         d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function prettyRaw(raw) {
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}

const PAGE_SIZE = 50;

export default function Events() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  // Initialize filters from URL params
  const [query, setQuery] = useState(searchParams.get('q') || '');
  const [searchTerm, setSearchTerm] = useState(searchParams.get('q') || '');
  const [filters, setFilters] = useState({
    source_type: searchParams.get('source_type') || '',
    severity: searchParams.get('severity') || '',
    category: searchParams.get('category') || '',
    src_ip: searchParams.get('src_ip') || '',
    user_name: searchParams.get('user_name') || '',
    action: searchParams.get('action') || '',
  });
  const [startMs, setStartMs] = useState(searchParams.get('start') || '');
  const [endMs, setEndMs] = useState(searchParams.get('end') || '');

  const [events, setEvents] = useState([]);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [showFilters, setShowFilters] = useState(
    Object.values(filters).some(v => v) || startMs || endMs
  );

  // Options for filter dropdowns
  const [sourceOptions, setSourceOptions] = useState([]);
  const [severityOptions, setSeverityOptions] = useState([]);
  const [categoryOptions, setCategoryOptions] = useState([]);

  // Saved searches
  const [savedSearches, setSavedSearches] = useState(() => {
    try { return JSON.parse(localStorage.getItem('outpost_saved_searches') || '[]'); }
    catch { return []; }
  });
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [saveName, setSaveName] = useState('');

  // Load filter options
  useEffect(() => {
    Promise.all([api.sources(), api.severity(), api.categories()])
      .then(([src, sev, cat]) => {
        setSourceOptions(src.map(([name]) => name));
        setSeverityOptions(sev.map(([name]) => name));
        setCategoryOptions(cat.map(([name]) => name));
      })
      .catch(() => {});
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { limit: PAGE_SIZE, offset };
      if (searchTerm) params.q = searchTerm;
      if (startMs) params.start = startMs;
      if (endMs) params.end = endMs;
      // Add active filters
      for (const [k, v] of Object.entries(filters)) {
        if (v) params[k] = v;
      }
      const data = await api.events(params);
      setEvents(data.events || []);
      setTotal(data.total || data.count || 0);
    } catch {
      setEvents([]);
    }
    setLoading(false);
  }, [searchTerm, offset, filters, startMs, endMs]);

  useEffect(() => { load(); }, [load]);

  // Sync filters to URL
  useEffect(() => {
    const params = {};
    if (searchTerm) params.q = searchTerm;
    for (const [k, v] of Object.entries(filters)) {
      if (v) params[k] = v;
    }
    if (startMs) params.start = startMs;
    if (endMs) params.end = endMs;
    setSearchParams(params, { replace: true });
  }, [searchTerm, filters, startMs, endMs]);

  function handleSearch(e) {
    e.preventDefault();
    setSearchTerm(query);
    setOffset(0);
  }

  function updateFilter(key, value) {
    setFilters(prev => ({ ...prev, [key]: value }));
    setOffset(0);
  }

  function clearFilters() {
    setFilters({ source_type: '', severity: '', category: '', src_ip: '', user_name: '', action: '' });
    setStartMs('');
    setEndMs('');
    setQuery('');
    setSearchTerm('');
    setOffset(0);
  }

  function saveSearch() {
    if (!saveName.trim()) return;
    const search = { name: saveName, filters: { ...filters }, query: searchTerm, startMs, endMs };
    const updated = [...savedSearches, search];
    setSavedSearches(updated);
    localStorage.setItem('outpost_saved_searches', JSON.stringify(updated));
    setShowSaveDialog(false);
    setSaveName('');
  }

  function loadSearch(search) {
    setFilters(search.filters || {});
    setQuery(search.query || '');
    setSearchTerm(search.query || '');
    setStartMs(search.startMs || '');
    setEndMs(search.endMs || '');
    setOffset(0);
    setShowFilters(true);
  }

  function deleteSearch(idx) {
    const updated = savedSearches.filter((_, i) => i !== idx);
    setSavedSearches(updated);
    localStorage.setItem('outpost_saved_searches', JSON.stringify(updated));
  }

  const hasActiveFilters = Object.values(filters).some(v => v) || startMs || endMs || searchTerm;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Events</h1>
          <div className="subtitle">Browse and search security events across all sources</div>
        </div>
      </div>

      <div className="table-container">
        <form className="table-toolbar" onSubmit={handleSearch}>
          <Search size={14} style={{color: 'var(--text-muted)', flexShrink: 0}} />
          <input
            type="text"
            placeholder="Search events (full-text across all fields)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button type="submit" className="btn-search">Search</button>
          <button type="button" className={`btn-search ${showFilters ? 'active' : ''}`}
                  onClick={() => setShowFilters(!showFilters)}>
            <Filter size={12} /> Filters
          </button>
          {hasActiveFilters && (
            <button type="button" className="btn-search" onClick={clearFilters}>
              <X size={12} /> Clear
            </button>
          )}
        </form>

        {/* Filter row */}
        {showFilters && (
          <div className="filter-row">
            <select value={filters.source_type} onChange={e => updateFilter('source_type', e.target.value)}>
              <option value="">All Sources</option>
              {sourceOptions.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select value={filters.severity} onChange={e => updateFilter('severity', e.target.value)}>
              <option value="">All Severities</option>
              {severityOptions.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select value={filters.category} onChange={e => updateFilter('category', e.target.value)}>
              <option value="">All Categories</option>
              {categoryOptions.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <input
              type="text" placeholder="Filter by IP..."
              value={filters.src_ip} onChange={e => updateFilter('src_ip', e.target.value)}
              style={{width: 140}}
            />
            <input
              type="text" placeholder="Filter by user..."
              value={filters.user_name} onChange={e => updateFilter('user_name', e.target.value)}
              style={{width: 140}}
            />
            <div className="filter-actions">
              <button type="button" className="btn-search" onClick={() => setShowSaveDialog(true)}>
                <Save size={12} /> Save
              </button>
              {savedSearches.length > 0 && (
                <select onChange={e => { if (e.target.value !== '') loadSearch(savedSearches[e.target.value]); e.target.value = ''; }}
                        defaultValue="">
                  <option value="" disabled>Load saved...</option>
                  {savedSearches.map((s, i) => (
                    <option key={i} value={i}>{s.name}</option>
                  ))}
                </select>
              )}
            </div>
          </div>
        )}

        {/* Save search dialog */}
        {showSaveDialog && (
          <div className="filter-row" style={{background: 'var(--bg-primary)'}}>
            <input type="text" placeholder="Search name..." value={saveName}
                   onChange={e => setSaveName(e.target.value)} autoFocus style={{flex: 1}} />
            <button type="button" className="btn-primary" onClick={saveSearch}
                    style={{padding: '4px 12px', fontSize: 12}}>Save</button>
            <button type="button" className="btn-search" onClick={() => setShowSaveDialog(false)}>Cancel</button>
          </div>
        )}

        {loading ? (
          <div className="loading"><div className="loading-spinner" /><div>Loading events...</div></div>
        ) : events.length === 0 ? (
          <div className="empty">No events found{searchTerm ? ` matching "${searchTerm}"` : ''}</div>
        ) : (
          <>
            <div className="events-summary-bar">
              <div className="events-summary-stat">
                <span className="events-summary-value">{total.toLocaleString()}</span>
                <span className="events-summary-label">Total Events</span>
              </div>
              {(() => {
                const sevCounts = {};
                events.forEach(e => {
                  const s = (e.severity || 'info').toLowerCase();
                  sevCounts[s] = (sevCounts[s] || 0) + 1;
                });
                return Object.entries(sevCounts)
                  .sort((a, b) => b[1] - a[1])
                  .map(([sev, count]) => (
                    <div key={sev} className="events-summary-stat clickable" onClick={() => updateFilter('severity', sev)}>
                      <span className={`badge ${SEVERITY_CLASS[sev] || 'info'}`} style={{fontSize: 11}}>{count}</span>
                      <span className="events-summary-label">{sev}</span>
                    </div>
                  ));
              })()}
              {(() => {
                const srcCounts = {};
                events.forEach(e => {
                  const s = e.source_type || 'unknown';
                  srcCounts[s] = (srcCounts[s] || 0) + 1;
                });
                return Object.entries(srcCounts)
                  .sort((a, b) => b[1] - a[1])
                  .map(([src, count]) => (
                    <div key={src} className="events-summary-stat clickable" onClick={() => updateFilter('source_type', src)}>
                      <span className={`source-badge ${SOURCE_CLASS[src?.toLowerCase()] || 'unknown'}`} style={{fontSize: 11}}>{count}</span>
                      <span className="events-summary-label">{src}</span>
                    </div>
                  ));
              })()}
            </div>

            <table>
              <thead>
                <tr>
                  <th style={{width: 28}}></th>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Description</th>
                  <th>Src IP</th>
                  <th>User</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <Fragment key={e.event_id}>
                    <tr className="clickable" onClick={() => setExpanded(expanded === e.event_id ? null : e.event_id)}>
                      <td style={{padding: '8px 4px 8px 12px', color: 'var(--text-muted)'}}>
                        {expanded === e.event_id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                      <td className="time-cell">{formatTs(e.timestamp)}</td>
                      <td>
                        <span className={`source-badge ${SOURCE_CLASS[e.source_type?.toLowerCase()] || 'unknown'}`}>
                          {e.source_type}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${SEVERITY_CLASS[e.severity?.toLowerCase()] || 'info'}`}>
                          {e.severity}
                        </span>
                      </td>
                      <td style={{maxWidth: 320}}>
                        <div className="event-desc-cell">
                          <span className="event-action">{e.action || e.category}</span>
                          {e.resource && !e.resource.startsWith('{') && (
                            <span className="event-resource">{e.resource.length > 60 ? e.resource.slice(0, 60) + '...' : e.resource}</span>
                          )}
                        </div>
                      </td>
                      <td className="mono">
                        {e.src_ip && (
                          <span className="investigate-link" onClick={(ev) => {
                            ev.stopPropagation();
                            navigate(`/events?src_ip=${e.src_ip}`);
                          }}>{e.src_ip}</span>
                        )}
                      </td>
                      <td style={{maxWidth: 180}}>
                        {e.user_name && (
                          <span className="investigate-link" onClick={(ev) => {
                            ev.stopPropagation();
                            navigate(`/events?user_name=${e.user_name}`);
                          }}>{e.user_name}</span>
                        )}
                      </td>
                    </tr>
                    {expanded === e.event_id && (
                      <tr>
                        <td colSpan={7} style={{padding: 0}}>
                          <div className="event-detail">
                            <div className="event-detail-grid">
                              <div className="detail-item"><span className="detail-label">Event ID</span><span className="detail-value mono">{e.event_id}</span></div>
                              <div className="detail-item"><span className="detail-label">Timestamp</span><span className="detail-value">{formatTs(e.timestamp)}</span></div>
                              <div className="detail-item"><span className="detail-label">Source</span><span className="detail-value">{e.source_type}</span></div>
                              <div className="detail-item"><span className="detail-label">Severity</span><span className="detail-value">{e.severity}</span></div>
                              <div className="detail-item"><span className="detail-label">Category</span><span className="detail-value">{e.category || '—'}</span></div>
                              <div className="detail-item"><span className="detail-label">Action</span><span className="detail-value">{e.action || '—'}</span></div>
                              <div className="detail-item"><span className="detail-label">Outcome</span><span className="detail-value">{e.outcome || '—'}</span></div>
                              <div className="detail-item"><span className="detail-label">Source IP</span>
                                <span className="detail-value">{e.src_ip ?
                                  <span className="investigate-link" onClick={() => navigate(`/events?src_ip=${e.src_ip}`)}>{e.src_ip}</span>
                                  : '—'}</span>
                              </div>
                              <div className="detail-item"><span className="detail-label">Dest IP</span><span className="detail-value mono">{e.dst_ip || '—'}</span></div>
                              <div className="detail-item"><span className="detail-label">User</span>
                                <span className="detail-value">{e.user_name ?
                                  <span className="investigate-link" onClick={() => navigate(`/events?user_name=${e.user_name}`)}>{e.user_name}</span>
                                  : '—'}</span>
                              </div>
                              <div className="detail-item"><span className="detail-label">Source Host</span><span className="detail-value">{e.source_host || '—'}</span></div>
                              {e.resource && !e.resource.startsWith('{') && (
                                <div className="detail-item"><span className="detail-label">Resource</span><span className="detail-value">{e.resource}</span></div>
                              )}
                            </div>
                            {e.metadata && Object.keys(e.metadata).length > 0 && (
                              <details className="raw-section">
                                <summary>Metadata</summary>
                                <pre className="expanded-row">{JSON.stringify(e.metadata, null, 2)}</pre>
                              </details>
                            )}
                            {e.resource && e.resource.startsWith('{') && (
                              <details className="raw-section">
                                <summary>Resource Data</summary>
                                <pre className="expanded-row">{prettyRaw(e.resource)}</pre>
                              </details>
                            )}
                            <details className="raw-section">
                              <summary>Raw Event Data</summary>
                              <pre className="expanded-row">{prettyRaw(e.raw)}</pre>
                            </details>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>

            <div className="pagination">
              <span className="page-info">
                Showing {offset + 1}&ndash;{offset + events.length} of {total.toLocaleString()}
                {hasActiveFilters && <> (filtered)</>}
              </span>
              <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous</button>
              <button disabled={events.length < PAGE_SIZE} onClick={() => setOffset(offset + PAGE_SIZE)}>Next</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
