import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Plus, Save, ArrowLeft, ChevronUp, ChevronDown, X, Settings
} from 'lucide-react';
import WidgetRenderer from '../widgets/WidgetRenderer';
import { WIDGET_TYPES, DATA_SOURCE_LABELS, SIZE_OPTIONS, DEFAULT_DASHBOARD } from '../widgets/WidgetRegistry';
import { api } from '../api';

function loadDashboard() {
  try {
    const stored = localStorage.getItem('outpost_dashboard');
    if (stored) return JSON.parse(stored);
  } catch {}
  return DEFAULT_DASHBOARD;
}

function saveDashboard(dashboard) {
  localStorage.setItem('outpost_dashboard', JSON.stringify(dashboard));
}

let widgetIdCounter = Date.now();
function newWidgetId() { return `w_${widgetIdCounter++}`; }

export default function DashboardBuilder() {
  const navigate = useNavigate();
  const [dashboard, setDashboard] = useState(loadDashboard);
  const [widgetData, setWidgetData] = useState({});
  const [showAddModal, setShowAddModal] = useState(false);
  const [editWidget, setEditWidget] = useState(null);

  // Add widget form state
  const [addType, setAddType] = useState('');
  const [addTitle, setAddTitle] = useState('');
  const [addDataSource, setAddDataSource] = useState('');
  const [addSize, setAddSize] = useState('half');
  const [addParams, setAddParams] = useState({});

  // Fetch data for all widgets
  useEffect(() => {
    async function fetchAll() {
      const data = {};
      const needed = new Set(dashboard.widgets.map(w => w.dataSource));
      const fetchers = {
        health: () => api.health(),
        timeline: () => api.timeline(24),
        sources: () => api.sources(),
        severity: () => api.severity(),
        categories: () => api.categories(),
        topIps: () => api.topIps(10),
        topUsers: () => api.topUsers(10),
        topActions: () => api.topActions(10),
      };
      await Promise.all([...needed].map(async ds => {
        try { data[ds] = await fetchers[ds]?.(); } catch {}
      }));
      setWidgetData(data);
    }
    fetchAll();
    const id = setInterval(fetchAll, 15000);
    return () => clearInterval(id);
  }, [dashboard.widgets.length]);

  function handleSave() {
    saveDashboard(dashboard);
    navigate('/');
  }

  function handleReset() {
    setDashboard(DEFAULT_DASHBOARD);
    saveDashboard(DEFAULT_DASHBOARD);
  }

  function moveWidget(idx, dir) {
    const widgets = [...dashboard.widgets];
    const newIdx = idx + dir;
    if (newIdx < 0 || newIdx >= widgets.length) return;
    [widgets[idx], widgets[newIdx]] = [widgets[newIdx], widgets[idx]];
    widgets.forEach((w, i) => w.order = i);
    setDashboard({ ...dashboard, widgets });
  }

  function removeWidget(idx) {
    const widgets = dashboard.widgets.filter((_, i) => i !== idx);
    widgets.forEach((w, i) => w.order = i);
    setDashboard({ ...dashboard, widgets });
  }

  function openAdd() {
    setAddType(''); setAddTitle(''); setAddDataSource(''); setAddSize('half'); setAddParams({});
    setEditWidget(null);
    setShowAddModal(true);
  }

  function openEdit(widget, idx) {
    setAddType(widget.type);
    setAddTitle(widget.title);
    setAddDataSource(widget.dataSource);
    setAddSize(widget.size);
    setAddParams(widget.params || {});
    setEditWidget(idx);
    setShowAddModal(true);
  }

  function selectType(type) {
    setAddType(type);
    setAddTitle(WIDGET_TYPES[type]?.name || type);
    const ds = WIDGET_TYPES[type]?.dataSources;
    setAddDataSource(ds?.[0] || '');
    // Set default params
    const params = {};
    WIDGET_TYPES[type]?.fields?.forEach(f => { params[f.key] = f.default ?? ''; });
    setAddParams(params);
  }

  function confirmAdd() {
    if (!addType || !addTitle) return;
    const widget = {
      id: editWidget !== null ? dashboard.widgets[editWidget].id : newWidgetId(),
      type: addType, title: addTitle, dataSource: addDataSource,
      params: addParams, size: addSize,
      order: editWidget !== null ? editWidget : dashboard.widgets.length,
    };
    let widgets;
    if (editWidget !== null) {
      widgets = [...dashboard.widgets];
      widgets[editWidget] = widget;
    } else {
      widgets = [...dashboard.widgets, widget];
    }
    widgets.forEach((w, i) => w.order = i);
    setDashboard({ ...dashboard, widgets });
    setShowAddModal(false);
  }

  const sorted = [...dashboard.widgets].sort((a, b) => a.order - b.order);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Customize Dashboard</h1>
          <div className="subtitle">Add, remove, and reorder widgets</div>
        </div>
        <div style={{display: 'flex', gap: 8}}>
          <button className="btn-secondary" onClick={() => navigate('/')}><ArrowLeft size={14} /> Back</button>
          <button className="btn-secondary" onClick={handleReset}>Reset Default</button>
          <button className="btn-primary" onClick={handleSave}><Save size={14} /> Save & View</button>
        </div>
      </div>

      <div style={{marginBottom: 16}}>
        <button className="btn-secondary" onClick={openAdd}><Plus size={14} /> Add Widget</button>
      </div>

      {/* Add/Edit modal */}
      {showAddModal && (
        <div className="connector-modal" style={{marginBottom: 16}}>
          <div className="connector-modal-header">
            <h3>{editWidget !== null ? 'Edit Widget' : 'Add Widget'}</h3>
            <button className="btn-icon" onClick={() => setShowAddModal(false)}><X size={16} /></button>
          </div>

          {!addType ? (
            <div className="connector-type-grid">
              {Object.entries(WIDGET_TYPES).map(([type, meta]) => (
                <button key={type} className="connector-type-card" onClick={() => selectType(type)}>
                  <span>{meta.name}</span>
                </button>
              ))}
            </div>
          ) : (
            <div className="connector-form">
              <div className="field">
                <label>Title</label>
                <input type="text" value={addTitle} onChange={e => setAddTitle(e.target.value)} />
              </div>
              <div className="field">
                <label>Data Source</label>
                <select value={addDataSource} onChange={e => setAddDataSource(e.target.value)}>
                  {WIDGET_TYPES[addType]?.dataSources?.map(ds => (
                    <option key={ds} value={ds}>{DATA_SOURCE_LABELS[ds] || ds}</option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label>Size</label>
                <select value={addSize} onChange={e => setAddSize(e.target.value)}>
                  {SIZE_OPTIONS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                </select>
              </div>
              {WIDGET_TYPES[addType]?.fields?.map(f => (
                <div className="field" key={f.key}>
                  <label>{f.label}</label>
                  {f.type === 'select' ? (
                    <select value={addParams[f.key] || ''} onChange={e => setAddParams({...addParams, [f.key]: e.target.value})}>
                      {f.options.map(o => <option key={o} value={o}>{o}</option>)}
                    </select>
                  ) : (
                    <input type={f.type || 'text'} value={addParams[f.key] ?? ''}
                           onChange={e => setAddParams({...addParams, [f.key]: f.type === 'number' ? parseInt(e.target.value) || 0 : e.target.value})} />
                  )}
                </div>
              ))}
              <div style={{display: 'flex', gap: 8, marginTop: 12}}>
                <button className="btn-primary" onClick={confirmAdd}>
                  {editWidget !== null ? 'Update' : 'Add'} Widget
                </button>
                {editWidget === null && <button className="btn-secondary" onClick={() => setAddType('')}>Back</button>}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Widget grid */}
      <div className="widget-grid">
        {sorted.map((widget, idx) => {
          const sizeClass = `widget-${widget.size || 'half'}`;
          return (
            <div key={widget.id} className={`chart-panel widget-card ${sizeClass}`}>
              <div className="widget-header">
                <h3 style={{margin: 0, fontSize: 13}}>{widget.title}</h3>
                <div className="widget-actions">
                  <button className="btn-icon-sm" onClick={() => moveWidget(idx, -1)} disabled={idx === 0}><ChevronUp size={12} /></button>
                  <button className="btn-icon-sm" onClick={() => moveWidget(idx, 1)} disabled={idx === sorted.length - 1}><ChevronDown size={12} /></button>
                  <button className="btn-icon-sm" onClick={() => openEdit(widget, idx)}><Settings size={12} /></button>
                  <button className="btn-icon-sm danger" onClick={() => removeWidget(idx)}><X size={12} /></button>
                </div>
              </div>
              <WidgetRenderer type={widget.type} data={widgetData[widget.dataSource]} config={widget} />
            </div>
          );
        })}
      </div>

      {sorted.length === 0 && (
        <div className="table-container">
          <div className="empty">
            <p>Dashboard is empty. Click "Add Widget" to get started.</p>
          </div>
        </div>
      )}
    </div>
  );
}
