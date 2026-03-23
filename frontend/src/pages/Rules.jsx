import { useState, useEffect } from 'react';
import {
  BookOpen, Shield, Zap, List, Plus, X, Edit3, Trash2, CheckCircle,
  AlertTriangle, Eye, EyeOff, Filter, Settings
} from 'lucide-react';
import { api } from '../api';

const SEVERITY_CLASS = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info',
};

const TYPE_ICONS = {
  threshold: <Zap size={14} />,
  sequence: <List size={14} />,
  valuelist: <Shield size={14} />,
  anomaly: <BookOpen size={14} />,
};

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const RULE_TYPES = ['threshold', 'sequence', 'valuelist'];
const SOURCE_TYPES = ['', 'windows', 'azure', 'm365', 'fortigate', 'syslog'];
const GROUP_BY_OPTIONS = ['src_ip', 'user', 'source_host', 'action', 'category'];
const VALUELIST_FIELDS = ['action', 'src_ip', 'user_name', 'category', 'source_type'];

export default function Rules() {
  const [tab, setTab] = useState('active');
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [success, setSuccess] = useState('');

  async function loadRules() {
    try {
      const data = await api.rules();
      setRules(data.rules || []);
    } catch { setRules([]); }
    setLoading(false);
  }

  useEffect(() => { loadRules(); }, []);

  if (loading) return (
    <div className="loading"><div className="loading-spinner" /><div>Loading rules...</div></div>
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Detection Rules</h1>
          <div className="subtitle">{rules.length} rule{rules.length !== 1 ? 's' : ''} loaded</div>
        </div>
      </div>

      {success && <div className="status-banner success"><CheckCircle size={16} /> {success}</div>}

      <div className="filter-tabs" style={{marginBottom: 20}}>
        <button className={tab === 'active' ? 'active' : ''} onClick={() => setTab('active')}>
          <Eye size={14} /> Active Rules
        </button>
        <button className={tab === 'builder' ? 'active' : ''} onClick={() => setTab('builder')}>
          <Settings size={14} /> Rule Builder
        </button>
      </div>

      {tab === 'active' && (
        <ActiveRules rules={rules} onReload={loadRules} setSuccess={setSuccess} />
      )}
      {tab === 'builder' && (
        <RuleBuilder onCreated={() => { loadRules(); setTab('active'); setSuccess('Rule created successfully'); }} />
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// ACTIVE RULES
// ════════════════════════════════════════════════════════════════

function ActiveRules({ rules, onReload, setSuccess }) {
  const [filter, setFilter] = useState('all');
  const [editRule, setEditRule] = useState(null);
  const [error, setError] = useState('');

  async function handleToggle(rule) {
    if (rule.source === 'builtin') return;
    try {
      await api.updateRule({ ...rule, enabled: !rule.enabled });
      setSuccess(rule.enabled ? `"${rule.name}" disabled` : `"${rule.name}" enabled`);
      onReload();
    } catch (e) { setError(e.message); }
  }

  async function handleDelete(rule) {
    if (rule.source === 'builtin') return;
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    try {
      await api.deleteRule(rule.id);
      setSuccess(`"${rule.name}" deleted`);
      onReload();
    } catch (e) { setError(e.message); }
  }

  const filtered = rules.filter(r => {
    if (filter === 'builtin') return r.source === 'builtin';
    if (filter === 'custom') return r.source === 'custom';
    if (filter === 'enabled') return r.enabled;
    if (filter === 'disabled') return !r.enabled;
    return true;
  });

  const builtinCount = rules.filter(r => r.source === 'builtin').length;
  const customCount = rules.filter(r => r.source === 'custom').length;

  return (
    <div>
      {error && <div className="status-banner error">{error}</div>}

      <div className="filter-row" style={{marginBottom: 16}}>
        <select value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="all">All Rules ({rules.length})</option>
          <option value="builtin">Built-in ({builtinCount})</option>
          <option value="custom">Custom ({customCount})</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
      </div>

      {/* Edit modal */}
      {editRule && (
        <EditRuleModal
          rule={editRule}
          onClose={() => setEditRule(null)}
          onSaved={() => { setEditRule(null); onReload(); setSuccess('Rule updated'); }}
        />
      )}

      <div style={{display: 'grid', gap: 10}}>
        {filtered.map(rule => (
          <div key={rule.id} className="integration-card" style={{padding: 14}}>
            <div style={{display: 'flex', alignItems: 'center', justifyContent: 'space-between'}}>
              <div style={{display: 'flex', alignItems: 'center', gap: 12, flex: 1, minWidth: 0}}>
                <div style={{
                  width: 36, height: 36, borderRadius: 'var(--radius-md)', flexShrink: 0,
                  background: 'var(--accent-subtle)', color: 'var(--accent)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  {TYPE_ICONS[rule.type] || <Shield size={14} />}
                </div>
                <div style={{minWidth: 0}}>
                  <div style={{display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap'}}>
                    <span style={{fontSize: 14, fontWeight: 600, color: 'var(--text-primary)'}}>{rule.name}</span>
                    <span className={`badge ${SEVERITY_CLASS[rule.severity?.toLowerCase()] || 'info'}`}>
                      {rule.severity}
                    </span>
                    <span style={{
                      fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                      padding: '1px 6px', borderRadius: 8,
                      background: 'var(--bg-tertiary)', color: 'var(--text-muted)',
                    }}>
                      {rule.type}
                    </span>
                    <span style={{
                      fontSize: 10, fontWeight: 500, padding: '1px 6px', borderRadius: 8,
                      background: rule.source === 'custom' ? 'var(--accent-subtle)' : 'var(--bg-tertiary)',
                      color: rule.source === 'custom' ? 'var(--accent)' : 'var(--text-muted)',
                    }}>
                      {rule.source === 'custom' ? 'Custom' : 'Built-in'}
                    </span>
                  </div>
                  <div style={{fontSize: 12, color: 'var(--text-muted)', marginTop: 2}}>{rule.description}</div>
                  {rule.filter?.source_type && (
                    <div style={{fontSize: 11, color: 'var(--text-muted)', marginTop: 2}}>
                      <Filter size={10} style={{verticalAlign: 'middle'}} /> Source: {rule.filter.source_type}
                      {rule.filter.action && ` | Action: ${rule.filter.action}`}
                      {rule.filter.category && ` | Category: ${rule.filter.category}`}
                    </div>
                  )}
                </div>
              </div>
              <div style={{display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0}}>
                {rule.source === 'custom' && (
                  <>
                    <button className="btn-icon-sm" title="Edit" onClick={() => setEditRule(rule)}>
                      <Edit3 size={12} />
                    </button>
                    <button className="btn-icon-sm danger" title="Delete" onClick={() => handleDelete(rule)}>
                      <Trash2 size={12} />
                    </button>
                  </>
                )}
                <button
                  className={`btn-icon-sm ${!rule.enabled ? 'danger' : ''}`}
                  title={rule.enabled ? 'Disable' : 'Enable'}
                  onClick={() => handleToggle(rule)}
                  disabled={rule.source === 'builtin'}
                  style={{opacity: rule.source === 'builtin' ? 0.4 : 1}}
                >
                  {rule.enabled ? <Eye size={12} /> : <EyeOff size={12} />}
                </button>
                <span className={`pulse`}
                  style={{width: 8, height: 8, borderRadius: '50%',
                    background: rule.enabled ? 'var(--green)' : 'var(--text-muted)'}} />
              </div>
            </div>
            {rule.tags?.length > 0 && (
              <div style={{display: 'flex', gap: 4, marginTop: 8, marginLeft: 48, flexWrap: 'wrap'}}>
                {rule.tags.map(tag => (
                  <span key={tag} style={{
                    fontSize: 10, padding: '1px 7px', borderRadius: 10,
                    background: 'var(--blue-muted)', color: 'var(--blue)',
                  }}>{tag}</span>
                ))}
              </div>
            )}
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="table-container"><div className="empty">No rules match filter</div></div>
        )}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// EDIT RULE MODAL (for custom rules)
// ════════════════════════════════════════════════════════════════

function EditRuleModal({ rule, onClose, onSaved }) {
  const [name, setName] = useState(rule.name);
  const [description, setDescription] = useState(rule.description || '');
  const [severity, setSeverity] = useState(rule.severity || 'medium');
  const [enabled, setEnabled] = useState(rule.enabled);
  const [error, setError] = useState('');

  async function handleSave() {
    try {
      await api.updateRule({ ...rule, name, description, severity, enabled });
      onSaved();
    } catch (e) { setError(e.message); }
  }

  return (
    <div className="connector-modal" style={{marginBottom: 16}}>
      <div className="connector-modal-header">
        <h3>Edit Rule: {rule.name}</h3>
        <button className="btn-icon" onClick={onClose}><X size={16} /></button>
      </div>
      <div className="connector-form">
        {error && <div className="status-banner error" style={{marginBottom: 12}}>{error}</div>}
        <div className="field">
          <label>Name</label>
          <input type="text" value={name} onChange={e => setName(e.target.value)} />
        </div>
        <div className="field">
          <label>Description</label>
          <input type="text" value={description} onChange={e => setDescription(e.target.value)} />
        </div>
        <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12}}>
          <div className="field">
            <label>Severity</label>
            <select value={severity} onChange={e => setSeverity(e.target.value)}>
              {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
            </select>
          </div>
          <div className="field">
            <label>Status</label>
            <select value={enabled ? 'enabled' : 'disabled'} onChange={e => setEnabled(e.target.value === 'enabled')}>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </div>
        </div>
        <div style={{display: 'flex', gap: 8, marginTop: 12}}>
          <button className="btn-primary" onClick={handleSave}>Save Changes</button>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════
// RULE BUILDER
// ════════════════════════════════════════════════════════════════

function RuleBuilder({ onCreated }) {
  const [step, setStep] = useState(1);
  const [error, setError] = useState('');

  // Step 1: basics
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [ruleType, setRuleType] = useState('threshold');
  const [tags, setTags] = useState('');

  // Step 2: filter
  const [sourceType, setSourceType] = useState('');
  const [category, setCategory] = useState('');
  const [action, setAction] = useState('');
  const [fieldMatch, setFieldMatch] = useState('');
  const [fieldValue, setFieldValue] = useState('');

  // Step 3: condition
  const [threshold, setThreshold] = useState(5);
  const [windowMin, setWindowMin] = useState(5);
  const [groupBy, setGroupBy] = useState('src_ip');

  // Sequence steps
  const [seqSteps, setSeqSteps] = useState([
    { label: 'Step 1', action: '' },
    { label: 'Step 2', action: '' },
  ]);

  // Valuelist
  const [vlField, setVlField] = useState('action');
  const [vlValues, setVlValues] = useState('');

  function buildConfig() {
    if (ruleType === 'threshold') {
      return { threshold, window_seconds: windowMin * 60, group_by: groupBy };
    }
    if (ruleType === 'sequence') {
      return {
        window_seconds: windowMin * 60,
        group_by: groupBy,
        steps: seqSteps.filter(s => s.action).map(s => ({
          label: s.label,
          filter: { action: s.action }
        }))
      };
    }
    if (ruleType === 'valuelist') {
      return {
        field: vlField,
        values: vlValues.split('\n').map(v => v.trim()).filter(Boolean)
      };
    }
    return {};
  }

  async function handleCreate() {
    setError('');
    if (!name) { setError('Rule name is required'); return; }

    const tagList = tags.split(',').map(t => t.trim()).filter(Boolean);
    const config = buildConfig();

    try {
      await api.createRule({
        name, description, severity, type: ruleType,
        source_type: sourceType, category, action,
        field_match: fieldMatch, field_value: fieldValue,
        config, tags: tagList, enabled: true,
      });
      onCreated();
    } catch (e) { setError(e.message); }
  }

  function addSeqStep() {
    setSeqSteps([...seqSteps, { label: `Step ${seqSteps.length + 1}`, action: '' }]);
  }

  function updateSeqStep(idx, key, val) {
    const steps = [...seqSteps];
    steps[idx] = { ...steps[idx], [key]: val };
    setSeqSteps(steps);
  }

  function removeSeqStep(idx) {
    if (seqSteps.length <= 2) return;
    setSeqSteps(seqSteps.filter((_, i) => i !== idx));
  }

  return (
    <div>
      {error && <div className="status-banner error" style={{marginBottom: 16}}>{error}</div>}

      {/* Progress indicator */}
      <div className="rule-builder-progress">
        {[1, 2, 3, 4].map(s => (
          <div key={s} className={`rb-step ${step === s ? 'active' : ''} ${step > s ? 'done' : ''}`}
               onClick={() => s < step && setStep(s)}>
            <span className="rb-step-num">{step > s ? '✓' : s}</span>
            <span className="rb-step-label">
              {s === 1 ? 'Basics' : s === 2 ? 'Filter' : s === 3 ? 'Condition' : 'Review'}
            </span>
          </div>
        ))}
      </div>

      <div className="connector-modal" style={{marginTop: 16}}>
        {/* Step 1: Basics */}
        {step === 1 && (
          <div className="connector-form">
            <h3 style={{marginBottom: 16, color: 'var(--text-primary)'}}>Rule Details</h3>
            <div className="field">
              <label>Rule Name *</label>
              <input type="text" value={name} onChange={e => setName(e.target.value)}
                     placeholder="e.g., Brute Force Detection" autoFocus />
            </div>
            <div className="field">
              <label>Description</label>
              <input type="text" value={description} onChange={e => setDescription(e.target.value)}
                     placeholder="What does this rule detect?" />
            </div>
            <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12}}>
              <div className="field">
                <label>Severity</label>
                <select value={severity} onChange={e => setSeverity(e.target.value)}>
                  {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                </select>
              </div>
              <div className="field">
                <label>Rule Type</label>
                <select value={ruleType} onChange={e => setRuleType(e.target.value)}>
                  {RULE_TYPES.map(t => <option key={t} value={t}>
                    {t === 'threshold' ? 'Threshold (count-based)' :
                     t === 'sequence' ? 'Sequence (ordered events)' :
                     'Value List (known-bad match)'}
                  </option>)}
                </select>
              </div>
            </div>
            <div className="field">
              <label>Tags (comma-separated)</label>
              <input type="text" value={tags} onChange={e => setTags(e.target.value)}
                     placeholder="brute_force, windows, auth" />
            </div>
            <div style={{display: 'flex', justifyContent: 'flex-end', marginTop: 16}}>
              <button className="btn-primary" onClick={() => { if (!name) { setError('Name required'); return; } setError(''); setStep(2); }}>
                Next: Filter &rarr;
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Filter */}
        {step === 2 && (
          <div className="connector-form">
            <h3 style={{marginBottom: 16, color: 'var(--text-primary)'}}>
              <Filter size={16} style={{verticalAlign: 'middle'}} /> Event Filter
            </h3>
            <p style={{fontSize: 12, color: 'var(--text-muted)', marginBottom: 16}}>
              Define which events this rule should evaluate. Leave blank to match all.
            </p>
            <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12}}>
              <div className="field">
                <label>Source Type</label>
                <select value={sourceType} onChange={e => setSourceType(e.target.value)}>
                  <option value="">Any source</option>
                  {SOURCE_TYPES.filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div className="field">
                <label>Category</label>
                <input type="text" value={category} onChange={e => setCategory(e.target.value)}
                       placeholder="e.g., auth, network" />
              </div>
            </div>
            <div className="field">
              <label>Action</label>
              <input type="text" value={action} onChange={e => setAction(e.target.value)}
                     placeholder="e.g., login_failure, account_created" />
            </div>
            <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12}}>
              <div className="field">
                <label>Custom Field Name</label>
                <input type="text" value={fieldMatch} onChange={e => setFieldMatch(e.target.value)}
                       placeholder="e.g., subtype" />
              </div>
              <div className="field">
                <label>Custom Field Value</label>
                <input type="text" value={fieldValue} onChange={e => setFieldValue(e.target.value)}
                       placeholder="e.g., system" />
              </div>
            </div>
            <div style={{display: 'flex', justifyContent: 'space-between', marginTop: 16}}>
              <button className="btn-secondary" onClick={() => setStep(1)}>&larr; Back</button>
              <button className="btn-primary" onClick={() => setStep(3)}>Next: Condition &rarr;</button>
            </div>
          </div>
        )}

        {/* Step 3: Condition */}
        {step === 3 && (
          <div className="connector-form">
            <h3 style={{marginBottom: 16, color: 'var(--text-primary)'}}>
              <Zap size={16} style={{verticalAlign: 'middle'}} /> Detection Condition
            </h3>

            {ruleType === 'threshold' && (
              <>
                <p style={{fontSize: 12, color: 'var(--text-muted)', marginBottom: 16}}>
                  Alert when N matching events occur within a time window, grouped by a field.
                </p>
                <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12}}>
                  <div className="field">
                    <label>Threshold (count)</label>
                    <input type="number" min={1} value={threshold}
                           onChange={e => setThreshold(parseInt(e.target.value) || 1)} />
                  </div>
                  <div className="field">
                    <label>Window (minutes)</label>
                    <input type="number" min={1} value={windowMin}
                           onChange={e => setWindowMin(parseInt(e.target.value) || 1)} />
                  </div>
                  <div className="field">
                    <label>Group By</label>
                    <select value={groupBy} onChange={e => setGroupBy(e.target.value)}>
                      {GROUP_BY_OPTIONS.map(g => <option key={g} value={g}>{g}</option>)}
                    </select>
                  </div>
                </div>
                <div style={{
                  marginTop: 12, padding: 12, borderRadius: 8,
                  background: 'var(--bg-tertiary)', fontSize: 12, color: 'var(--text-muted)'
                }}>
                  Alert when <strong style={{color: 'var(--accent)'}}>{threshold}</strong> matching events
                  from the same <strong style={{color: 'var(--accent)'}}>{groupBy}</strong> occur
                  within <strong style={{color: 'var(--accent)'}}>{windowMin} minute{windowMin > 1 ? 's' : ''}</strong>.
                </div>
              </>
            )}

            {ruleType === 'sequence' && (
              <>
                <p style={{fontSize: 12, color: 'var(--text-muted)', marginBottom: 16}}>
                  Alert when events occur in a specific order within a time window.
                </p>
                <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12}}>
                  <div className="field">
                    <label>Window (minutes)</label>
                    <input type="number" min={1} value={windowMin}
                           onChange={e => setWindowMin(parseInt(e.target.value) || 1)} />
                  </div>
                  <div className="field">
                    <label>Group By</label>
                    <select value={groupBy} onChange={e => setGroupBy(e.target.value)}>
                      {GROUP_BY_OPTIONS.map(g => <option key={g} value={g}>{g}</option>)}
                    </select>
                  </div>
                </div>
                <label style={{fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, display: 'block'}}>
                  Sequence Steps
                </label>
                {seqSteps.map((s, i) => (
                  <div key={i} style={{display: 'grid', gridTemplateColumns: '120px 1fr 32px', gap: 8, marginBottom: 8}}>
                    <input type="text" value={s.label} onChange={e => updateSeqStep(i, 'label', e.target.value)}
                           placeholder="Step label" style={{fontSize: 12}} />
                    <input type="text" value={s.action} onChange={e => updateSeqStep(i, 'action', e.target.value)}
                           placeholder="Action to match (e.g., login_failure)" style={{fontSize: 12}} />
                    <button className="btn-icon-sm danger" onClick={() => removeSeqStep(i)}
                            disabled={seqSteps.length <= 2}><X size={10} /></button>
                  </div>
                ))}
                <button className="btn-secondary" onClick={addSeqStep} style={{fontSize: 12}}>
                  <Plus size={10} /> Add Step
                </button>
              </>
            )}

            {ruleType === 'valuelist' && (
              <>
                <p style={{fontSize: 12, color: 'var(--text-muted)', marginBottom: 16}}>
                  Alert when an event field matches any value in a known-bad list.
                </p>
                <div className="field">
                  <label>Field to Check</label>
                  <select value={vlField} onChange={e => setVlField(e.target.value)}>
                    {VALUELIST_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
                  </select>
                </div>
                <div className="field">
                  <label>Values (one per line)</label>
                  <textarea rows={6} value={vlValues} onChange={e => setVlValues(e.target.value)}
                            placeholder={"malicious_action\nsuspicious_login\ndata_export"}
                            style={{
                              width: '100%', fontFamily: 'var(--mono)', fontSize: 12,
                              background: 'var(--bg-primary)', color: 'var(--text-primary)',
                              border: '1px solid var(--border)', borderRadius: 8, padding: 10, resize: 'vertical',
                            }} />
                </div>
              </>
            )}

            <div style={{display: 'flex', justifyContent: 'space-between', marginTop: 16}}>
              <button className="btn-secondary" onClick={() => setStep(2)}>&larr; Back</button>
              <button className="btn-primary" onClick={() => setStep(4)}>Next: Review &rarr;</button>
            </div>
          </div>
        )}

        {/* Step 4: Review */}
        {step === 4 && (
          <div className="connector-form">
            <h3 style={{marginBottom: 16, color: 'var(--text-primary)'}}>Review & Create</h3>

            <div className="rule-review">
              <div className="review-row"><span className="review-label">Name</span><span>{name}</span></div>
              <div className="review-row"><span className="review-label">Description</span><span>{description || '--'}</span></div>
              <div className="review-row">
                <span className="review-label">Severity</span>
                <span className={`badge ${SEVERITY_CLASS[severity]}`}>{severity}</span>
              </div>
              <div className="review-row"><span className="review-label">Type</span><span>{ruleType}</span></div>
              {sourceType && <div className="review-row"><span className="review-label">Source</span><span>{sourceType}</span></div>}
              {action && <div className="review-row"><span className="review-label">Action</span><span>{action}</span></div>}
              {category && <div className="review-row"><span className="review-label">Category</span><span>{category}</span></div>}
              {ruleType === 'threshold' && (
                <div className="review-row">
                  <span className="review-label">Condition</span>
                  <span>{threshold} events in {windowMin}m grouped by {groupBy}</span>
                </div>
              )}
              {ruleType === 'sequence' && (
                <div className="review-row">
                  <span className="review-label">Sequence</span>
                  <span>{seqSteps.filter(s => s.action).map(s => s.label).join(' → ')} within {windowMin}m</span>
                </div>
              )}
              {ruleType === 'valuelist' && (
                <div className="review-row">
                  <span className="review-label">Value List</span>
                  <span>{vlField}: {vlValues.split('\n').filter(Boolean).length} values</span>
                </div>
              )}
              {tags && (
                <div className="review-row">
                  <span className="review-label">Tags</span>
                  <span>{tags}</span>
                </div>
              )}
            </div>

            <div style={{display: 'flex', justifyContent: 'space-between', marginTop: 16}}>
              <button className="btn-secondary" onClick={() => setStep(3)}>&larr; Back</button>
              <button className="btn-primary" onClick={handleCreate}>
                <Plus size={14} /> Create Rule
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
