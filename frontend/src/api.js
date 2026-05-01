const BASE = '/api';

// All requests include credentials so the browser sends the HttpOnly session
// cookie automatically. The server also accepts Bearer tokens for API/script
// clients that set an Authorization header directly.
async function fetchJson(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    credentials: 'include',
    headers: { ...(options.headers || {}) },
  });

  if (res.status === 401) {
    // Session expired or cookie cleared — let the app handle redirect
    throw new Error('Session expired');
  }

  if (!res.ok) {
    let msg = `API error: ${res.status}`;
    try { const body = await res.json(); if (body.error) msg = body.error; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

export async function postJson(path, body) {
  return fetchJson(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function putJson(path, body) {
  return fetchJson(path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function deleteJson(path, body) {
  return fetchJson(path, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export const api = {
  // Auth
  login: async (username, password) => {
    const res = await fetch(`${BASE}/auth/login`, {
      method: 'POST',
      credentials: 'include',   // ensures the Set-Cookie response header is accepted
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      let msg = `API error: ${res.status}`;
      try { const b = await res.json(); if (b.error) msg = b.error; } catch {}
      throw new Error(msg);
    }
    return res.json();
  },
  logout:         () => postJson('/auth/logout', {}),
  me:             () => fetchJson('/auth/me'),

  mfaChallenge: async (mfa_token, code, backup_code) => {
    const res = await fetch(`${BASE}/auth/mfa/challenge`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_token, ...(backup_code ? { backup_code } : { code }) }),
    });
    if (!res.ok) {
      let msg = `API error: ${res.status}`;
      try { const b = await res.json(); if (b.error) msg = b.error; } catch {}
      throw new Error(msg);
    }
    return res.json();
  },
  mfaStatus:      () => fetchJson('/auth/mfa/status'),
  mfaSetup:       () => fetchJson('/auth/mfa/setup'),
  mfaEnable:      (code) => postJson('/auth/mfa/enable', { code }),
  mfaDisable:     (password) => postJson('/auth/mfa/disable', { password }),
  forgotPassword: async (email) => {
    const res = await fetch(`${BASE}/auth/forgot-password`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) {
      let msg = `API error: ${res.status}`;
      try { const b = await res.json(); if (b.error) msg = b.error; } catch {}
      throw new Error(msg);
    }
    return res.json();
  },
  resetPassword: async (token, new_password) => {
    const res = await fetch(`${BASE}/auth/reset-password`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, new_password }),
    });
    if (!res.ok) {
      let msg = `API error: ${res.status}`;
      try { const b = await res.json(); if (b.error) msg = b.error; } catch {}
      throw new Error(msg);
    }
    return res.json();
  },
  setPassword: async (change_token, new_password) => {
    const res = await fetch(`${BASE}/auth/set-password`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ change_token, new_password }),
    });
    if (!res.ok) {
      let msg = `API error: ${res.status}`;
      try { const b = await res.json(); if (b.error) msg = b.error; } catch {}
      throw new Error(msg);
    }
    return res.json();
  },

  // Health & Stats
  health:      () => fetchJson('/health'),
  stats:       () => fetchJson('/stats'),
  sources:     () => fetchJson('/stats/sources'),
  severity:    () => fetchJson('/stats/severity'),
  categories:  () => fetchJson('/stats/categories'),
  topIps:      (limit = 10) => fetchJson(`/stats/top-ips?limit=${limit}`),
  topUsers:    (limit = 10) => fetchJson(`/stats/top-users?limit=${limit}`),
  topActions:  (limit = 10) => fetchJson(`/stats/top-actions?limit=${limit}`),
  timeline:    (hours = 24) => fetchJson(`/stats/timeline?hours=${hours}`),

  // Events
  events: (params = {}) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') q.set(k, v);
    }
    return fetchJson(`/events?${q.toString()}`);
  },

  // Alerts
  alerts:           (params = {}) => {
    const q = new URLSearchParams(params);
    return fetchJson(`/alerts?${q.toString()}`);
  },
  acknowledgeAlert: (alert_id) => postJson('/alerts/acknowledge', { alert_id }),
  closeAlert:       (alert_id) => postJson('/alerts/close', { alert_id }),

  // Rules
  rules:       () => fetchJson('/rules'),
  createRule:  (data) => postJson('/rules', data),
  updateRule:  (data) => putJson('/rules', data),
  deleteRule:  (id) => deleteJson('/rules', { id }),

  // Reports
  reportSummary: () => fetchJson('/reports/summary'),

  // Geo
  geoPoints: (source = '', severity = '') => {
    const params = new URLSearchParams();
    if (source) params.set('source', source);
    if (severity) params.set('severity', severity);
    const qs = params.toString();
    return fetchJson(`/geo/points${qs ? `?${qs}` : ''}`);
  },

  // Integrations (legacy)
  integrations:     () => fetchJson('/integrations'),
  saveIntegrations: (data) => postJson('/integrations', data),

  // Connectors
  connectors:      () => fetchJson('/connectors'),
  connectorTypes:  () => fetchJson('/connectors/types'),
  createConnector: (data) => postJson('/connectors', data),
  updateConnector: (data) => putJson('/connectors', data),
  deleteConnector: (id) => deleteJson('/connectors', { id }),
  testConnector:   (settings) => postJson('/connectors/test', { settings }),

  // User management
  listUsers:      () => fetchJson('/users'),
  createUser:     (data) => postJson('/users', data),
  updateUser:     (data) => putJson('/users', data),
  deleteUser:     (user_id) => deleteJson('/users', { user_id }),
  forceLogoff:    (user_id) => postJson('/users/force-logoff',   { user_id }),
  forceMfaReset:  (user_id) => postJson('/users/force-mfa-reset', { user_id }),
  sendAdminReset: (user_id) => postJson('/users/send-reset',      { user_id }),
};
