const BASE = '/api';

async function fetchJson(path, options = {}) {
  const token = localStorage.getItem('outpost_token');
  const headers = { ...(options.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    localStorage.removeItem('outpost_token');
    if (window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
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
  logout:      () => postJson('/auth/logout', {}),
  me:          () => fetchJson('/auth/me'),

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

  // Integrations (legacy)
  integrations:    () => fetchJson('/integrations'),
  saveIntegrations: (data) => postJson('/integrations', data),

  // Connectors
  connectors:       () => fetchJson('/connectors'),
  connectorTypes:   () => fetchJson('/connectors/types'),
  createConnector:  (data) => postJson('/connectors', data),
  updateConnector:  (data) => putJson('/connectors', data),
  deleteConnector:  (id) => deleteJson('/connectors', { id }),

  // User management
  listUsers:    () => fetchJson('/users'),
  createUser:   (data) => postJson('/users', data),
  updateUser:   (data) => putJson('/users', data),
  deleteUser:   (user_id) => deleteJson('/users', { user_id }),
};
