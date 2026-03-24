export const WIDGET_TYPES = {
  stat_card: {
    name: 'Stat Counter',
    icon: 'Hash',
    dataSources: ['health'],
    fields: [
      { key: 'field', label: 'Metric', type: 'select',
        options: ['events_stored_today', 'total_events_inserted', 'buffer_usage', 'buffer_drops', 'uptime_ms', 'active_rules', 'alerts_fired'] },
    ],
  },
  area_chart: {
    name: 'Area Chart',
    icon: 'TrendingUp',
    dataSources: ['timeline'],
    fields: [
      { key: 'hours', label: 'Hours', type: 'number', default: 24 },
    ],
  },
  bar_chart: {
    name: 'Bar Chart',
    icon: 'BarChart3',
    dataSources: ['sources', 'severity', 'categories'],
    fields: [],
  },
  pie_chart: {
    name: 'Pie Chart',
    icon: 'PieChart',
    dataSources: ['severity', 'sources', 'categories'],
    fields: [],
  },
  top_list: {
    name: 'Top-N List',
    icon: 'List',
    dataSources: ['topIps', 'topUsers', 'topActions'],
    fields: [
      { key: 'limit', label: 'Max items', type: 'number', default: 8 },
    ],
  },
  geo_map: {
    name: '3D Globe',
    icon: 'Globe',
    dataSources: ['_self'],
    fields: [],
    selfFetch: true,
  },
};

export const DATA_SOURCE_LABELS = {
  health: 'System Health',
  timeline: 'Event Timeline',
  sources: 'Events by Source',
  severity: 'Events by Severity',
  categories: 'Events by Category',
  topIps: 'Top Source IPs',
  topUsers: 'Top Users',
  topActions: 'Top Actions',
  _self: 'Built-in (self-managed)',
};

export const SIZE_OPTIONS = [
  { value: 'full', label: 'Full Width', cols: 12 },
  { value: 'half', label: 'Half', cols: 6 },
  { value: 'third', label: 'Third', cols: 4 },
  { value: 'quarter', label: 'Quarter', cols: 3 },
];

export const DEFAULT_DASHBOARD = {
  id: 'default',
  name: 'Security Overview',
  widgets: [
    { id: 'w1', type: 'stat_card', title: 'Events Today', dataSource: 'health', params: { field: 'events_stored_today' }, size: 'quarter', order: 0 },
    { id: 'w2', type: 'stat_card', title: 'Total Ingested', dataSource: 'health', params: { field: 'total_events_inserted' }, size: 'quarter', order: 1 },
    { id: 'w3', type: 'stat_card', title: 'Alerts Fired', dataSource: 'health', params: { field: 'alerts_fired' }, size: 'quarter', order: 2 },
    { id: 'w4', type: 'stat_card', title: 'Active Rules', dataSource: 'health', params: { field: 'active_rules' }, size: 'quarter', order: 3 },
    { id: 'w5', type: 'geo_map', title: '3D Globe', dataSource: '_self', params: {}, size: 'full', height: 520, order: 4 },
    { id: 'w6', type: 'area_chart', title: 'Event Timeline (24h)', dataSource: 'timeline', params: { hours: 24 }, size: 'full', order: 5 },
    { id: 'w7', type: 'pie_chart', title: 'Events by Severity', dataSource: 'severity', params: {}, size: 'half', order: 6 },
    { id: 'w8', type: 'bar_chart', title: 'Events by Source', dataSource: 'sources', params: {}, size: 'half', order: 7 },
    { id: 'w9', type: 'top_list', title: 'Top Source IPs', dataSource: 'topIps', params: { limit: 8 }, size: 'third', order: 8 },
    { id: 'w10', type: 'top_list', title: 'Top Users', dataSource: 'topUsers', params: { limit: 8 }, size: 'third', order: 9 },
    { id: 'w11', type: 'top_list', title: 'Top Actions', dataSource: 'topActions', params: { limit: 8 }, size: 'third', order: 10 },
  ],
};
