export const WIDGET_TYPES = {
  stat_card: {
    name: 'Stat Counter',
    icon: 'Hash',
    dataSources: ['health'],
    fields: [
      { key: 'field', label: 'Metric', type: 'select',
        options: ['events_stored_today', 'total_events_inserted', 'buffer_usage', 'buffer_drops', 'uptime_ms'] },
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
    { id: 'w3', type: 'stat_card', title: 'Buffer Usage', dataSource: 'health', params: { field: 'buffer_usage' }, size: 'quarter', order: 2 },
    { id: 'w4', type: 'stat_card', title: 'Uptime', dataSource: 'health', params: { field: 'uptime_ms' }, size: 'quarter', order: 3 },
    { id: 'w5', type: 'area_chart', title: 'Event Timeline (24h)', dataSource: 'timeline', params: { hours: 24 }, size: 'full', order: 4 },
    { id: 'w6', type: 'pie_chart', title: 'Events by Severity', dataSource: 'severity', params: {}, size: 'half', order: 5 },
    { id: 'w7', type: 'bar_chart', title: 'Events by Source', dataSource: 'sources', params: {}, size: 'half', order: 6 },
    { id: 'w8', type: 'top_list', title: 'Top Source IPs', dataSource: 'topIps', params: { limit: 8 }, size: 'third', order: 7 },
    { id: 'w9', type: 'top_list', title: 'Top Users', dataSource: 'topUsers', params: { limit: 8 }, size: 'third', order: 8 },
    { id: 'w10', type: 'top_list', title: 'Top Actions', dataSource: 'topActions', params: { limit: 8 }, size: 'third', order: 9 },
  ],
};
