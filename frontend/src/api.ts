const API_BASE = '/api/v1';

export function getAuthToken(): string | null {
  return localStorage.getItem('access_token');
}

export function setAuthToken(token: string) {
  localStorage.setItem('access_token', token);
}

export function removeAuthToken() {
  localStorage.removeItem('access_token');
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> || {}),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let errorDetail = 'Request failed';
    try {
      const errorJson = await res.json();
      errorDetail = errorJson.detail || errorDetail;
    } catch {
      // fallback
    }
    throw new Error(errorDetail);
  }

  return res.json();
}

export const api = {
  // Auth
  login: (email: string, password: string) =>
    request<{ access_token: string; role: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),
  getMe: () => request<{ id: string; email: string; role: string; is_active: boolean }>('/auth/me'),

  // Metrics
  getMetricsSummary: () => request<any>('/metrics/summary'),
  getAnalytics: () => request<any>('/metrics/analytics'),

  // Alerts
  listAlerts: (status?: string, minScore?: number) => {
    let url = '/alerts?limit=50';
    if (status) url += `&status=${status}`;
    if (minScore !== undefined) url += `&min_score=${minScore}`;
    return request<{ data: any[]; total: number }>(url);
  },
  getAlertDetail: (id: string) => request<any>(`/alerts/${id}`),
  triageAlert: (id: string, status: string, comments?: string) =>
    request<any>(`/alerts/${id}/triage`, {
      method: 'PATCH',
      body: JSON.stringify({ status, comments }),
    }),

  // Cases
  listCases: (severity?: string, status?: string, search?: string) => {
    let url = '/cases?limit=50';
    if (severity) url += `&severity=${severity}`;
    if (status) url += `&status=${status}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    return request<{ data: any[]; total: number }>(url);
  },
  createCase: (data: { title: string; description?: string; severity: string; tags?: string }) =>
    request<any>('/cases', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  getCaseDetail: (id: string) => request<any>(`/cases/${id}`),
  updateCase: (id: string, data: { status?: string; severity?: string }) =>
    request<any>(`/cases/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  addCaseNote: (caseId: string, content: string) =>
    request<any>(`/cases/${caseId}/notes`, {
      method: 'POST',
      body: JSON.stringify({ content }),
    }),
  addCaseEvidence: (caseId: string, evidence_type: string, reference_id: string, description: string) =>
    request<any>(`/cases/${caseId}/evidence`, {
      method: 'POST',
      body: JSON.stringify({ evidence_type, reference_id, description }),
    }),

  // Ingestion
  ingestEmailAsync: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return request<{ task_id: string; status: string }>('/ingest/email/async', {
      method: 'POST',
      body: formData,
    });
  },

  // Threat Intel
  enrichSingleIOC: (value: string) =>
    request<any>(`/threat-intel/ioc/${encodeURIComponent(value)}`),
  enrichBatchIOCs: (iocs: string[]) =>
    request<any>('/threat-intel/enrich', {
      method: 'POST',
      body: JSON.stringify({ iocs }),
    }),
  getProviderHealth: () => request<any[]>('/threat-intel/providers'),
  getCacheStatus: () => request<any>('/threat-intel/cache'),

  // Tasks
  listTasks: () => request<{ data: any[]; total: number }>('/tasks?limit=50'),

  // Admin
  listUsers: () => request<any[]>('/admin/users'),
  createUser: (data: { email: string; password: string; role: string }) =>
    request<any>('/admin/users', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  getAuditLogs: () => request<any[]>('/admin/audit-logs?limit=50'),

  // Settings
  getSettings: () => request<any>('/settings'),
  updateSettings: (data: { confidence_threshold?: number; threat_intel_ttl?: number }) =>
    request<any>('/settings', {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  // Reports
  getCaseReportText: (caseId: string) =>
    request<string>(`/reports/case/${caseId}?format=text`),
};
