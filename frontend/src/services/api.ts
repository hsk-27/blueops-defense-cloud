import {
  Incident,
  IncidentSeverity,
  IncidentPriority,
  IncidentStatus,
  IncidentEvidence,
  RelatedFinding,
  TimelineEntry,
  Asset,
  DetectionRule,
  Finding,
  IocIndicator,
  ResponsePlaybook,
  ResponseAction,
  ResponseExecution,
  AuditLog,
  SocOverviewMetrics,
  IncidentRecommendation,
  IocMatch
} from '../types';

const BASE_URL = '/api/v1';

export class ApiError extends Error {
  status: number;
  details?: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

function getAuthHeaders(extraHeaders?: HeadersInit): Record<string, string> {
  const token = localStorage.getItem('blueops_token');
  const base: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {})
  };
  if (extraHeaders && !Array.isArray(extraHeaders) && !(extraHeaders instanceof Headers)) {
    return { ...base, ...(extraHeaders as Record<string, string>) };
  }
  return base;
}

function isApiResponseEnvelope(
  payload: unknown
): payload is { success: boolean; message?: string; data?: unknown; timestamp?: string } {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return false;
  }
  const obj = payload as Record<string, unknown>;
  return typeof obj.success === 'boolean' && 'message' in obj && 'timestamp' in obj;
}

async function parseBodySafely(res: Response): Promise<{ parsed: unknown; rawText: string }> {
  const rawText = await res.text();
  if (!rawText || rawText.trim().length === 0) {
    return { parsed: undefined, rawText: '' };
  }
  try {
    return { parsed: JSON.parse(rawText), rawText };
  } catch {
    return { parsed: rawText, rawText };
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers: getAuthHeaders(options.headers)
  });

  if (res.status === 401) {
    localStorage.removeItem('blueops_token');
    localStorage.removeItem('blueops_refresh_token');
    localStorage.removeItem('blueops_user');
  }

  const { parsed, rawText } = await parseBodySafely(res);

  if (!res.ok) {
    let errorMessage = `Request failed with status ${res.status}`;
    if (typeof parsed === 'object' && parsed !== null) {
      const errObj = parsed as Record<string, unknown>;
      if (typeof errObj.message === 'string' && errObj.message.trim().length > 0) {
        errorMessage = errObj.message;
      } else if (typeof errObj.error === 'string' && errObj.error.trim().length > 0) {
        errorMessage = errObj.error;
      }
    } else if (typeof rawText === 'string' && rawText.trim().length > 0) {
      errorMessage = rawText.trim();
    }
    throw new ApiError(errorMessage, res.status, parsed);
  }

  if (res.status === 204 || parsed === undefined) {
    return undefined as T;
  }

  if (isApiResponseEnvelope(parsed)) {
    if (!parsed.success) {
      throw new ApiError(parsed.message || 'Operation failed', res.status, parsed);
    }
    return parsed.data as T;
  }

  return parsed as T;
}

export const api = {
  // Auth
  login: (credentials: { username: string; password: string }) =>
    request<any>('/auth/login', { method: 'POST', body: JSON.stringify(credentials) }),
  getMe: () => request<any>('/auth/me'),

  // SOC Overview & Metrics
  getSocOverview: () => request<SocOverviewMetrics>('/reports/overview'),
  getAttackCoverage: () => request<any>('/reports/attack-coverage'),

  // Incidents
  getIncidents: (params?: { status?: string; severity?: string; priority?: string; assignedTo?: string; search?: string; page?: number; size?: number }) => {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    if (params?.severity) q.append('severity', params.severity);
    if (params?.priority) q.append('priority', params.priority);
    if (params?.assignedTo) q.append('assignedTo', params.assignedTo);
    if (params?.search) q.append('search', params.search);
    if (params?.page !== undefined) q.append('page', params.page.toString());
    if (params?.size !== undefined) q.append('size', params.size.toString());
    return request<{ content: Incident[]; totalElements: number; totalPages: number }>(`/incidents?${q.toString()}`);
  },
  getIncidentById: (id: number) => request<Incident>(`/incidents/${id}`),
  createIncident: (payload: { title: string; description?: string; severity: IncidentSeverity; priority?: IncidentPriority; primaryAssetId?: number; sourceFindingId?: string; findingIds?: string[] }) =>
    request<Incident>('/incidents', { method: 'POST', body: JSON.stringify(payload) }),
  getTimeline: (id: number) => request<TimelineEntry[]>(`/incidents/${id}/timeline`),
  getIncidentFindings: (id: number) => request<any[]>(`/incidents/${id}/findings`),
  getIncidentEvidence: (id: number) => request<IncidentEvidence[]>(`/incidents/${id}/evidence`),
  attachFinding: (id: number, findingId: string) =>
    request<any>(`/incidents/${id}/findings?findingId=${encodeURIComponent(findingId)}`, { method: 'POST' }),
  detachFinding: (id: number, findingId: string) =>
    request<void>(`/incidents/${id}/findings/${encodeURIComponent(findingId)}`, { method: 'DELETE' }),
  addNote: (id: number, noteText: string) =>
    request<void>(`/incidents/${id}/notes`, { method: 'POST', body: JSON.stringify({ noteText }) }),
  assignIncident: (id: number, assignedTo: string) =>
    request<Incident>(`/incidents/${id}/assign`, { method: 'PUT', body: JSON.stringify({ assignedTo }) }),
  updateIncidentStatus: (id: number, status: IncidentStatus, reason?: string, resolutionRationale?: string, closureNotes?: string) =>
    request<Incident>(`/incidents/${id}/status`, { method: 'PUT', body: JSON.stringify({ status, reason, resolutionRationale, closureNotes }) }),
  reopenIncident: (id: number, reason?: string) =>
    request<Incident>(`/incidents/${id}/reopen?reason=${encodeURIComponent(reason || '')}`, { method: 'POST' }),

  // Assets
  getAssets: () => request<Asset[]>('/assets'),
  getAssetById: (id: number) => request<Asset>(`/assets/${id}`),
  getAssetHistory: (id: number) => request<any[]>(`/assets/${id}/history`),

  // Detections & Findings
  getDetections: () => request<DetectionRule[]>('/detections'),
  getDetectionById: (id: number) => request<DetectionRule>(`/detections/${id}`),
  updateDetectionStatus: (id: number, status: string) =>
    request<DetectionRule>(`/detections/${id}/status?status=${status}`, { method: 'PUT' }),
  getFindings: () => request<Finding[]>('/detections/findings'),
  getFindingEvidence: (findingId: string) => request<any>(`/detections/findings/${encodeURIComponent(findingId)}/evidence`),
  getRelatedFindings: (findingId: string) => request<RelatedFinding[]>(`/detections/findings/${encodeURIComponent(findingId)}/related`),
  reloadSigmaRules: () =>
    request<{ reloadedCount: number; status: string; message: string }>('/detections/reload', { method: 'POST' }),
  getSigmaCatalog: () => request<any[]>('/detections/sigma-catalog'),

  // Threat Intel
  getIocs: () => request<IocIndicator[]>('/threat-intel/iocs'),
  createIoc: (ioc: Partial<IocIndicator>) => request<IocIndicator>('/threat-intel/iocs', { method: 'POST', body: JSON.stringify(ioc) }),
  updateIoc: (id: number, ioc: Partial<IocIndicator>) => request<IocIndicator>(`/threat-intel/iocs/${id}`, { method: 'PUT', body: JSON.stringify(ioc) }),
  deleteIoc: (id: number) => request<void>(`/threat-intel/iocs/${id}`, { method: 'DELETE' }),
  importIocsCsv: (csvContent: string) =>
    request<any>('/threat-intel/import', { method: 'POST', body: csvContent, headers: { 'Content-Type': 'text/plain' } }),
  getIocMatches: () => request<IocMatch[]>('/threat-intel/matches'),

  // Response Orchestration
  getPlaybooks: () => request<ResponsePlaybook[]>('/response/playbooks'),
  getActions: () => request<ResponseAction[]>('/response/actions'),
  requestAction: (payload: { playbookCode: string; targetIdentifier: string; incidentId?: number; targetAssetId?: number; simulation?: boolean }) =>
    request<ResponseAction>('/response/actions', { method: 'POST', body: JSON.stringify(payload) }),
  approveAction: (id: number) => request<ResponseAction>(`/response/actions/${id}/approve`, { method: 'POST' }),
  rejectAction: (id: number, reason?: string) => request<ResponseAction>(`/response/actions/${id}/reject?reason=${encodeURIComponent(reason || '')}`, { method: 'POST' }),
  rollbackAction: (id: number) => request<ResponseAction>(`/response/actions/${id}/rollback`, { method: 'POST' }),
  getExecutions: () => request<ResponseExecution[]>('/response/executions'),

  // Audit Logs
  getAuditLogs: (page = 0, size = 25) => request<{ content: AuditLog[]; totalElements: number }>(`/audit/logs?page=${page}&size=${size}`),

  // Telemetry & Live Stream
  getRecentTelemetry: (limit = 50) => request<any[]>(`/telemetry/events?limit=${limit}`),
  getDeadLetterQueue: (limit = 50) => request<any[]>(`/telemetry/dlq?limit=${limit}`),
  getTelemetryStats: () => request<any>('/telemetry/stats'),
  ingestTelemetry: (events: any) => request<any>('/telemetry/ingest', { method: 'POST', body: JSON.stringify(events) }),
  simulateAttack: (scenario: string) => request<any>('/telemetry/simulate-attack', { method: 'POST', body: JSON.stringify({ scenario }) }),

  // Authoritative Advisory & Guidance
  getIncidentRecommendations: (incidentId: number) =>
    request<IncidentRecommendation[]>(`/advisory/incidents/${incidentId}/recommendations`),
  analyzeAdvisory: (payload: any) =>
    request<IncidentRecommendation[]>('/advisory/analyze', { method: 'POST', body: JSON.stringify(payload) }),

  // M5 Context, Entity & Correlation
  getEntities: (type?: string, search?: string) => {
    const params = new URLSearchParams();
    if (type) params.append('type', type);
    if (search) params.append('search', search);
    const qs = params.toString();
    return request<any>(`/entities${qs ? `?${qs}` : ''}`);
  },
  getEntityById: (id: number) => request<any>(`/entities/${id}`),
  getEntityObservations: (id: number) => request<any[]>(`/entities/${id}/observations`),
  getEntityRelationships: (id: number) => request<any[]>(`/entities/${id}/relationships`),
  getEntityContext: (id: number) => request<any>(`/entities/${id}/context`),
  getCorrelations: () => request<any[]>('/correlations'),
  getCorrelationRules: () => request<any[]>('/correlations/rules'),
  promoteCorrelation: (id: number) => request<any>(`/correlations/${id}/promote`, { method: 'POST' }),

  // M6 Controlled SOAR & Policy Governance
  getResponseCatalog: () => request<any[]>('/response/soar/catalog'),
  getResponseTargets: () => request<any[]>('/response/soar/targets'),
  previewResponsePolicy: (payload: any) =>
    request<any>('/response/soar/policy-preview', { method: 'POST', body: JSON.stringify(payload) }),
  createResponseProposal: (payload: any) =>
    request<any>('/response/soar/proposals', { method: 'POST', body: JSON.stringify(payload) }),
  getResponseProposals: (status?: string, page = 0, size = 20) => {
    const params = new URLSearchParams({ page: String(page), size: String(size) });
    if (status) params.append('status', status);
    return request<any>(`/response/soar/proposals?${params.toString()}`);
  },
  getResponseProposalById: (id: number) => request<any>(`/response/soar/proposals/${id}`),
  getIncidentResponseProposals: (incidentId: number) =>
    request<any[]>(`/response/soar/incidents/${incidentId}/proposals`),
  approveResponseProposal: (id: number, payload?: any) =>
    request<any>(`/response/soar/proposals/${id}/approve`, { method: 'POST', body: JSON.stringify(payload || {}) }),
  denyResponseProposal: (id: number, reason: string) =>
    request<any>(`/response/soar/proposals/${id}/deny`, { method: 'POST', body: JSON.stringify({ reason }) }),
  cancelResponseProposal: (id: number, reason: string) =>
    request<any>(`/response/soar/proposals/${id}/cancel`, { method: 'POST', body: JSON.stringify({ reason }) }),
  executeResponseProposal: (id: number) =>
    request<any>(`/response/soar/proposals/${id}/execute`, { method: 'POST' }),
  getProposalVerification: (id: number) =>
    request<any>(`/response/soar/proposals/${id}/verification`),

  // M7 Operational Hardening & Health Telemetry
  getSystemHealth: () => request<{ status: string; database: string; rulesEngine: string; rulesCount: number; storageFallback: string; timestamp: string }>('/system/health'),
  getSystemDiagnostics: () => request<any>('/system/diagnostics'),
};
