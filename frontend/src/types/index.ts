export type Role = 'ROLE_ADMIN' | 'ROLE_ANALYST' | 'ROLE_VIEWER';

export interface User {
  id: number;
  username: string;
  email: string;
  fullName: string;
  role: Role;
  enabled: boolean;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresInMs: number;
  username: string;
  email: string;
  role: string;
  fullName: string;
}

export type AssetStatus = 'HEALTHY' | 'SUSPICIOUS' | 'COMPROMISED' | 'ISOLATED' | 'OFFLINE';

export interface Asset {
  id: number;
  persistentId: string;
  hostname: string;
  ipAddress: string;
  osName: string;
  osVersion?: string;
  environment: string;
  status: AssetStatus;
  criticality: string;
  lastTelemetryAt?: string;
  createdAt: string;
  updatedAt: string;
}

export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatus =
  | 'NEW'
  | 'TRIAGED'
  | 'INVESTIGATING'
  | 'CONTAINMENT_PENDING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'
  | 'REOPENED';

export interface Incident {
  id: number;
  incidentNumber: string;
  title: string;
  description?: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  primaryAssetId?: number;
  primaryAssetHostname?: string;
  primaryAssetIp?: string;
  assignedTo?: string;
  createdBy: string;
  resolutionRationale?: string;
  createdAt: string;
  updatedAt: string;
  containedAt?: string;
  resolvedAt?: string;
  findingCount: number;
  noteCount: number;
}

export interface TimelineEntry {
  type: 'FINDING' | 'STATUS_CHANGE' | 'NOTE' | 'ACTION';
  timestamp: string;
  title: string;
  description: string;
  actor: string;
  severity: string;
}

export interface DetectionRule {
  id: number;
  ruleCode: string;
  name: string;
  description: string;
  logSource: string;
  severity: string;
  mitreTactic: string;
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  status: 'ACTIVE' | 'DISABLED' | 'TESTING';
  queryDsl: string;
  sigmaYaml?: string;
  falsePositives?: string;
  version: number;
}

export interface Finding {
  findingId: string;
  ruleId: string;
  ruleName: string;
  ruleSeverity: string;
  mitreTactic: string;
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  assetId: string;
  assetName: string;
  timestamp: string;
  status: string;
  relatedDocId?: string;
  details?: Record<string, any>;
}

export interface IocIndicator {
  id: number;
  indicatorValue: string;
  indicatorType: 'IP' | 'DOMAIN' | 'URL' | 'MD5' | 'SHA256';
  source: string;
  confidence: number;
  severity: string;
  description?: string;
  status: string;
  firstSeenAt: string;
  lastSeenAt: string;
  expiresAt?: string;
  tags?: string;
}

export interface IocMatch {
  id: number;
  iocId?: number;
  iocValue?: string;
  iocType?: string;
  matchedValue: string;
  assetId?: number;
  assetHostname?: string;
  eventTimestamp: string;
  opensearchDocId?: string;
  matchedField: string;
  incidentId?: number;
  createdAt: string;
}

export interface ResponsePlaybook {
  id: number;
  playbookCode: string;
  name: string;
  description: string;
  actionType: string;
  requiresApproval: boolean;
  targetType: string;
  rollbackSupported: boolean;
}

export interface ResponseAction {
  id: number;
  actionUuid: string;
  playbookCode: string;
  incidentId?: number;
  targetIdentifier: string;
  targetAssetId?: number;
  requestedBy: string;
  approvalStatus: 'PENDING' | 'APPROVED' | 'REJECTED' | 'AUTO_APPROVED';
  approvedBy?: string;
  approvedAt?: string;
  executionStatus: 'NOT_STARTED' | 'IN_PROGRESS' | 'SUCCEEDED' | 'FAILED' | 'ROLLED_BACK' | 'CANCELLED';
  isSimulation: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ResponseExecution {
  id: number;
  actionId: number;
  actionUuid: string;
  executedAt: string;
  executionDurationMs: number;
  success: boolean;
  statusCode: number;
  responsePayload?: string;
  errorMessage?: string;
  verificationPassed: boolean;
}

export interface AuditLog {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  targetEntity: string;
  targetId?: string;
  sourceIp?: string;
  details?: string;
}

export interface SocOverviewMetrics {
  totalIncidents: number;
  activeIncidents: number;
  criticalIncidents: number;
  highIncidents: number;
  mediumIncidents: number;
  lowIncidents: number;
  totalAssets: number;
  assetsWithAlerts: number;
  totalDetectionRules: number;
  activeDetectionRules: number;
  meanTimeToDetectSeconds: number;
  meanTimeToRespondSeconds: number;
  subsystemHealth: Record<string, string>;
  recentIncidents: Array<{
    id: number;
    incidentNumber: string;
    title: string;
    severity: string;
    status: string;
    createdAt: string;
  }>;
  detectionTacticDistribution: Array<{
    tactic: string;
    count: number;
  }>;
}
