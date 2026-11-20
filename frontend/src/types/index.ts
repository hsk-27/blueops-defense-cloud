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
export type IncidentPriority = 'P1_CRITICAL' | 'P2_HIGH' | 'P3_MEDIUM' | 'P4_LOW';
export type IncidentStatus =
  | 'NEW'
  | 'TRIAGED'
  | 'INVESTIGATING'
  | 'CONTAINMENT_PENDING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED'
  | 'FALSE_POSITIVE'
  | 'REOPENED';

export interface Incident {
  id: number;
  incidentNumber: string;
  title: string;
  description?: string;
  severity: IncidentSeverity;
  priority?: IncidentPriority;
  status: IncidentStatus;
  primaryAssetId?: number;
  primaryAssetHostname?: string;
  primaryAssetIp?: string;
  assignedTo?: string;
  createdBy: string;
  resolutionRationale?: string;
  closureNotes?: string;
  createdAt: string;
  updatedAt: string;
  containedAt?: string;
  resolvedAt?: string;
  closedAt?: string;
  closedBy?: string;
  findingCount: number;
  noteCount: number;
}

export interface IncidentEvidence {
  evidenceId: string;
  type: string;
  findingId: string;
  ruleId: string;
  ruleName: string;
  severity: string;
  timestamp: string;
  provider: string;
  host: string;
  sourceIp?: string;
  user?: string;
  process?: string;
  rawPayload?: string;
  normalizedAttributes?: Record<string, any>;
}

export interface RelatedFinding {
  finding: Finding;
  relationType: string;
  relationshipRationale: string;
  confidenceScore: number;
}

export interface TimelineEntry {
  type: 'FINDING' | 'STATUS_CHANGE' | 'NOTE' | 'ACTION' | 'CLOSURE' | 'INCIDENT_CREATED';
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

export type AuthoritativeSource =
  | 'NIST_SP_800_61R2'
  | 'CISA_IR_PLAYBOOK'
  | 'MITRE_ATTACK_MITIGATION'
  | 'MITRE_D3FEND'
  | 'SANS_PICERL'
  | 'RFC_3227';

export type AdvisoryPhase =
  | 'DETECTION_AND_ANALYSIS'
  | 'CONTAINMENT'
  | 'ERADICATION'
  | 'RECOVERY'
  | 'POST_INCIDENT';

export type AdvisoryPriority =
  | 'IMMEDIATE_ACTION'
  | 'HIGH_PRIORITY'
  | 'RECOMMENDED_FOLLOW_UP'
  | 'STRATEGIC_HARDENING';

export interface IncidentRecommendation {
  id: string;
  title: string;
  phase: AdvisoryPhase;
  priority: AdvisoryPriority;
  authoritativeSource: AuthoritativeSource;
  citation: string;
  rationale: string;
  actionableSteps: string[];
  suggestedPlaybookCode?: string;
  suggestedPlaybookName?: string;
  suggestedTarget?: string;
  applicableTechniques: string[];
}


// --- M5 Context, Entity & Correlation Types ---

export type EntityType = 'HOST' | 'USER' | 'IP_ADDRESS' | 'DOMAIN' | 'PROCESS' | 'FILE' | 'HASH';
export type EntityStatus = 'ACTIVE' | 'INACTIVE' | 'SUSPICIOUS' | 'COMPROMISED' | 'BENIGN';
export type EntityRelationType =
  | 'HOST_HAS_USER'
  | 'HOST_HAS_PROCESS'
  | 'PROCESS_CONNECTED_TO'
  | 'USER_AUTHENTICATED_TO'
  | 'FILE_OBSERVED_ON'
  | 'ENTITY_RESOLVED_TO_IP'
  | 'PROCESS_SPAWNED_PROCESS'
  | 'ENTITY_ASSOCIATED_WITH_FINDING';

export interface EntityRecord {
  id: number;
  canonicalId: string;
  type: EntityType;
  displayName: string;
  status: EntityStatus;
  riskScore: number;
  firstSeen: string;
  lastSeen: string;
  attributes?: Record<string, any>;
}

export interface EntityObservation {
  id: number;
  entityId: number;
  observationType: string;
  referenceId: string;
  observedHostname?: string;
  rawReference?: string;
  confidence: number;
  observedAt: string;
}

export interface EntityRelationship {
  id: number;
  sourceCanonicalId: string;
  targetCanonicalId: string;
  relationType: EntityRelationType;
  confidence: number;
  contextReason?: string;
  firstObservedAt: string;
  lastObservedAt: string;
}

export interface CorrelationRecord {
  id: number;
  correlationKey: string;
  ruleId: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  primaryEntityCanonicalId: string;
  findingCount: number;
  entityCount: number;
  correlationWindowSeconds: number;
  windowStart: string;
  windowEnd: string;
  explanation: string;
  incidentId?: number;
  createdAt: string;
}

export interface CorrelationRule {
  ruleId: string;
  name: string;
  description: string;
  scenarioType: string;
  severity: string;
  windowSeconds: number;
  requiredFindingCount: number;
  requiredDetectionIds: string[];
  targetEntityType: string;
  enabled: boolean;
}

// --- M6 Controlled SOAR & Response Governance Types ---

export type ResponseRiskLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
export type ResponseExecutionMode = 'SIMULATION' | 'LIVE';
export type ResponsePolicyOutcome = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'SIMULATION_ONLY' | 'BLOCKED' | 'INVALID';
export type ProposalStatus =
  | 'DRAFT'
  | 'VALIDATING'
  | 'REJECTED'
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'DENIED'
  | 'READY'
  | 'EXECUTING'
  | 'EXECUTION_FAILED'
  | 'EXECUTED'
  | 'VERIFICATION_PENDING'
  | 'VERIFIED'
  | 'VERIFICATION_FAILED'
  | 'CANCELLED'
  | 'EXPIRED';

export type VerificationStatus = 'NOT_STARTED' | 'PENDING' | 'VERIFIED' | 'FAILED' | 'INCONCLUSIVE';

export interface ResponseActionCatalogItem {
  id: number;
  actionCode: string;
  name: string;
  description: string;
  category: string;
  targetType: string;
  riskLevel: ResponseRiskLevel;
  requiresApproval: boolean;
  simulationSupported: boolean;
  rollbackSupported: boolean;
  reversalActionCode?: string;
  timeoutSeconds: number;
  verificationMethod: string;
  parameterSchema?: string;
  isEnabled: boolean;
}

export interface ResponseTargetItem {
  id: number;
  targetId: string;
  targetType: string;
  identifier: string;
  displayName?: string;
  criticality: string;
  environment: string;
  trustStatus: string;
  isProtected: boolean;
}

export interface ResponseVerification {
  id: number;
  verificationUuid: string;
  proposalId: number;
  executionId?: number;
  status: VerificationStatus;
  verificationMethod: string;
  expectedOutcome: string;
  observedOutcome: string;
  evidencePayload?: string;
  verifiedAt: string;
  isSimulation: boolean;
}

export interface ResponseProposal {
  id: number;
  proposalUuid: string;
  incidentId?: number;
  findingId?: string;
  correlationId?: number;
  actionCode: string;
  actionName: string;
  actionType: string;
  targetCanonicalId?: string;
  targetIdentifier: string;
  targetType: string;
  parametersJson?: string;
  proposedBy: string;
  proposedAt: string;
  riskLevel: ResponseRiskLevel;
  executionMode: ResponseExecutionMode;
  policyOutcome: ResponsePolicyOutcome;
  policyReason?: string;
  status: ProposalStatus;
  requiresApproval: boolean;
  approver?: string;
  approvedAt?: string;
  denialReason?: string;
  expiresAt?: string;
  executionId?: number;
  createdAt: string;
  updatedAt: string;
  verification?: ResponseVerification;
}

export interface PolicyEvaluationResult {
  outcome: ResponsePolicyOutcome;
  riskLevel: ResponseRiskLevel;
  requiresApproval: boolean;
  isSeparationOfDutiesRequired: boolean;
  reason: string;
  policyViolations: string[];
  blastRadiusAssessment: string;
}

export interface CreateProposalRequest {
  incidentId?: number;
  findingId?: string;
  correlationId?: number;
  actionCode: string;
  targetIdentifier: string;
  targetCanonicalId?: string;
  executionMode?: ResponseExecutionMode;
  parameters?: Record<string, any>;
}

export interface ApproveProposalRequest {
  reason?: string;
  executeImmediately?: boolean;
}
