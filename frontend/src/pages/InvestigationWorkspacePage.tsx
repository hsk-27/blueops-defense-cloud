import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  ArrowLeft,
  Clock,
  Server,
  User as UserIcon,
  MessageSquare,
  Zap,
  CheckCircle,
  AlertOctagon,
  RefreshCw,
  Binary,
  Tag,
  Download,
  FileText,
  Plus,
  Link2,
  Trash2,
  Eye,
  Layers,
  Activity,
  FileCheck,
  UserCheck,
  AlertTriangle
} from 'lucide-react';
import { api } from '../services/api';
import {
  Incident,
  TimelineEntry,
  IncidentStatus,
  IncidentEvidence,
  RelatedFinding,
  IncidentRecommendation
} from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { AuthoritativeAdvisor } from '../components/AuthoritativeAdvisor';
import { useAuth } from '../context/AuthContext';

interface InvestigationWorkspaceProps {
  incidentId: number;
  onBack: () => void;
  onNavigateToResponse: (playbookCode: string, target: string, incId: number) => void;
}

export const InvestigationWorkspacePage: React.FC<InvestigationWorkspaceProps> = ({
  incidentId,
  onBack,
  onNavigateToResponse
}) => {
  const { user } = useAuth();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [evidenceList, setEvidenceList] = useState<IncidentEvidence[]>([]);
  const [relatedFindings, setRelatedFindings] = useState<RelatedFinding[]>([]);
  const [recommendations, setRecommendations] = useState<IncidentRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingAdvisor, setLoadingAdvisor] = useState(false);

  // Active right column tab: 'FINDINGS' | 'EVIDENCE' | 'RELATED'
  const [activeTab, setActiveTab] = useState<'FINDINGS' | 'EVIDENCE' | 'RELATED'>('FINDINGS');
  const [inspectEvidenceItem, setInspectEvidenceItem] = useState<IncidentEvidence | null>(null);

  // Note form state
  const [newNote, setNewNote] = useState('');
  const [submittingNote, setSubmittingNote] = useState(false);

  // Status transition state
  const [statusReason, setStatusReason] = useState('');
  const [transitioning, setTransitioning] = useState(false);

  // Modals for Assignment & Resolution/Closure
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [assignTarget, setAssignTarget] = useState('');
  const [showResolveModal, setShowResolveModal] = useState(false);
  const [resolutionRationale, setResolutionRationale] = useState('');
  const [showCloseModal, setShowCloseModal] = useState(false);
  const [closureNotes, setClosureNotes] = useState('');

  // Finding attach state
  const [showAttachInput, setShowAttachInput] = useState(false);
  const [findingIdToAttach, setFindingIdToAttach] = useState('');
  const [attachingFinding, setAttachingFinding] = useState(false);

  const loadIncidentData = async () => {
    try {
      setLoading(true);
      const [incData, tlData, findData, evdData, recData] = await Promise.all([
        api.getIncidentById(incidentId),
        api.getTimeline(incidentId),
        api.getIncidentFindings(incidentId),
        api.getIncidentEvidence(incidentId).catch(() => [] as IncidentEvidence[]),
        api.getIncidentRecommendations(incidentId).catch((err) => {
          console.warn('Failed to load incident recommendations:', err);
          return [] as IncidentRecommendation[];
        })
      ]);

      setIncident(incData);
      setTimeline(tlData || []);
      setFindings(findData || []);
      setEvidenceList(evdData || []);
      setRecommendations(recData || []);

      // If findings exist, query related findings for the first attached finding
      if (findData && findData.length > 0) {
        const primaryFindingId = findData[0].opensearchFindingId || findData[0].findingId;
        if (primaryFindingId) {
          api.getRelatedFindings(primaryFindingId)
            .then(rel => setRelatedFindings(rel || []))
            .catch(() => setRelatedFindings([]));
        }
      }
    } catch (err) {
      console.error('Failed to load incident investigation details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidentData();
  }, [incidentId]);

  const handleAttachFinding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!findingIdToAttach.trim()) return;
    try {
      setAttachingFinding(true);
      await api.attachFinding(incidentId, findingIdToAttach.trim());
      setFindingIdToAttach('');
      setShowAttachInput(false);
      await loadIncidentData();
    } catch (err: any) {
      alert(err.message || 'Failed to attach finding to incident');
    } finally {
      setAttachingFinding(false);
    }
  };

  const handleAttachSpecificFinding = async (fId: string) => {
    try {
      setAttachingFinding(true);
      await api.attachFinding(incidentId, fId);
      await loadIncidentData();
    } catch (err: any) {
      alert(err.message || 'Failed to attach related finding');
    } finally {
      setAttachingFinding(false);
    }
  };

  const handleDetachFinding = async (findingId: string) => {
    if (!confirm(`Are you sure you want to detach finding ${findingId} from this incident?`)) return;
    try {
      await api.detachFinding(incidentId, findingId);
      await loadIncidentData();
    } catch (err: any) {
      alert(err.message || 'Failed to detach finding');
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    try {
      setSubmittingNote(true);
      await api.addNote(incidentId, newNote);
      setNewNote('');
      await loadIncidentData();
    } catch (err: any) {
      alert(err.message || 'Failed to add note');
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleAssignIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.assignIncident(incidentId, assignTarget.trim());
      setShowAssignModal(false);
      await loadIncidentData();
    } catch (err: any) {
      alert(err.message || 'Failed to assign incident');
    }
  };

  const handleStatusChange = async (targetStatus: IncidentStatus) => {
    if (targetStatus === 'RESOLVED') {
      setShowResolveModal(true);
      return;
    }
    if (targetStatus === 'CLOSED') {
      setShowCloseModal(true);
      return;
    }

    try {
      setTransitioning(true);
      await api.updateIncidentStatus(
        incidentId,
        targetStatus,
        statusReason || `Analyst transitioned state to ${targetStatus}`
      );
      setStatusReason('');
      await loadIncidentData();
    } catch (err: any) {
      alert(err.message || 'Invalid state transition');
    } finally {
      setTransitioning(false);
    }
  };

  const submitResolve = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resolutionRationale.trim()) {
      alert('Resolution rationale is required.');
      return;
    }
    try {
      setTransitioning(true);
      await api.updateIncidentStatus(
        incidentId,
        'RESOLVED',
        'Incident resolved by analyst',
        resolutionRationale.trim()
      );
      setShowResolveModal(false);
      setResolutionRationale('');
      await loadIncidentData();
    } catch (err: any) {
      alert(err.message || 'Failed to resolve incident');
    } finally {
      setTransitioning(false);
    }
  };

  const submitClose = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setTransitioning(true);
      await api.updateIncidentStatus(
        incidentId,
        'CLOSED',
        'Incident formally closed post-verification',
        undefined,
        closureNotes.trim() || 'Post-incident review complete'
      );
      setShowCloseModal(false);
      setClosureNotes('');
      await loadIncidentData();
    } catch (err: any) {
      alert(err.message || 'Failed to close incident');
    } finally {
      setTransitioning(false);
    }
  };

  const exportIncidentReport = (format: 'markdown' | 'json') => {
    if (!incident) return;
    if (format === 'json') {
      const exportData = {
        incident,
        timeline,
        findings,
        evidence: evidenceList,
        recommendations,
        exportedAt: new Date().toISOString(),
        platform: 'BlueOps Enterprise Threat Detection & Incident Response'
      };
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${incident.incidentNumber}_SOC_Report.json`;
      a.click();
    } else {
      const md = `# BLUEOPS INCIDENT INVESTIGATION REPORT
## Incident: ${incident.incidentNumber} - ${incident.title}

- **Severity:** ${incident.severity}
- **Priority:** ${incident.priority || 'P3_MEDIUM'}
- **Status:** ${incident.status}
- **Primary Asset:** ${incident.primaryAssetHostname || 'None'}
- **Created At:** ${incident.createdAt}
- **Assigned Analyst:** ${incident.assignedTo || 'Unassigned'}
- **Closed At:** ${incident.closedAt || 'N/A'} (By: ${incident.closedBy || 'N/A'})

### Description & Executive Summary
${incident.description || 'No description provided.'}

${incident.resolutionRationale ? `### Resolution Rationale\n${incident.resolutionRationale}\n` : ''}
${incident.closureNotes ? `### Closure Review Notes\n${incident.closureNotes}\n` : ''}

---

### Associated Detection Findings (${findings.length})
${findings.map((f) => `- **[${f.ruleCode || 'N/A'}] ${f.ruleName || 'Finding'}** (Severity: ${f.severity || 'HIGH'})
  - Related Doc ID: ${f.rawDocumentId || 'N/A'}
  - Timestamp: ${f.detectedAt}`).join('\n')}

---

### Forensic Evidence Records (${evidenceList.length})
${evidenceList.map((e) => `- **[${e.provider}] ${e.ruleName}** on host \`${e.host}\` (${e.sourceIp || 'Internal'})
  - Process: \`${e.process || 'N/A'}\`
  - Evidence ID: ${e.evidenceId}`).join('\n')}

---

### Incident Timeline & Investigation Audit
${timeline.map((t) => `- **${new Date(t.timestamp).toLocaleString()}** [${t.type}] ${t.description} (User: ${t.actor || 'System'})`).join('\n')}

---
*Report generated automatically by BlueOps SOC Platform on ${new Date().toISOString()}*
`;
      const blob = new Blob([md], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${incident.incidentNumber}_SOC_Report.md`;
      a.click();
    }
  };

  if (loading && !incident) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[60vh] text-slate-400 space-x-3">
        <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />
        <span>Loading Incident Investigation Workspace...</span>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="p-8 text-center text-slate-400">
        <p>Incident not found.</p>
        <button onClick={onBack} className="mt-4 text-blue-400 hover:underline">
          Return to Incident Center
        </button>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Back button and Export Header */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center space-x-2 text-xs font-mono text-slate-400 hover:text-slate-200 transition"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>BACK TO INCIDENT CENTER</span>
        </button>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => exportIncidentReport('markdown')}
            title="Download incident report as Markdown"
            className="bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-semibold px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition"
          >
            <Download className="w-3.5 h-3.5 text-blue-400" />
            <span>Export Report (.md)</span>
          </button>
          <button
            onClick={() =>
              onNavigateToResponse(
                'P003',
                incident.primaryAssetHostname || 'LAB-HOST',
                incident.id
              )
            }
            className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-mono font-medium px-3 py-1.5 rounded flex items-center space-x-1.5 transition"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Launch Response Playbook</span>
          </button>
        </div>
      </div>

      {/* Incident Summary Card */}
      <div className="bg-[#11141d] border border-[#212738] rounded-md p-5 space-y-4">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-[#212738] pb-4">
          <div>
            <div className="flex items-center space-x-3 mb-1">
              <span className="font-mono text-sm text-sky-400 font-bold">{incident.incidentNumber}</span>
              <SeverityBadge severity={incident.severity} />
              {incident.priority && (
                <span className="bg-purple-950/60 text-purple-300 border border-purple-800/60 px-2 py-0.5 rounded text-[10px] font-mono font-bold">
                  {incident.priority}
                </span>
              )}
              <StatusBadge status={incident.status} />
            </div>
            <h2 className="text-xl font-bold text-slate-100">{incident.title}</h2>
          </div>

          {/* Quick Details Pills */}
          <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
            <div className="bg-[#0c0e15] border border-[#212738] px-3 py-1.5 rounded flex items-center space-x-2">
              <Server className="w-3.5 h-3.5 text-sky-400" />
              <span className="text-slate-400">Target Asset:</span>
              <span className="text-slate-100 font-semibold">{incident.primaryAssetHostname || 'None'}</span>
            </div>

            <div className="bg-[#0c0e15] border border-[#212738] px-3 py-1.5 rounded flex items-center space-x-2">
              <UserIcon className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-slate-400">Assigned:</span>
              <span className="text-slate-100 font-semibold">{incident.assignedTo || 'Unassigned'}</span>
              <button
                onClick={() => {
                  setAssignTarget(incident.assignedTo || '');
                  setShowAssignModal(true);
                }}
                className="text-[10px] text-sky-400 hover:underline pl-1"
              >
                (Change)
              </button>
            </div>
          </div>
        </div>

        {incident.description && (
          <p className="text-xs text-slate-300 leading-relaxed bg-[#0c0e15] p-3 rounded border border-[#212738]">
            {incident.description}
          </p>
        )}

        {incident.resolutionRationale && (
          <div className="bg-emerald-950/30 border border-emerald-800/40 p-3 rounded text-xs space-y-1">
            <span className="font-bold text-emerald-300 uppercase tracking-wider text-[10px]">Resolution Rationale:</span>
            <p className="text-slate-200">{incident.resolutionRationale}</p>
          </div>
        )}

        {incident.closureNotes && (
          <div className="bg-slate-900 border border-slate-700 p-3 rounded text-xs space-y-1">
            <span className="font-bold text-slate-400 uppercase tracking-wider text-[10px]">Closure Review:</span>
            <p className="text-slate-300">{incident.closureNotes} (Closed by {incident.closedBy})</p>
          </div>
        )}

        {/* State Machine Transition Bar */}
        <div className="pt-2 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-2 font-mono text-xs">
            <span className="text-slate-400 uppercase tracking-wider text-[11px]">Workflow Phase:</span>
            {incident.status === 'NEW' && (
              <>
                <button
                  onClick={() => handleStatusChange('TRIAGED')}
                  disabled={transitioning}
                  className="px-2.5 py-1 bg-amber-950/60 hover:bg-amber-900 border border-amber-800 text-amber-300 text-xs rounded transition"
                >
                  Mark Triaged
                </button>
                <button
                  onClick={() => handleStatusChange('INVESTIGATING')}
                  disabled={transitioning}
                  className="px-2.5 py-1 bg-sky-950/60 hover:bg-sky-900 border border-sky-800 text-sky-300 text-xs rounded transition"
                >
                  Start Investigation
                </button>
              </>
            )}

            {incident.status === 'TRIAGED' && (
              <button
                onClick={() => handleStatusChange('INVESTIGATING')}
                disabled={transitioning}
                className="px-2.5 py-1 bg-sky-950/60 hover:bg-sky-900 border border-sky-800 text-sky-300 text-xs rounded transition"
              >
                Investigate
              </button>
            )}

            {incident.status === 'INVESTIGATING' && (
              <>
                <button
                  onClick={() => handleStatusChange('CONTAINMENT_PENDING')}
                  disabled={transitioning}
                  className="px-2.5 py-1 bg-purple-950/60 hover:bg-purple-900 border border-purple-800 text-purple-300 text-xs rounded transition"
                >
                  Request Containment
                </button>
                <button
                  onClick={() => handleStatusChange('CONTAINED')}
                  disabled={transitioning}
                  className="px-2.5 py-1 bg-emerald-950/60 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 text-xs rounded transition"
                >
                  Mark Contained
                </button>
                <button
                  onClick={() => handleStatusChange('RESOLVED')}
                  disabled={transitioning}
                  className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs rounded transition"
                >
                  Resolve Incident
                </button>
              </>
            )}

            {(incident.status === 'CONTAINMENT_PENDING' || incident.status === 'CONTAINED') && (
              <button
                onClick={() => handleStatusChange('RESOLVED')}
                disabled={transitioning}
                className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs rounded transition"
              >
                Resolve Incident
              </button>
            )}

            {(incident.status === 'RESOLVED' || incident.status === 'FALSE_POSITIVE') && (
              <>
                <button
                  onClick={() => handleStatusChange('CLOSED')}
                  disabled={transitioning}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-200 text-xs font-semibold rounded transition flex items-center space-x-1"
                >
                  <FileCheck className="w-3.5 h-3.5 text-blue-400" />
                  <span>Formally Close Incident</span>
                </button>
                <button
                  onClick={() => handleStatusChange('REOPENED')}
                  disabled={transitioning}
                  className="px-2.5 py-1 bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs rounded transition"
                >
                  Reopen Incident
                </button>
              </>
            )}

            {incident.status === 'CLOSED' && (
              <button
                onClick={() => handleStatusChange('REOPENED')}
                disabled={transitioning}
                className="px-2.5 py-1 bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs rounded transition"
              >
                Reopen Incident
              </button>
            )}

            {(incident.status === 'NEW' || incident.status === 'TRIAGED' || incident.status === 'INVESTIGATING') && (
              <button
                onClick={() => handleStatusChange('FALSE_POSITIVE')}
                disabled={transitioning}
                className="px-2.5 py-1 bg-[#181d2a] hover:bg-[#212738] border border-slate-700 text-slate-300 text-xs rounded transition"
              >
                Mark False Positive
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 2-Column Section: Investigation Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline, Guidance & Notes (2 Cols) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Authoritative Incident Advisor (NIST / CISA / MITRE / SANS) */}
          <AuthoritativeAdvisor
            recommendations={recommendations}
            loading={loadingAdvisor}
            onLaunchPlaybook={(playbookCode, target) =>
              onNavigateToResponse(playbookCode, target, incident.id)
            }
          />

          {/* Chronological Timeline */}
          <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
            <h3 className="text-xs font-mono uppercase font-bold text-slate-200 mb-4 flex items-center space-x-2 tracking-wider">
              <Clock className="w-4 h-4 text-sky-400" />
              <span>Chronological Investigation Timeline</span>
            </h3>

            <div className="space-y-4 relative before:absolute before:inset-0 before:left-3 before:w-0.5 before:bg-[#212738]">
              {timeline.length > 0 ? (
                timeline.map((entry, idx) => (
                  <div key={idx} className="relative flex items-start space-x-4 pl-8">
                    <div
                      className={`absolute left-1.5 top-1 w-3.5 h-3.5 rounded-full border-2 bg-[#11141d] ${
                        entry.type === 'FINDING'
                          ? 'border-rose-500'
                          : entry.type === 'STATUS_CHANGE'
                          ? 'border-sky-500'
                          : entry.type === 'CLOSURE'
                          ? 'border-slate-400'
                          : 'border-emerald-500'
                      }`}
                    ></div>

                    <div className="w-full bg-[#0c0e15] border border-[#212738] p-3 rounded space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-slate-200">{entry.title}</span>
                        <span className="text-[10px] font-mono text-slate-500">
                          {new Date(entry.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">{entry.description}</p>
                      <div className="text-[10px] font-mono text-slate-500 flex items-center space-x-2 pt-1">
                        <span>Actor: {entry.actor}</span>
                        <span>•</span>
                        <span className="uppercase text-slate-400">{entry.type}</span>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-xs text-slate-500 font-mono pl-8">No timeline milestones recorded.</p>
              )}
            </div>
          </div>

          {/* Add Investigation Note */}
          <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
            <h3 className="text-xs font-mono uppercase font-bold text-slate-200 mb-3 flex items-center space-x-2 tracking-wider">
              <MessageSquare className="w-4 h-4 text-emerald-400" />
              <span>Add Analyst Investigation Note</span>
            </h3>

            <form onSubmit={handleAddNote} className="space-y-3">
              <textarea
                rows={3}
                required
                placeholder="Document containment steps, memory artifacts, command hashes, or external pivots..."
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                className="w-full bg-[#0c0e15] border border-[#212738] rounded p-3 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
              />
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={submittingNote}
                  className="bg-sky-600 hover:bg-sky-500 text-white text-xs font-mono font-medium px-3 py-1.5 rounded disabled:opacity-50 transition"
                >
                  {submittingNote ? 'Saving...' : 'Append Note to Timeline'}
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Tabbed Side Panel: Findings, Forensic Evidence, Related Findings (1 Col) */}
        <div className="space-y-6">
          <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
            {/* Tabs Navigation */}
            <div className="flex items-center space-x-2 border-b border-[#212738] pb-3 mb-3">
              <button
                onClick={() => setActiveTab('FINDINGS')}
                className={`text-xs font-mono font-bold px-2.5 py-1 rounded transition ${
                  activeTab === 'FINDINGS' ? 'bg-sky-950 text-sky-300 border border-sky-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Findings ({findings.length})
              </button>
              <button
                onClick={() => setActiveTab('EVIDENCE')}
                className={`text-xs font-mono font-bold px-2.5 py-1 rounded transition ${
                  activeTab === 'EVIDENCE' ? 'bg-sky-950 text-sky-300 border border-sky-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Evidence ({evidenceList.length})
              </button>
              <button
                onClick={() => setActiveTab('RELATED')}
                className={`text-xs font-mono font-bold px-2.5 py-1 rounded transition ${
                  activeTab === 'RELATED' ? 'bg-sky-950 text-sky-300 border border-sky-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Related ({relatedFindings.length})
              </button>
            </div>

            {/* TAB 1: Associated Findings */}
            {activeTab === 'FINDINGS' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-400 uppercase">Linked Detections</span>
                  <button
                    onClick={() => setShowAttachInput(!showAttachInput)}
                    className="text-xs font-mono text-sky-400 hover:text-sky-300 font-medium flex items-center space-x-1"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Attach</span>
                  </button>
                </div>

                {showAttachInput && (
                  <form onSubmit={handleAttachFinding} className="bg-[#0c0e15] border border-[#212738] p-3 rounded space-y-2">
                    <label className="text-[10px] font-mono text-slate-400 uppercase">Finding ID (e.g. FND-SIGMA-D008-2001):</label>
                    <div className="flex space-x-2">
                      <input
                        type="text"
                        required
                        placeholder="Enter finding ID..."
                        value={findingIdToAttach}
                        onChange={(e) => setFindingIdToAttach(e.target.value)}
                        className="flex-1 bg-[#11141d] border border-[#212738] rounded px-2.5 py-1 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
                      />
                      <button
                        type="submit"
                        disabled={attachingFinding}
                        className="bg-sky-600 hover:bg-sky-500 text-white text-xs font-mono px-3 py-1 rounded disabled:opacity-50"
                      >
                        {attachingFinding ? 'Linking...' : 'Link'}
                      </button>
                    </div>
                  </form>
                )}

                {findings.length > 0 ? (
                  findings.map((f, idx) => (
                    <div key={idx} className="bg-[#0c0e15] border border-[#212738] p-3 rounded space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-sky-400">{f.ruleCode}</span>
                        <div className="flex items-center space-x-2">
                          <SeverityBadge severity={f.severity} />
                          <button
                            onClick={() => handleDetachFinding(f.opensearchFindingId || f.findingId)}
                            title="Detach finding"
                            className="text-slate-500 hover:text-rose-400 transition"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                      <p className="text-xs font-semibold text-slate-200">{f.ruleName}</p>
                      <div className="text-[10px] font-mono text-slate-500 truncate">
                        Doc ID: {f.rawDocumentId || 'DOC-OS-RAW'}
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 font-mono">No telemetry findings attached.</p>
                )}
              </div>
            )}

            {/* TAB 2: Forensic Evidence */}
            {activeTab === 'EVIDENCE' && (
              <div className="space-y-3">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Forensic Telemetry Artifacts</span>
                {evidenceList.length > 0 ? (
                  evidenceList.map((e, idx) => (
                    <div key={idx} className="bg-[#0c0e15] border border-[#212738] p-3 rounded space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="bg-sky-950 text-sky-300 border border-sky-800 text-[10px] font-mono px-2 py-0.5 rounded font-bold">
                          {e.provider}
                        </span>
                        <SeverityBadge severity={e.severity} />
                      </div>
                      <div className="text-xs font-semibold text-slate-200">{e.ruleName}</div>
                      <div className="text-[11px] font-mono text-slate-400 space-y-0.5">
                        <div>Host: <span className="text-slate-200">{e.host}</span></div>
                        {e.sourceIp && <div>Source IP: <span className="text-slate-200">{e.sourceIp}</span></div>}
                        {e.process && <div className="truncate text-slate-300 font-mono text-[10px] bg-[#11141d] p-1 rounded mt-1">{e.process}</div>}
                      </div>

                      {e.rawPayload && (
                        <button
                          onClick={() => setInspectEvidenceItem(inspectEvidenceItem?.evidenceId === e.evidenceId ? null : e)}
                          className="text-[11px] text-sky-400 hover:underline flex items-center space-x-1 font-mono pt-1"
                        >
                          <Eye className="w-3 h-3" />
                          <span>{inspectEvidenceItem?.evidenceId === e.evidenceId ? 'Hide Raw Payload' : 'View Raw Provenance'}</span>
                        </button>
                      )}

                      {inspectEvidenceItem?.evidenceId === e.evidenceId && (
                        <pre className="bg-[#11141d] border border-slate-700 p-2 rounded text-[10px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-48">
                          {inspectEvidenceItem.rawPayload}
                        </pre>
                      )}
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 font-mono">No raw forensic evidence linked yet.</p>
                )}
              </div>
            )}

            {/* TAB 3: Related Findings Engine */}
            {activeTab === 'RELATED' && (
              <div className="space-y-3">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Correlated Detections</span>
                {relatedFindings.length > 0 ? (
                  relatedFindings.map((r, idx) => (
                    <div key={idx} className="bg-[#0c0e15] border border-[#212738] p-3 rounded space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-sky-400">{r.finding.ruleId}</span>
                        <span className="bg-purple-950/60 text-purple-300 border border-purple-800 text-[10px] font-mono px-2 py-0.5 rounded">
                          {r.relationType} ({Math.round(r.confidenceScore * 100)}%)
                        </span>
                      </div>
                      <p className="text-xs font-semibold text-slate-200">{r.finding.ruleName}</p>
                      <p className="text-[11px] text-slate-400">{r.relationshipRationale}</p>
                      <div className="flex justify-end pt-1">
                        <button
                          onClick={() => handleAttachSpecificFinding(r.finding.findingId)}
                          disabled={attachingFinding}
                          className="bg-sky-600 hover:bg-sky-500 text-white text-[11px] font-mono px-2.5 py-1 rounded flex items-center space-x-1"
                        >
                          <Plus className="w-3 h-3" />
                          <span>Attach to Incident</span>
                        </button>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 font-mono">No related detections found across active assets.</p>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Assignment Modal */}
      {showAssignModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#11141d] border border-[#212738] rounded-md max-w-md w-full p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <UserCheck className="w-4 h-4 text-emerald-400" />
              <span>Assign Incident to SOC Analyst</span>
            </h3>
            <form onSubmit={handleAssignIncident} className="space-y-4">
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Analyst Username (or 'unassigned'):</label>
                <input
                  type="text"
                  required
                  value={assignTarget}
                  onChange={(e) => setAssignTarget(e.target.value)}
                  placeholder="e.g. analyst.alice"
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded px-3 py-1.5 text-xs text-slate-100 font-mono focus:outline-none focus:border-sky-500"
                />
              </div>
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowAssignModal(false)}
                  className="px-3 py-1.5 border border-slate-700 text-slate-300 text-xs rounded hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs rounded font-medium"
                >
                  Update Assignment
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Resolution Modal */}
      {showResolveModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#11141d] border border-[#212738] rounded-md max-w-md w-full p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              <span>Resolve Incident</span>
            </h3>
            <form onSubmit={submitResolve} className="space-y-4">
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Resolution Rationale (Mandatory):</label>
                <textarea
                  rows={3}
                  required
                  value={resolutionRationale}
                  onChange={(e) => setResolutionRationale(e.target.value)}
                  placeholder="Detail containment actions, adversary termination, or remediation confirmation..."
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded p-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowResolveModal(false)}
                  className="px-3 py-1.5 border border-slate-700 text-slate-300 text-xs rounded hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={transitioning}
                  className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs rounded font-medium"
                >
                  {transitioning ? 'Resolving...' : 'Confirm Resolution'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Closure Modal */}
      {showCloseModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#11141d] border border-[#212738] rounded-md max-w-md w-full p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <FileCheck className="w-4 h-4 text-blue-400" />
              <span>Formally Close Incident</span>
            </h3>
            <form onSubmit={submitClose} className="space-y-4">
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Closure Review Notes:</label>
                <textarea
                  rows={3}
                  value={closureNotes}
                  onChange={(e) => setClosureNotes(e.target.value)}
                  placeholder="Formal post-incident review notes and audit sign-off..."
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded p-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-sky-500"
                />
              </div>
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowCloseModal(false)}
                  className="px-3 py-1.5 border border-slate-700 text-slate-300 text-xs rounded hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={transitioning}
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs rounded font-medium"
                >
                  {transitioning ? 'Closing...' : 'Confirm Closure'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
