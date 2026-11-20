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
  Link2
} from 'lucide-react';
import { api } from '../services/api';
import { Incident, TimelineEntry, IncidentStatus, IncidentRecommendation } from '../types';
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
  const [recommendations, setRecommendations] = useState<IncidentRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingAdvisor, setLoadingAdvisor] = useState(false);

  // Note form state
  const [newNote, setNewNote] = useState('');
  const [submittingNote, setSubmittingNote] = useState(false);

  // Status transition state
  const [statusReason, setStatusReason] = useState('');
  const [transitioning, setTransitioning] = useState(false);

  // Evidence / finding attach state
  const [showAttachInput, setShowAttachInput] = useState(false);
  const [findingIdToAttach, setFindingIdToAttach] = useState('');
  const [attachingFinding, setAttachingFinding] = useState(false);

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

  const loadIncidentData = async () => {
    try {
      setLoading(true);
      const [incData, tlData, findData, recData] = await Promise.all([
        api.getIncidentById(incidentId),
        api.getTimeline(incidentId),
        api.getIncidentFindings(incidentId),
        api.getIncidentRecommendations(incidentId).catch((err) => {
          console.warn('Failed to load incident recommendations:', err);
          return [] as IncidentRecommendation[];
        })
      ]);
      setIncident(incData);
      setTimeline(tlData || []);
      setFindings(findData || []);
      setRecommendations(recData || []);
    } catch (err) {
      console.error('Failed to load incident investigation details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidentData();
  }, [incidentId]);

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

  const exportIncidentReport = (format: 'markdown' | 'json') => {
    if (!incident) return;
    if (format === 'json') {
      const exportData = {
        incident,
        timeline,
        findings,
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
- **Status:** ${incident.status}
- **Primary Asset:** ${incident.primaryAssetHostname || 'None'}
- **Created At:** ${incident.createdAt}
- **Assigned Analyst:** ${incident.assignedTo || 'Unassigned'}

### Description & Executive Summary
${incident.description || 'No description provided.'}

---

### Authoritative Next-Step Recommendations (NIST / CISA / MITRE)
${recommendations.map((r, i) => `#### ${i + 1}. [${r.priority}] ${r.title}
- **Authoritative Source:** ${r.authoritativeSource} (${r.citation})
- **Incident Phase:** ${r.phase}
${r.suggestedPlaybookCode ? `- **Suggested Playbook:** ${r.suggestedPlaybookCode} (${r.suggestedPlaybookName || 'Playbook'}) -> Target: ${r.suggestedTarget || 'N/A'}` : ''}
- **Analysis & Rationale:** ${r.rationale}
- **Actionable Steps:**
${r.actionableSteps.map(s => `  - ${s}`).join('\n')}`).join('\n\n')}

---

### Associated Detection Findings (${findings.length})
${findings.map((f) => `- **[${f.ruleId || 'N/A'}] ${f.ruleName || 'Finding'}** (Severity: ${f.ruleSeverity || 'HIGH'})
  - MITRE ATT&CK: ${f.mitreTactic || 'N/A'} - ${f.mitreTechniqueId || 'N/A'} (${f.mitreTechniqueName || 'N/A'})
  - Timestamp: ${f.timestamp}`).join('\n')}

---

### Incident Timeline & Investigation Audit
${timeline.map((t) => `- **${new Date(t.timestamp).toLocaleString()}** [${t.type}] ${t.description} (User: ${t.actor || 'System'})`).join('\n')}

---
*Report generated automatically by BlueOps SOC Platform v1.0.0 on ${new Date().toISOString()}*
`;
      const blob = new Blob([md], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${incident.incidentNumber}_SOC_Report.md`;
      a.click();
    }
  };

  const handleStatusChange = async (targetStatus: IncidentStatus) => {
    try {
      setTransitioning(true);
      await api.updateIncidentStatus(
        incidentId,
        targetStatus,
        statusReason || `Analyst moved incident to ${targetStatus}`,
        targetStatus === 'RESOLVED' ? statusReason || 'Adversary activity contained and verified clean' : undefined
      );
      setStatusReason('');
      await loadIncidentData();
    } catch (err: any) {
      alert(err.message || 'Invalid state transition');
    } finally {
      setTransitioning(false);
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
      {/* Back button and Header */}
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
            </div>
          </div>
        </div>

        {incident.description && (
          <p className="text-xs text-slate-300 leading-relaxed bg-[#0c0e15] p-3 rounded border border-[#212738]">
            {incident.description}
          </p>
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

      {/* 2-Column Section: Investigation Timeline & Associated Evidence */}
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
                    {/* Circle icon */}
                    <div
                      className={`absolute left-1.5 top-1 w-3.5 h-3.5 rounded-full border-2 bg-[#11141d] ${
                        entry.type === 'FINDING'
                          ? 'border-rose-500'
                          : entry.type === 'STATUS_CHANGE'
                          ? 'border-sky-500'
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

        {/* Associated Telemetry Findings & MITRE (1 Col) */}
        <div className="space-y-6">
          <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-mono uppercase font-bold text-slate-200 flex items-center space-x-2 tracking-wider">
                <Binary className="w-4 h-4 text-rose-500" />
                <span>Associated Telemetry Findings</span>
              </h3>
              <button
                onClick={() => setShowAttachInput(!showAttachInput)}
                title="Attach OpenSearch Finding or Telemetry Alert"
                className="text-xs font-mono text-sky-400 hover:text-sky-300 font-medium flex items-center space-x-1"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Attach</span>
              </button>
            </div>

            {showAttachInput && (
              <form onSubmit={handleAttachFinding} className="mb-4 bg-[#0c0e15] border border-[#212738] p-3 rounded space-y-2">
                <label className="text-[10px] font-mono text-slate-400 uppercase">Finding ID (e.g. FND-2026-001):</label>
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
                    {attachingFinding ? 'Attaching...' : 'Link'}
                  </button>
                </div>
              </form>
            )}

            <div className="space-y-3">
              {findings.length > 0 ? (
                findings.map((f, idx) => (
                  <div key={idx} className="bg-[#0c0e15] border border-[#212738] p-3 rounded space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-sky-400">{f.ruleCode}</span>
                      <SeverityBadge severity={f.severity} />
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
          </div>
        </div>
      </div>
    </div>
  );
};
