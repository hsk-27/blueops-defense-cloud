import React, { useEffect, useState } from 'react';
import {
  Zap,
  ShieldCheck,
  RefreshCw,
  AlertOctagon,
  CheckCircle2,
  Clock,
  Play,
  ShieldAlert,
  FileCheck,
  Ban,
  Check,
  X,
  Eye,
  Lock,
  Layers,
  Terminal,
  Server
} from 'lucide-react';
import { api } from '../services/api';
import {
  ResponseProposal,
  ResponseActionCatalogItem,
  ResponseTargetItem,
  PolicyEvaluationResult,
  ResponseRiskLevel,
  ProposalStatus
} from '../types';
import { useAuth } from '../context/AuthContext';

export const ResponseManagementPage: React.FC<{
  initialPlaybook?: string;
  initialTarget?: string;
  initialIncidentId?: number;
}> = ({ initialPlaybook, initialTarget, initialIncidentId }) => {
  const { user, isAdmin } = useAuth();
  const [activeTab, setActiveTab] = useState<'proposals' | 'catalog' | 'targets' | 'history'>('proposals');

  const [proposals, setProposals] = useState<ResponseProposal[]>([]);
  const [catalog, setCatalog] = useState<ResponseActionCatalogItem[]>([]);
  const [targets, setTargets] = useState<ResponseTargetItem[]>([]);
  const [loading, setLoading] = useState(true);

  // Proposal Creation Modal & Policy Preview State
  const [showModal, setShowModal] = useState(!!initialPlaybook);
  const [selectedAction, setSelectedAction] = useState(initialPlaybook || 'ACT-001');
  const [targetIdentifier, setTargetIdentifier] = useState(initialTarget || '198.51.100.24');
  const [incidentId, setIncidentId] = useState<number | undefined>(initialIncidentId);
  const [policyPreview, setPolicyPreview] = useState<PolicyEvaluationResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // Verification Evidence Modal State
  const [selectedVerification, setSelectedVerification] = useState<any | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [propsRes, catRes, tgtRes] = await Promise.all([
        api.getResponseProposals(undefined, 0, 50).catch(() => ({ content: [] })),
        api.getResponseCatalog().catch(() => []),
        api.getResponseTargets().catch(() => [])
      ]);
      setProposals(propsRes?.content || []);
      setCatalog(catRes || []);
      setTargets(tgtRes || []);
    } catch (err) {
      console.error('Failed loading SOAR response data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handlePreviewPolicy = async () => {
    try {
      setPreviewLoading(true);
      const result = await api.previewResponsePolicy({
        actionCode: selectedAction,
        targetIdentifier: targetIdentifier.trim(),
        incidentId: incidentId ? Number(incidentId) : undefined,
        executionMode: 'SIMULATION'
      });
      setPolicyPreview(result);
    } catch (err: any) {
      alert(err.message || 'Policy evaluation preview failed');
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleCreateProposal = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmitting(true);
      await api.createResponseProposal({
        actionCode: selectedAction,
        targetIdentifier: targetIdentifier.trim(),
        incidentId: incidentId ? Number(incidentId) : undefined,
        executionMode: 'SIMULATION'
      });
      setShowModal(false);
      setPolicyPreview(null);
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to create response proposal');
    } finally {
      setSubmitting(false);
    }
  };

  const handleApprove = async (proposalId: number) => {
    const reason = prompt('Approval justification (required for audit logging):') || 'Approved by analyst';
    try {
      await api.approveResponseProposal(proposalId, { reason, executeImmediately: true });
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Approval rejected by policy engine');
    }
  };

  const handleDeny = async (proposalId: number) => {
    const reason = prompt('Reason for proposal denial:') || 'Denied by analyst';
    try {
      await api.denyResponseProposal(proposalId, reason);
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to deny proposal');
    }
  };

  const handleCancel = async (proposalId: number) => {
    const reason = prompt('Reason for cancellation:') || 'Cancelled by operator';
    try {
      await api.cancelResponseProposal(proposalId, reason);
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to cancel proposal');
    }
  };

  const handleExecute = async (proposalId: number) => {
    try {
      await api.executeResponseProposal(proposalId);
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Execution failed');
    }
  };

  const getRiskBadge = (risk: ResponseRiskLevel) => {
    switch (risk) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">CRITICAL RISK</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">HIGH RISK</span>;
      case 'MODERATE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30">MODERATE</span>;
      case 'LOW':
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">LOW RISK</span>;
    }
  };

  const getStatusBadge = (status: ProposalStatus) => {
    switch (status) {
      case 'VERIFIED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center space-x-1"><CheckCircle2 className="w-3 h-3" /><span>VERIFIED</span></span>;
      case 'EXECUTED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">EXECUTED</span>;
      case 'APPROVED':
      case 'READY':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30">APPROVED / READY</span>;
      case 'PENDING_APPROVAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center space-x-1"><Clock className="w-3 h-3" /><span>PENDING APPROVAL</span></span>;
      case 'DENIED':
      case 'REJECTED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">DENIED</span>;
      case 'CANCELLED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-500/20 text-slate-400 border border-slate-500/30">CANCELLED</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300">{status}</span>;
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Host Safety & Controlled SOAR Banner */}
      <div className="bg-[#0b1329] border border-blue-800/60 p-4 rounded-xl flex items-center justify-between shadow-lg">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-blue-500/20 text-blue-400 rounded-lg">
            <ShieldCheck className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono">
                Policy-Governed Response & Controlled SOAR (M6)
              </h4>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 rounded border border-emerald-500/30">
                HOST SAFETY ACTIVE
              </span>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-sky-500/20 text-sky-300 rounded border border-sky-500/30">
                MODE: SIMULATION (LAB CONTAINMENT)
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Separation of duties enforced. All response actions run in bounded simulation adapters with independent post-execution verification.
            </p>
          </div>
        </div>

        <button
          onClick={() => { setShowModal(true); setPolicyPreview(null); }}
          className="bg-indigo-600 hover:bg-indigo-500 text-white font-mono text-xs px-3.5 py-2 rounded-lg flex items-center space-x-2 transition shrink-0 shadow-md"
        >
          <Play className="w-3.5 h-3.5" />
          <span>New Response Proposal</span>
        </button>
      </div>

      {/* Navigation Tabs */}
      <div className="flex space-x-2 border-b border-[#212738] pb-2 font-mono text-xs">
        <button
          onClick={() => setActiveTab('proposals')}
          className={`px-4 py-2 rounded-md font-semibold transition ${activeTab === 'proposals' ? 'bg-[#1e293b] text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Active Proposals & Queue ({proposals.length})
        </button>
        <button
          onClick={() => setActiveTab('catalog')}
          className={`px-4 py-2 rounded-md font-semibold transition ${activeTab === 'catalog' ? 'bg-[#1e293b] text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Action Catalog ({catalog.length})
        </button>
        <button
          onClick={() => setActiveTab('targets')}
          className={`px-4 py-2 rounded-md font-semibold transition ${activeTab === 'targets' ? 'bg-[#1e293b] text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Authorized Targets ({targets.length})
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={`px-4 py-2 rounded-md font-semibold transition ${activeTab === 'history' ? 'bg-[#1e293b] text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Verification & Evidence Logs
        </button>
      </div>

      {/* Tab Content: Proposals Queue */}
      {activeTab === 'proposals' && (
        <div className="bg-[#11141d] border border-[#212738] rounded-xl overflow-hidden shadow-lg">
          <div className="p-4 border-b border-[#212738] bg-[#171b26] flex items-center justify-between">
            <h3 className="text-xs font-bold font-mono uppercase text-slate-100 flex items-center space-x-2 tracking-wider">
              <Clock className="w-4 h-4 text-amber-400" />
              <span>Multi-Stage Proposal & Authorization Queue</span>
            </h3>
            <button onClick={loadData} title="Refresh" className="p-1 hover:bg-[#212738] rounded">
              <RefreshCw className={`w-3.5 h-3.5 text-slate-400 ${loading ? 'animate-spin text-sky-400' : ''}`} />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0c0e15] border-b border-[#212738] text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="p-3">Proposal UUID</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">Target</th>
                  <th className="p-3">Risk Level</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Proposed By</th>
                  <th className="p-3">Policy / Approver</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#212738] text-slate-300">
                {proposals.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-6 text-center text-slate-500">
                      No response proposals in queue. Click "New Response Proposal" to initiate policy evaluation.
                    </td>
                  </tr>
                ) : (
                  proposals.map((prop) => (
                    <tr key={prop.id} className="hover:bg-[#161a26] transition">
                      <td className="p-3 font-bold text-sky-400">{prop.proposalUuid}</td>
                      <td className="p-3">
                        <div className="font-semibold text-slate-100">{prop.actionName}</div>
                        <div className="text-[10px] text-slate-500">{prop.actionCode} · {prop.actionType}</div>
                      </td>
                      <td className="p-3 font-mono text-amber-300">{prop.targetIdentifier}</td>
                      <td className="p-3">{getRiskBadge(prop.riskLevel)}</td>
                      <td className="p-3">{getStatusBadge(prop.status)}</td>
                      <td className="p-3 text-slate-400">{prop.proposedBy}</td>
                      <td className="p-3">
                        {prop.approver ? (
                          <span className="text-[10px] text-emerald-400">Approved by: {prop.approver}</span>
                        ) : prop.denialReason ? (
                          <span className="text-[10px] text-rose-400">{prop.denialReason}</span>
                        ) : (
                          <span className="text-[10px] text-slate-500">Separation of Duties Required</span>
                        )}
                      </td>
                      <td className="p-3 text-right space-x-1.5">
                        {prop.status === 'PENDING_APPROVAL' && (
                          <>
                            <button
                              onClick={() => handleApprove(prop.id)}
                              className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-[10px] transition"
                            >
                              Approve
                            </button>
                            <button
                              onClick={() => handleDeny(prop.id)}
                              className="px-2.5 py-1 rounded bg-rose-600/80 hover:bg-rose-600 text-white font-mono text-[10px] transition"
                            >
                              Deny
                            </button>
                          </>
                        )}
                        {(prop.status === 'APPROVED' || prop.status === 'READY') && (
                          <button
                            onClick={() => handleExecute(prop.id)}
                            className="px-2.5 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white font-mono text-[10px] transition"
                          >
                            Dispatch Sim
                          </button>
                        )}
                        {prop.verification && (
                          <button
                            onClick={() => setSelectedVerification(prop.verification)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 border border-slate-700 font-mono text-[10px] transition"
                          >
                            Evidence
                          </button>
                        )}
                        {prop.status === 'PENDING_APPROVAL' && (
                          <button
                            onClick={() => handleCancel(prop.id)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 font-mono text-[10px] transition"
                          >
                            Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab Content: Action Catalog */}
      {activeTab === 'catalog' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {catalog.map((item) => (
            <div key={item.id} className="bg-[#11141d] border border-[#212738] rounded-xl p-5 space-y-3 shadow-md">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-sky-400">{item.actionCode}</span>
                {getRiskBadge(item.riskLevel)}
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-100">{item.name}</h4>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{item.description}</p>
              </div>
              <div className="pt-2 border-t border-[#212738] grid grid-cols-2 gap-2 text-[10px] font-mono text-slate-400">
                <div>Category: <span className="text-slate-200">{item.category}</span></div>
                <div>Target Type: <span className="text-slate-200">{item.targetType}</span></div>
                <div>Approval: <span className="text-slate-200">{item.requiresApproval ? 'Required' : 'Auto'}</span></div>
                <div>Reversible: <span className="text-slate-200">{item.rollbackSupported ? 'Yes' : 'No'}</span></div>
                <div>Timeout: <span className="text-slate-200">{item.timeoutSeconds}s</span></div>
                <div>Verification: <span className="text-cyan-400">{item.verificationMethod}</span></div>
              </div>
              <button
                onClick={() => {
                  setSelectedAction(item.actionCode);
                  setShowModal(true);
                  setPolicyPreview(null);
                }}
                className="w-full py-1.5 mt-2 rounded bg-[#1e293b] hover:bg-[#283548] text-sky-400 font-mono text-xs transition border border-sky-500/20"
              >
                Propose This Action
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Tab Content: Authorized Targets */}
      {activeTab === 'targets' && (
        <div className="bg-[#11141d] border border-[#212738] rounded-xl overflow-hidden shadow-lg">
          <div className="p-4 border-b border-[#212738] bg-[#171b26] flex items-center justify-between">
            <h3 className="text-xs font-bold font-mono uppercase text-slate-100 flex items-center space-x-2">
              <Server className="w-4 h-4 text-emerald-400" />
              <span>Allowlisted Target Registry & Protected Infrastructure Bounds</span>
            </h3>
          </div>
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#0c0e15] border-b border-[#212738] text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="p-3">Target ID</th>
                <th className="p-3">Type</th>
                <th className="p-3">Identifier</th>
                <th className="p-3">Display Name</th>
                <th className="p-3">Criticality</th>
                <th className="p-3">Trust Status</th>
                <th className="p-3">Protection Boundary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#212738] text-slate-300">
              {targets.map((tgt) => (
                <tr key={tgt.id} className="hover:bg-[#161a26] transition">
                  <td className="p-3 text-sky-400 font-bold">{tgt.targetId}</td>
                  <td className="p-3">{tgt.targetType}</td>
                  <td className="p-3 text-amber-300 font-semibold">{tgt.identifier}</td>
                  <td className="p-3 text-slate-200">{tgt.displayName}</td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${tgt.criticality === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-800 text-slate-400'}`}>
                      {tgt.criticality}
                    </span>
                  </td>
                  <td className="p-3 text-emerald-400 font-bold">{tgt.trustStatus}</td>
                  <td className="p-3">
                    {tgt.isProtected ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center space-x-1 w-max">
                        <Lock className="w-3 h-3" />
                        <span>PROTECTED (BLOCKED)</span>
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300">
                        LAB AUTHORIZED
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab Content: History & Verification Evidence */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          {proposals.filter(p => p.verification).length === 0 ? (
            <div className="p-8 bg-[#11141d] border border-[#212738] rounded-xl text-center text-slate-500 font-mono text-xs">
              No verification records available yet. Execute and verify a proposal to see independent evidence.
            </div>
          ) : (
            proposals.filter(p => p.verification).map((p) => (
              <div key={p.id} className="bg-[#11141d] border border-[#212738] rounded-xl p-5 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-[#212738] pb-3">
                  <div className="flex items-center space-x-3">
                    <span className="font-bold text-sky-400">{p.proposalUuid}</span>
                    <span className="text-slate-400">{p.actionName} ({p.actionCode})</span>
                    <span className="text-amber-300">Target: {p.targetIdentifier}</span>
                  </div>
                  <span className="px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold flex items-center space-x-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>INDEPENDENTLY VERIFIED</span>
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-4 text-slate-300">
                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase">Expected Outcome</span>
                    <p className="bg-[#0c0e15] p-2.5 rounded border border-[#212738] text-slate-300">
                      {p.verification?.expectedOutcome}
                    </p>
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-500 uppercase">Observed Outcome</span>
                    <p className="bg-[#0c0e15] p-2.5 rounded border border-[#212738] text-emerald-400">
                      {p.verification?.observedOutcome}
                    </p>
                  </div>
                </div>
                {p.verification?.evidencePayload && (
                  <div className="space-y-1 pt-2">
                    <span className="text-[10px] text-slate-500 uppercase">Cryptographic Evidence Payload</span>
                    <pre className="p-2.5 bg-[#0c0e15] rounded border border-[#212738] text-[11px] text-slate-400 overflow-x-auto font-mono">
                      {p.verification.evidencePayload}
                    </pre>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* New Proposal & Policy Preview Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#11141d] border border-[#212738] rounded-xl max-w-xl w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#212738] pb-3">
              <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center space-x-2">
                <Play className="w-4 h-4 text-indigo-400" />
                <span>Create Response Proposal with Policy Preview</span>
              </h3>
              <button onClick={() => setShowModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateProposal} className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Select Response Action</label>
                <select
                  value={selectedAction}
                  onChange={(e) => { setSelectedAction(e.target.value); setPolicyPreview(null); }}
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-sky-500"
                >
                  {catalog.map((act) => (
                    <option key={act.actionCode} value={act.actionCode}>
                      {act.actionCode} — {act.name} ({act.riskLevel})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Target Identifier (IP, Username, or Host)</label>
                <input
                  type="text"
                  value={targetIdentifier}
                  onChange={(e) => { setTargetIdentifier(e.target.value); setPolicyPreview(null); }}
                  placeholder="e.g. 198.51.100.24, CORP\\analyst, WIN-PROD-01"
                  required
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Associated Incident ID (Optional)</label>
                <input
                  type="number"
                  value={incidentId || ''}
                  onChange={(e) => setIncidentId(e.target.value ? Number(e.target.value) : undefined)}
                  placeholder="e.g. 1"
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-sky-500"
                />
              </div>

              {/* Policy Preview Section */}
              <div className="p-3 bg-[#0c0e15] border border-[#212738] rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-slate-400 uppercase">Policy Pre-Flight Evaluation</span>
                  <button
                    type="button"
                    onClick={handlePreviewPolicy}
                    disabled={previewLoading || !targetIdentifier}
                    className="px-2.5 py-1 rounded bg-[#1e293b] hover:bg-[#283548] text-sky-400 text-[10px] transition border border-sky-500/20"
                  >
                    {previewLoading ? 'Evaluating...' : 'Run Policy Preview'}
                  </button>
                </div>

                {policyPreview && (
                  <div className="space-y-1.5 pt-2 border-t border-[#212738]">
                    <div className="flex items-center space-x-2">
                      <span className="text-[10px] text-slate-400">Outcome:</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${policyPreview.outcome === 'ALLOW' ? 'bg-emerald-500/20 text-emerald-300' : policyPreview.outcome === 'REQUIRE_APPROVAL' ? 'bg-amber-500/20 text-amber-300' : 'bg-rose-500/20 text-rose-300'}`}>
                        {policyPreview.outcome}
                      </span>
                      {getRiskBadge(policyPreview.riskLevel)}
                    </div>
                    <p className="text-[11px] text-slate-300">{policyPreview.reason}</p>
                    {policyPreview.isSeparationOfDutiesRequired && (
                      <p className="text-[10px] text-amber-400 flex items-center space-x-1">
                        <Lock className="w-3 h-3" />
                        <span>Separation of Duties Required: Proposer cannot approve this action.</span>
                      </p>
                    )}
                    {policyPreview.policyViolations?.length > 0 && (
                      <div className="text-[10px] text-rose-400 space-y-0.5">
                        {policyPreview.policyViolations.map((v, idx) => (
                          <div key={idx}>⚠️ {v}</div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-[#212738]">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-lg bg-[#1e293b] hover:bg-[#283548] text-slate-300 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={Boolean(submitting || (policyPreview && policyPreview.outcome === 'DENY'))}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold transition disabled:opacity-50"
                >
                  {submitting ? 'Registering...' : 'Register Response Proposal'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Verification Evidence Drawer Modal */}
      {selectedVerification && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#11141d] border border-[#212738] rounded-xl max-w-xl w-full p-6 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between border-b border-[#212738] pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <FileCheck className="w-4 h-4 text-emerald-400" />
                <span>Independent Verification Evidence ({selectedVerification.verificationUuid})</span>
              </h3>
              <button onClick={() => setSelectedVerification(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-3">
              <div>
                <span className="text-[10px] text-slate-500 uppercase">Verification Method</span>
                <p className="text-slate-200 font-bold">{selectedVerification.verificationMethod}</p>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase">Expected Outcome</span>
                <p className="bg-[#0c0e15] p-2.5 rounded border border-[#212738] text-slate-300">
                  {selectedVerification.expectedOutcome}
                </p>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase">Observed Outcome</span>
                <p className="bg-[#0c0e15] p-2.5 rounded border border-[#212738] text-emerald-400 font-semibold">
                  {selectedVerification.observedOutcome}
                </p>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase">Cryptographic Audit Evidence</span>
                <pre className="p-3 bg-[#0c0e15] rounded border border-[#212738] text-[11px] text-slate-300 overflow-x-auto">
                  {selectedVerification.evidencePayload}
                </pre>
              </div>
            </div>
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedVerification(null)}
                className="px-4 py-2 rounded-lg bg-[#1e293b] hover:bg-[#283548] text-slate-300"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
