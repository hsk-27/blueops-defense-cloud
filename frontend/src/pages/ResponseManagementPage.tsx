import React, { useEffect, useState } from 'react';
import {
  Zap,
  ShieldCheck,
  RotateCcw,
  RefreshCw,
  AlertOctagon,
  CheckCircle2,
  Clock,
  Play
} from 'lucide-react';
import { api } from '../services/api';
import { ResponsePlaybook, ResponseAction, ResponseExecution } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { useAuth } from '../context/AuthContext';

export const ResponseManagementPage: React.FC<{
  initialPlaybook?: string;
  initialTarget?: string;
  initialIncidentId?: number;
}> = ({ initialPlaybook, initialTarget, initialIncidentId }) => {
  const { isAdmin } = useAuth();
  const [playbooks, setPlaybooks] = useState<ResponsePlaybook[]>([]);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [executions, setExecutions] = useState<ResponseExecution[]>([]);
  const [loading, setLoading] = useState(true);

  // New action modal
  const [showRequestModal, setShowRequestModal] = useState(!!initialPlaybook);
  const [selectedPlaybook, setSelectedPlaybook] = useState(initialPlaybook || 'P001');
  const [targetIdent, setTargetIdent] = useState(initialTarget || '198.51.100.24');
  const [incidentId, setIncidentId] = useState<number | undefined>(initialIncidentId);
  const [simulation, setSimulation] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const [pbList, actList, execList] = await Promise.all([
        api.getPlaybooks(),
        api.getActions(),
        api.getExecutions(),
      ]);
      setPlaybooks(pbList || []);
      setActions(actList || []);
      setExecutions(execList || []);
    } catch (err) {
      console.error('Failed to load response management:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRequestAction = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.requestAction({
        playbookCode: selectedPlaybook,
        targetIdentifier: targetIdent,
        incidentId,
        simulation,
      });
      setShowRequestModal(false);
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to submit response request');
    }
  };

  const handleApprove = async (id: number) => {
    try {
      await api.approveAction(id);
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to approve action');
    }
  };

  const handleReject = async (id: number) => {
    const reason = prompt('Reason for rejecting action:') || 'Analyst rejected action';
    try {
      await api.rejectAction(id, reason);
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to reject action');
    }
  };

  const handleRollback = async (id: number) => {
    if (!confirm('Execute reversal / rollback playbook for this action?')) return;
    try {
      await api.rollbackAction(id);
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to rollback action');
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Simulation Banner */}
      <div className="bg-blue-950/40 border border-blue-800/60 p-4 rounded-xl flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-500/20 text-blue-400 rounded-lg">
            <Zap className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono">
              Constrained Response Orchestration Mode: ACTIVE
            </h4>
            <p className="text-xs text-slate-400 mt-0.5">
              All playbooks require HMAC-SHA256 authorization and adhere to strict lab allowlisting (no arbitrary shell execution).
            </p>
          </div>
        </div>

        <button
          onClick={() => setShowRequestModal(true)}
          className="bg-indigo-600 hover:bg-indigo-500 text-white font-mono text-xs px-3 py-1.5 rounded flex items-center space-x-1.5 transition shrink-0"
        >
          <Play className="w-3.5 h-3.5" />
          <span>Trigger Playbook</span>
        </button>
      </div>

      {/* Available Playbooks Grid */}
      <div>
        <h3 className="text-xs font-mono uppercase text-slate-400 tracking-wider mb-3">Orchestrated SecOps Playbooks</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {playbooks.map((pb) => (
            <div key={pb.id} className="bg-[#11141d] border border-[#212738] rounded-md p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-sky-400">{pb.playbookCode}</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 bg-[#0c0e15] border border-[#212738] text-slate-400 rounded uppercase">
                  {pb.actionType}
                </span>
              </div>
              <h4 className="text-xs font-bold text-slate-100 font-mono">{pb.name}</h4>
              <p className="text-[11px] text-slate-400 leading-relaxed">{pb.description}</p>
              <div className="pt-2 flex items-center justify-between text-[10px] font-mono text-slate-500">
                <span>Requires Approval: {pb.requiresApproval ? 'Yes' : 'Auto'}</span>
                <span>Rollback: {pb.rollbackSupported ? 'Supported' : 'No'}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Action Requests & Approvals Queue */}
      <div className="bg-[#11141d] border border-[#212738] rounded-md overflow-hidden">
        <div className="p-4 border-b border-[#212738] bg-[#171b26] flex items-center justify-between">
          <h3 className="text-xs font-bold font-mono uppercase text-slate-100 flex items-center space-x-2 tracking-wider">
            <Clock className="w-4 h-4 text-amber-400" />
            <span>Response Action Queue & Authorization Audit</span>
          </h3>
          <button onClick={loadData} title="Refresh">
            <RefreshCw className={`w-3.5 h-3.5 text-slate-400 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#171b26] text-slate-400 uppercase font-mono text-[10px] border-b border-[#212738]">
              <tr>
                <th className="py-2.5 px-4">Action UUID</th>
                <th className="py-2.5 px-4">Playbook</th>
                <th className="py-2.5 px-4">Target</th>
                <th className="py-2.5 px-4">Requested By</th>
                <th className="py-2.5 px-4">Approval Status</th>
                <th className="py-2.5 px-4">Execution Status</th>
                <th className="py-2.5 px-4">Mode</th>
                <th className="py-2.5 px-4 text-right">Action Controls</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#212738]">
              {actions.length > 0 ? (
                actions.map((act) => (
                  <tr key={act.id} className="hover:bg-[#181d2a] transition-colors">
                    <td className="py-3 px-4 font-mono text-sky-400 font-semibold">{act.actionUuid.slice(0, 8)}...</td>
                    <td className="py-3 px-4 font-mono text-slate-200 font-medium">{act.playbookCode}</td>
                    <td className="py-3 px-4 font-mono text-slate-300 font-medium">{act.targetIdentifier}</td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">{act.requestedBy}</td>
                    <td className="py-3 px-4">
                      <StatusBadge status={act.approvalStatus} />
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={act.executionStatus} />
                    </td>
                    <td className="py-3 px-4 font-mono text-[10px] text-sky-300">
                      {act.isSimulation ? 'SANDBOX' : 'PRODUCTION'}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      {act.approvalStatus === 'PENDING' && isAdmin && (
                        <>
                          <button
                            onClick={() => handleApprove(act.id)}
                            className="bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs px-2 py-0.5 rounded transition"
                          >
                            Approve
                          </button>
                          <button
                            onClick={() => handleReject(act.id)}
                            className="bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 font-mono text-xs px-2 py-0.5 rounded transition"
                          >
                            Reject
                          </button>
                        </>
                      )}

                      {act.executionStatus === 'SUCCEEDED' && (
                        <button
                          onClick={() => handleRollback(act.id)}
                          className="bg-purple-950/60 hover:bg-purple-900 border border-purple-800 text-purple-300 font-mono text-xs px-2 py-0.5 rounded inline-flex items-center space-x-1 transition"
                        >
                          <RotateCcw className="w-3 h-3" />
                          <span>Rollback</span>
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-mono text-xs">
                    No response actions logged.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Trigger Modal */}
      {showRequestModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#11141d] border border-[#212738] rounded-md max-w-md w-full p-5 space-y-4 shadow-2xl">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-100 flex items-center space-x-2">
              <Zap className="w-4 h-4 text-indigo-400" />
              <span>Trigger SecOps Response Playbook</span>
            </h3>

            <form onSubmit={handleRequestAction} className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">Select Playbook *</label>
                <select
                  value={selectedPlaybook}
                  onChange={(e) => setSelectedPlaybook(e.target.value)}
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
                >
                  {playbooks.length > 0 ? (
                    playbooks.map((pb) => (
                      <option key={pb.playbookCode} value={pb.playbookCode}>
                        {pb.playbookCode} — {pb.name} ({pb.targetType})
                      </option>
                    ))
                  ) : (
                    <>
                      <option value="P001">P001 — Block Malicious Egress IP</option>
                      <option value="P002">P002 — Revoke Compromised Credentials</option>
                      <option value="P003">P003 — Isolate Compromised Host</option>
                    </>
                  )}
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">Target Identifier (IP, Account, Host) *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.24, sec-analyst, or PROD-WIN-01"
                  value={targetIdent}
                  onChange={(e) => setTargetIdent(e.target.value)}
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
                />
              </div>

              <div className="flex items-center space-x-2 pt-1 font-mono">
                <input
                  type="checkbox"
                  id="simCheck"
                  checked={simulation}
                  onChange={(e) => setSimulation(e.target.checked)}
                  className="rounded bg-[#0c0e15] border-[#212738] text-indigo-600 focus:ring-0"
                />
                <label htmlFor="simCheck" className="text-[11px] text-slate-300">
                  Execute in Autonomous Sandbox (Safe dry-run verification)
                </label>
              </div>

              <div className="flex justify-end space-x-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowRequestModal(false)}
                  className="px-3 py-1.5 bg-[#0c0e15] hover:bg-[#181d2a] text-slate-400 hover:text-slate-200 text-xs font-mono rounded border border-[#212738]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-mono font-medium rounded transition"
                >
                  Request Playbook
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
