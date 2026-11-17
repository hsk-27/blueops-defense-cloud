import React, { useEffect, useState } from 'react';
import { Binary, Search, RefreshCw, FileCode, CheckCircle2, XCircle, AlertTriangle, Grid, List } from 'lucide-react';
import { api } from '../services/api';
import { DetectionRule } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { useAuth } from '../context/AuthContext';

const MITRE_TACTICS = [
  { id: 'Initial Access', label: 'Initial Access', techniques: ['T1078'] },
  { id: 'Execution', label: 'Execution', techniques: ['T1059', 'T1059.001'] },
  { id: 'Persistence', label: 'Persistence', techniques: ['T1053.003', 'T1053.005', 'T1136.001', 'T1543.002', 'T1543.003', 'T1547.001', 'T1569.002'] },
  { id: 'Privilege Escalation', label: 'Privilege Escalation', techniques: ['T1548.003'] },
  { id: 'Defense Evasion', label: 'Defense Evasion', techniques: ['T1036', 'T1070.001', 'T1562.001', 'T1562.002'] },
  { id: 'Credential Access', label: 'Credential Access', techniques: ['T1003.001', 'T1110', 'T1110.001', 'T1110.003'] },
  { id: 'Discovery', label: 'Discovery', techniques: ['T1082', 'T1087'] },
  { id: 'Command and Control', label: 'Command & Control', techniques: ['T1071', 'T1071.001'] },
  { id: 'Impact', label: 'Impact', techniques: ['T1565.001'] }
];

export const DetectionManagementPage: React.FC = () => {
  const { isAdmin } = useAuth();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedSource, setSelectedSource] = useState('');
  const [viewMode, setViewMode] = useState<'table' | 'matrix'>('table');
  const [inspectRule, setInspectRule] = useState<DetectionRule | null>(null);
  const [reloadingSigma, setReloadingSigma] = useState(false);

  const loadRules = async () => {
    try {
      setLoading(true);
      const data = await api.getDetections();
      setRules(data || []);
    } catch (err) {
      console.error('Failed to load detection rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleToggleStatus = async (rule: DetectionRule) => {
    if (!isAdmin) {
      alert('Only administrators can modify detection rule states.');
      return;
    }
    const nextStatus = rule.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE';
    try {
      await api.updateDetectionStatus(rule.id, nextStatus);
      await loadRules();
    } catch (err: any) {
      alert(err.message || 'Failed to update rule status');
    }
  };

  const handleReloadSigma = async () => {
    try {
      setReloadingSigma(true);
      const res = await api.reloadSigmaRules();
      alert(`Dynamic Sigma Engine: Successfully reloaded ${res.reloadedCount} Sigma YAML rules from disk!`);
      await loadRules();
    } catch (err: any) {
      alert(err.message || 'Failed to reload Sigma rules');
    } finally {
      setReloadingSigma(false);
    }
  };

  const filtered = rules.filter(
    (r) =>
      (selectedSource === '' || r.logSource.includes(selectedSource)) &&
      (r.name.toLowerCase().includes(search.toLowerCase()) ||
        r.ruleCode.toLowerCase().includes(search.toLowerCase()) ||
        r.mitreTactic.toLowerCase().includes(search.toLowerCase()) ||
        r.mitreTechniqueId.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[#11141d] border border-[#212738] p-4 rounded-md">
        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Search Sigma rules, techniques, tactics..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-[#0c0e15] border border-[#212738] rounded pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>

          <select
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            className="bg-[#0c0e15] border border-[#212738] rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-mono"
          >
            <option value="">All Log Sources</option>
            <option value="windows">Windows Sysmon</option>
            <option value="linux">Linux auditd/journald</option>
            <option value="suricata">Suricata NIDS</option>
          </select>
        </div>

        <div className="flex items-center space-x-2">
          <div className="flex bg-[#0c0e15] border border-[#212738] rounded p-0.5 font-mono">
            <button
              onClick={() => setViewMode('table')}
              className={`flex items-center space-x-1.5 px-3 py-1 rounded text-xs font-medium transition ${
                viewMode === 'table' ? 'bg-[#181d2a] text-sky-400 border border-[#2b354c]' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <List className="w-3.5 h-3.5" />
              <span>Rules Table</span>
            </button>
            <button
              onClick={() => setViewMode('matrix')}
              className={`flex items-center space-x-1.5 px-3 py-1 rounded text-xs font-medium transition ${
                viewMode === 'matrix' ? 'bg-[#181d2a] text-sky-400 border border-[#2b354c]' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Grid className="w-3.5 h-3.5" />
              <span>ATT&CK Matrix</span>
            </button>
          </div>

          {isAdmin && (
            <button
              onClick={handleReloadSigma}
              disabled={reloadingSigma}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-sky-950/70 hover:bg-sky-900/90 border border-sky-700/60 text-sky-300 hover:text-sky-100 rounded text-xs font-mono transition"
              title="Reload all Sigma YAML files from disk dynamically"
            >
              <FileCode className={`w-3.5 h-3.5 ${reloadingSigma ? 'animate-spin' : ''}`} />
              <span>{reloadingSigma ? 'Reloading...' : 'Reload Sigma YAML'}</span>
            </button>
          )}

          <button
            onClick={loadRules}
            title="Refresh"
            className="p-2 bg-[#0c0e15] hover:bg-[#181d2a] border border-[#212738] rounded text-slate-400 hover:text-slate-200 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* View Mode 1: Rules Table */}
      {viewMode === 'table' && (
        <div className="bg-[#11141d] border border-[#212738] rounded-md overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#171b26] text-slate-400 uppercase font-mono text-[10px] border-b border-[#212738]">
                <tr>
                  <th className="py-2.5 px-4">Rule Code</th>
                  <th className="py-2.5 px-4">Detection Title</th>
                  <th className="py-2.5 px-4">Log Source</th>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4">MITRE ATT&CK</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#212738]">
                {filtered.length > 0 ? (
                  filtered.map((r) => (
                    <tr key={r.id} className="hover:bg-[#181d2a] transition-colors">
                      <td className="py-3 px-4 font-mono font-bold text-sky-400">{r.ruleCode}</td>
                      <td className="py-3 px-4 max-w-sm">
                        <p className="font-semibold text-slate-100 truncate">{r.name}</p>
                        <p className="text-[11px] text-slate-400 truncate mt-0.5">{r.description}</p>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">{r.logSource}</td>
                      <td className="py-3 px-4">
                        <SeverityBadge severity={r.severity} />
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-col space-y-0.5">
                          <span className="font-mono text-sky-400 font-semibold">{r.mitreTechniqueId}</span>
                          <span className="text-[11px] text-slate-400">{r.mitreTactic}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <button
                          onClick={() => handleToggleStatus(r)}
                          className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider transition ${
                            r.status === 'ACTIVE'
                              ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/80 hover:bg-emerald-900'
                              : 'bg-zinc-800 text-zinc-400 border border-zinc-700 hover:bg-zinc-700'
                          }`}
                        >
                          {r.status === 'ACTIVE' ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                          <span>{r.status}</span>
                        </button>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setInspectRule(r)}
                          className="text-sky-400 hover:text-sky-300 font-mono text-[11px] font-medium inline-flex items-center space-x-1"
                        >
                          <FileCode className="w-3.5 h-3.5" />
                          <span>Inspect Sigma</span>
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500 font-mono text-xs">
                      No matching detection rules found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* View Mode 2: MITRE ATT&CK Matrix Interactive Heatmap */}
      {viewMode === 'matrix' && (
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-5 space-y-5">
          <div>
            <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-100 flex items-center space-x-2">
              <Grid className="w-4 h-4 text-sky-400" />
              <span>MITRE ATT&CK Matrix Navigator</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Deterministic rule coverage mapping across Sigma detection rules (D001 - D018).
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {MITRE_TACTICS.map((tactic) => {
              const matchedRules = rules.filter(
                (r) => r.mitreTactic.toLowerCase() === tactic.id.toLowerCase() || tactic.techniques.includes(r.mitreTechniqueId)
              );

              return (
                <div key={tactic.id} className="bg-[#0c0e15] border border-[#212738] rounded p-3 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between pb-2 border-b border-[#212738]">
                      <span className="font-bold text-xs text-slate-200 font-mono">{tactic.label}</span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold ${
                        matchedRules.length > 0 ? 'bg-sky-950/60 text-sky-400 border border-sky-800/60' : 'bg-[#11141d] text-slate-500'
                      }`}>
                        {matchedRules.length} rules
                      </span>
                    </div>

                    <div className="mt-2.5 space-y-2">
                      {matchedRules.length > 0 ? (
                        matchedRules.map((mr) => (
                          <div
                            key={mr.id}
                            onClick={() => setInspectRule(mr)}
                            className="p-2 bg-[#11141d] hover:bg-[#181d2a] border border-[#212738] rounded cursor-pointer transition text-xs"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-mono font-bold text-sky-400">{mr.ruleCode}</span>
                              <span className="font-mono text-[10px] text-slate-400">{mr.mitreTechniqueId}</span>
                            </div>
                            <p className="text-slate-200 font-medium truncate mt-1 text-[11px]">{mr.name}</p>
                          </div>
                        ))
                      ) : (
                        <div className="py-4 text-center text-slate-600 text-xs italic font-mono">
                          Planned coverage
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Inspect Sigma Modal */}
      {inspectRule && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#11141d] border border-[#212738] rounded-md max-w-2xl w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#212738] pb-3">
              <div>
                <span className="font-mono text-xs text-sky-400 font-bold">{inspectRule.ruleCode}</span>
                <h3 className="text-sm font-bold text-slate-100 font-mono">{inspectRule.name}</h3>
              </div>
              <button
                onClick={() => setInspectRule(null)}
                className="text-slate-400 hover:text-slate-200 text-xs font-mono"
              >
                CLOSE
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Detection Query DSL (OpenSearch):</span>
                <pre className="mt-1 p-2.5 bg-[#0c0e15] border border-[#212738] rounded text-xs font-mono text-emerald-400 overflow-x-auto">
                  {inspectRule.queryDsl}
                </pre>
              </div>

              {inspectRule.sigmaYaml && (
                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Sigma YAML Specification:</span>
                  <pre className="mt-1 p-2.5 bg-[#0c0e15] border border-[#212738] rounded text-xs font-mono text-slate-200 overflow-x-auto max-h-48">
                    {inspectRule.sigmaYaml}
                  </pre>
                </div>
              )}

              {inspectRule.falsePositives && (
                <div>
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Known False Positives:</span>
                  <p className="mt-1 text-xs text-slate-400 bg-[#0c0e15] border border-[#212738] p-2.5 rounded font-mono">
                    {inspectRule.falsePositives}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
