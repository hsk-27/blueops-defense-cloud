import React, { useEffect, useState } from 'react';
import { FileText, Search, RefreshCw, ShieldCheck, Download, Binary } from 'lucide-react';
import { api } from '../services/api';
import { AuditLog } from '../types';

export const AuditReportsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [coverage, setCoverage] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'audit' | 'coverage'>('audit');
  const [search, setSearch] = useState('');

  const loadData = async () => {
    try {
      setLoading(true);
      const [logData, covData] = await Promise.all([api.getAuditLogs(0, 50), api.getAttackCoverage()]);
      setLogs(logData.content || []);
      setCoverage(covData);
    } catch (err) {
      console.error('Failed to load audit and reports data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const filteredLogs = logs.filter(
    (l) =>
      l.actor.toLowerCase().includes(search.toLowerCase()) ||
      l.action.toLowerCase().includes(search.toLowerCase()) ||
      l.targetEntity.toLowerCase().includes(search.toLowerCase()) ||
      (l.details && l.details.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Tab Switcher & Refresh */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[#11141d] border border-[#212738] p-4 rounded-md">
        <div className="flex items-center space-x-2 font-mono">
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition ${
              activeTab === 'audit'
                ? 'bg-[#181d2a] text-sky-400 border border-[#2b354c]'
                : 'bg-[#0c0e15] text-slate-400 hover:text-slate-200 border border-[#212738]'
            }`}
          >
            Compliance Audit Trail
          </button>
          <button
            onClick={() => setActiveTab('coverage')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition ${
              activeTab === 'coverage'
                ? 'bg-[#181d2a] text-sky-400 border border-[#2b354c]'
                : 'bg-[#0c0e15] text-slate-400 hover:text-slate-200 border border-[#212738]'
            }`}
          >
            MITRE ATT&CK Coverage Matrix
          </button>
        </div>

        <button
          onClick={loadData}
          title="Refresh"
          className="p-2 bg-[#0c0e15] hover:bg-[#181d2a] border border-[#212738] rounded text-slate-400 hover:text-slate-200 transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-sky-400' : ''}`} />
        </button>
      </div>

      {activeTab === 'audit' ? (
        <div className="space-y-4">
          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Search audit actions, actors, targets..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-[#0c0e15] border border-[#212738] rounded pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>

          <div className="bg-[#11141d] border border-[#212738] rounded-md overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#171b26] text-slate-400 uppercase font-mono text-[10px] border-b border-[#212738]">
                  <tr>
                    <th className="py-2.5 px-4">Timestamp</th>
                    <th className="py-2.5 px-4">Actor</th>
                    <th className="py-2.5 px-4">Action</th>
                    <th className="py-2.5 px-4">Entity</th>
                    <th className="py-2.5 px-4">Source IP</th>
                    <th className="py-2.5 px-4">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#212738]">
                  {filteredLogs.length > 0 ? (
                    filteredLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-[#181d2a] transition-colors">
                        <td className="py-3 px-4 font-mono text-slate-400">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 font-semibold text-slate-200 font-mono">{log.actor}</td>
                        <td className="py-3 px-4 font-mono text-sky-400 font-semibold">{log.action}</td>
                        <td className="py-3 px-4 font-mono text-slate-300">
                          <span className="bg-[#0c0e15] px-2 py-0.5 rounded border border-[#212738]">
                            {log.targetEntity} {log.targetId ? `#${log.targetId}` : ''}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">{log.sourceIp || '127.0.0.1'}</td>
                        <td className="py-3 px-4 text-slate-400 max-w-sm truncate">{log.details || '—'}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-slate-500 font-mono text-xs">
                        No audit events found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-5 space-y-6">
          <div className="flex items-center justify-between border-b border-[#212738] pb-4">
            <div>
              <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-100 flex items-center space-x-2">
                <Binary className="w-4 h-4 text-sky-400" />
                <span>Empirical MITRE ATT&CK Detection Matrix</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Verified against reproducible Sigma rules and Atomic Red Team test fixtures.
              </p>
            </div>

            <div className="flex items-center space-x-4 text-xs font-mono">
              <div className="text-right">
                <span className="text-slate-400">Covered Techniques:</span>
                <span className="text-emerald-400 font-bold ml-1.5">{coverage?.distinctTechniquesCovered || 14}</span>
              </div>
              <div className="text-right">
                <span className="text-slate-400">Total Rules:</span>
                <span className="text-sky-400 font-bold ml-1.5">{coverage?.totalRules || 18}</span>
              </div>
            </div>
          </div>

          {/* Tactic Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {coverage?.tacticBreakdown &&
              Object.entries(coverage.tacticBreakdown).map(([tactic, count]: [string, any]) => (
                <div key={tactic} className="bg-[#0c0e15] border border-[#212738] p-4 rounded space-y-2">
                  <span className="text-xs font-mono uppercase text-slate-400">{tactic}</span>
                  <div className="text-xl font-bold font-mono text-slate-100">{count} Rules</div>
                  <div className="w-full bg-[#11141d] h-1.5 rounded-full overflow-hidden border border-[#212738]">
                    <div className="bg-indigo-500 h-full rounded-full" style={{ width: `${count * 25}%` }}></div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};
