import React, { useEffect, useState } from 'react';
import {
  Radio,
  Search,
  Plus,
  Upload,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Trash2,
  ExternalLink
} from 'lucide-react';
import { api } from '../services/api';
import { IocIndicator, IocMatch } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { useAuth } from '../context/AuthContext';

export const ThreatIntelPage: React.FC = () => {
  const { isAdmin } = useAuth();
  const [iocs, setIocs] = useState<IocIndicator[]>([]);
  const [matches, setMatches] = useState<IocMatch[]>([]);
  const [activeTab, setActiveTab] = useState<'INDICATORS' | 'MATCHES'>('INDICATORS');
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedType, setSelectedType] = useState('');

  // Modals
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [csvContent, setCsvContent] = useState('');

  // New IOC Form State
  const [val, setVal] = useState('');
  const [type, setType] = useState<'IP' | 'DOMAIN' | 'URL' | 'MD5' | 'SHA256'>('IP');
  const [source, setSource] = useState('INTERNAL_SOC');
  const [confidence, setConfidence] = useState(85);
  const [severity, setSeverity] = useState('HIGH');
  const [description, setDescription] = useState('');

  const loadIocs = async () => {
    try {
      setLoading(true);
      const [iocList, matchList] = await Promise.all([api.getIocs(), api.getIocMatches()]);
      setIocs(iocList || []);
      setMatches(matchList || []);
    } catch (err) {
      console.error('Failed to load IOC threat intelligence:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIocs();
  }, []);

  const handleCreateIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createIoc({
        indicatorValue: val,
        indicatorType: type,
        source,
        confidence,
        severity,
        description,
      });
      setShowCreateModal(false);
      setVal('');
      setDescription('');
      await loadIocs();
    } catch (err: any) {
      alert(err.message || 'Failed to create IOC');
    }
  };

  const handleImportCsv = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await api.importIocsCsv(csvContent);
      alert(`Import complete! Imported: ${res.imported}, Skipped: ${res.skipped}`);
      setShowImportModal(false);
      setCsvContent('');
      await loadIocs();
    } catch (err: any) {
      alert(err.message || 'Failed to import CSV');
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to remove this indicator?')) return;
    try {
      await api.deleteIoc(id);
      await loadIocs();
    } catch (err: any) {
      alert(err.message || 'Failed to delete IOC');
    }
  };

  const filtered = iocs.filter(
    (i) =>
      (selectedType === '' || i.indicatorType === selectedType) &&
      (i.indicatorValue.toLowerCase().includes(search.toLowerCase()) ||
        i.source.toLowerCase().includes(search.toLowerCase()) ||
        (i.description && i.description.toLowerCase().includes(search.toLowerCase())))
  );

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Tab Switcher */}
      <div className="flex border-b border-[#212738] space-x-2">
        <button
          onClick={() => setActiveTab('INDICATORS')}
          className={`pb-3 px-4 text-xs font-mono font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'INDICATORS'
              ? 'border-sky-500 text-sky-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Radio className="w-4 h-4" />
          <span>Active Threat Indicators ({iocs.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('MATCHES')}
          className={`pb-3 px-4 text-xs font-mono font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'MATCHES'
              ? 'border-sky-500 text-sky-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          <span>Live Telemetry Matches ({matches.length})</span>
        </button>
      </div>

      {activeTab === 'INDICATORS' ? (
        <>
          {/* Header and Controls */}
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[#11141d] border border-[#212738] p-4 rounded-md">
            <div className="flex items-center space-x-3 w-full sm:w-auto">
              <div className="relative w-full sm:w-72">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="text"
                  placeholder="Search IOCs, domains, hashes..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
                />
              </div>

              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="bg-[#0c0e15] border border-[#212738] rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-mono"
              >
                <option value="">All Types</option>
                <option value="IP">IP Address</option>
                <option value="DOMAIN">Domain</option>
                <option value="URL">URL</option>
                <option value="SHA256">SHA256</option>
                <option value="MD5">MD5</option>
              </select>
            </div>

            <div className="flex items-center space-x-3 w-full sm:w-auto justify-end">
              <button
                onClick={loadIocs}
                title="Refresh"
                className="p-2 bg-[#0c0e15] hover:bg-[#181d2a] border border-[#212738] rounded text-slate-400 hover:text-slate-200 transition"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-sky-400' : ''}`} />
              </button>
              <button
                onClick={() => setShowImportModal(true)}
                className="bg-[#0c0e15] hover:bg-[#181d2a] border border-[#212738] text-slate-200 font-mono text-xs px-3 py-1.5 rounded flex items-center space-x-1.5 transition"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Import CSV</span>
              </button>
              <button
                onClick={() => setShowCreateModal(true)}
                className="bg-sky-600 hover:bg-sky-500 text-white font-mono font-medium text-xs px-3 py-1.5 rounded flex items-center space-x-1.5 transition"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Indicator</span>
              </button>
            </div>
          </div>

          {/* Main IOC Table */}
          <div className="bg-[#11141d] border border-[#212738] rounded-md overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#171b26] text-slate-400 uppercase font-mono text-[10px] border-b border-[#212738]">
                  <tr>
                    <th className="py-2.5 px-4">Indicator Value</th>
                    <th className="py-2.5 px-4">Type</th>
                    <th className="py-2.5 px-4">Confidence</th>
                    <th className="py-2.5 px-4">Severity</th>
                    <th className="py-2.5 px-4">Source Provenance</th>
                    <th className="py-2.5 px-4">Status</th>
                    {isAdmin && <th className="py-2.5 px-4 text-right">Actions</th>}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#212738]">
                  {filtered.length > 0 ? (
                    filtered.map((ioc) => (
                      <tr key={ioc.id} className="hover:bg-[#181d2a] transition-colors">
                        <td className="py-3 px-4 font-mono font-semibold text-sky-400 break-all max-w-xs">
                          {ioc.indicatorValue}
                        </td>
                        <td className="py-3 px-4">
                          <span className="font-mono text-slate-300 bg-[#0c0e15] border border-[#212738] px-2 py-0.5 rounded text-[11px]">
                            {ioc.indicatorType}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono">
                          <span className="text-emerald-400 font-bold">{ioc.confidence}%</span>
                        </td>
                        <td className="py-3 px-4">
                          <SeverityBadge severity={ioc.severity} />
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-300">{ioc.source}</td>
                        <td className="py-3.5 px-4">
                          <StatusBadge status={ioc.status} />
                        </td>
                        {isAdmin && (
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => handleDelete(ioc.id)}
                              className="text-rose-400 hover:text-rose-300 p-1 rounded"
                              title="Delete indicator"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        )}
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-slate-500 font-mono text-xs">
                        No threat intelligence indicators found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : (
        /* Matches Table */
        <div className="bg-[#11141d] border border-[#212738] rounded-md overflow-hidden space-y-4">
          <div className="p-4 bg-[#171b26] border-b border-[#212738] flex justify-between items-center">
            <div>
              <h3 className="text-xs font-bold font-mono uppercase text-slate-100 flex items-center space-x-2 tracking-wider">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Threat Intelligence Ingestion Matches</span>
              </h3>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                Evaluated against AlienVault OTX, CISA KEV, and custom indicators
              </p>
            </div>
            <button
              onClick={loadIocs}
              title="Refresh"
              className="p-1.5 bg-[#0c0e15] hover:bg-[#181d2a] border border-[#212738] rounded text-slate-400 hover:text-slate-200 transition"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-sky-400' : ''}`} />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#171b26] text-slate-400 uppercase font-mono text-[10px] border-b border-[#212738]">
                <tr>
                  <th className="py-2.5 px-4">Matched Value</th>
                  <th className="py-2.5 px-4">Telemetry Field</th>
                  <th className="py-2.5 px-4">Target Hostname</th>
                  <th className="py-2.5 px-4">Event Timestamp</th>
                  <th className="py-2.5 px-4">Doc Reference</th>
                  <th className="py-2.5 px-4">Incident Link</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#212738]">
                {matches.length > 0 ? (
                  matches.map((m) => (
                    <tr key={m.id} className="hover:bg-[#181d2a] transition-colors">
                      <td className="py-3 px-4 font-mono font-semibold text-rose-400 break-all">
                        {m.matchedValue}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        <span className="bg-[#0c0e15] border border-[#212738] px-2 py-0.5 rounded text-[11px]">
                          {m.matchedField}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-200">
                        {m.assetHostname || 'Endpoint Asset'}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {new Date(m.eventTimestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                        {m.opensearchDocId || 'telemetry-stream'}
                      </td>
                      <td className="py-3 px-4 font-mono">
                        {m.incidentId ? (
                          <span className="text-sky-400 font-semibold">INC-{m.incidentId}</span>
                        ) : (
                          <span className="text-slate-500">Unlinked</span>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-500 font-mono text-xs">
                      No telemetry events have matched active threat intelligence indicators yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#11141d] border border-[#212738] rounded-md max-w-md w-full p-5 space-y-4 shadow-2xl">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-100 flex items-center space-x-2">
              <Radio className="w-4 h-4 text-sky-400" />
              <span>Add Threat Intelligence Indicator</span>
            </h3>

            <form onSubmit={handleCreateIoc} className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">Indicator Value *</label>
                <input
                  type="text"
                  required
                  placeholder="198.51.100.24 or evil-corp.blueops.lab"
                  value={val}
                  onChange={(e) => setVal(e.target.value)}
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">Type *</label>
                  <select
                    value={type}
                    onChange={(e) => setType(e.target.value as any)}
                    className="w-full bg-[#0c0e15] border border-[#212738] rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
                  >
                    <option value="IP">IP Address</option>
                    <option value="DOMAIN">Domain</option>
                    <option value="URL">URL</option>
                    <option value="SHA256">SHA256 Hash</option>
                    <option value="MD5">MD5 Hash</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">Confidence (0-100) *</label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    required
                    value={confidence}
                    onChange={(e) => setConfidence(parseInt(e.target.value) || 0)}
                    className="w-full bg-[#0c0e15] border border-[#212738] rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">Source Provenance</label>
                  <input
                    type="text"
                    required
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                    className="w-full bg-[#0c0e15] border border-[#212738] rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">Severity *</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="w-full bg-[#0c0e15] border border-[#212738] rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">Threat Context / Attribution</label>
                <textarea
                  rows={2}
                  placeholder="e.g., C2 infrastructure observed in BAS validation test..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full bg-[#0c0e15] border border-[#212738] rounded px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-sky-500 font-mono"
                />
              </div>

              <div className="flex justify-end space-x-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 bg-[#0c0e15] hover:bg-[#181d2a] text-slate-400 hover:text-slate-200 text-xs font-mono rounded border border-[#212738]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-mono font-medium rounded transition"
                >
                  Register Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CSV Import Modal */}
      {showImportModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#11141d] border border-[#212738] rounded-md max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-100 flex items-center space-x-2">
              <Upload className="w-4 h-4 text-sky-400" />
              <span>Import Indicators via CSV</span>
            </h3>

            <p className="text-xs text-slate-400 font-mono">
              Format: <code className="font-mono text-sky-300">indicator_value,indicator_type,source,confidence,severity</code>
            </p>

            <form onSubmit={handleImportCsv} className="space-y-4">
              <textarea
                rows={6}
                required
                placeholder="198.51.100.24,IP,CISA,90,CRITICAL&#10;evil-corp.blueops.lab,DOMAIN,OTX,85,HIGH"
                value={csvContent}
                onChange={(e) => setCsvContent(e.target.value)}
                className="w-full bg-[#0c0e15] border border-[#212738] rounded p-3 text-xs text-slate-100 font-mono focus:outline-none focus:border-sky-500"
              />

              <div className="flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowImportModal(false)}
                  className="px-3 py-1.5 bg-[#0c0e15] hover:bg-[#181d2a] text-slate-400 hover:text-slate-200 text-xs font-mono rounded border border-[#212738]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-mono font-medium rounded transition"
                >
                  Import Indicators
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
