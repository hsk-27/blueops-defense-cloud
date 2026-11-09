import React, { useState, useEffect } from 'react';
import { 
  Activity, RefreshCw, Filter, Search, Terminal, Database, 
  ShieldAlert, CheckCircle2, AlertTriangle, Eye, Copy, X, Upload 
} from 'lucide-react';
import { api } from '../services/api';

export const LiveTelemetryPage: React.FC = () => {
  const [events, setEvents] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({ totalReceived: 0, totalNormalized: 0, bufferedCount: 0, dlqCount: 0 });
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [search, setSearch] = useState('');
  const [providerFilter, setProviderFilter] = useState('ALL');
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [customPayload, setCustomPayload] = useState('{\n  "provider": "Sysmon",\n  "hostname": "WIN-WORKSTATION-01",\n  "Image": "powershell.exe",\n  "CommandLine": "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="\n}');
  const [ingestStatus, setIngestStatus] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const fetchTelemetry = async () => {
    try {
      const [evts, st] = await Promise.all([
        api.getRecentTelemetry(50).catch(() => []),
        api.getTelemetryStats().catch(() => ({ totalReceived: 0, totalNormalized: 0, bufferedCount: 0, dlqCount: 0 }))
      ]);
      setEvents(evts || []);
      setStats(st || {});
    } catch (err) {
      console.error('Failed to load telemetry', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
    let interval: any = null;
    if (autoRefresh) {
      interval = setInterval(fetchTelemetry, 3000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh]);

  const handleCopyJson = () => {
    if (selectedEvent) {
      navigator.clipboard.writeText(JSON.stringify(selectedEvent, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleIngest = async () => {
    try {
      const parsed = JSON.parse(customPayload);
      setIngestStatus('Ingesting into pipeline...');
      const res = await api.ingestTelemetry(parsed);
      setIngestStatus(`Success: ${res.normalized} event(s) normalized, ${res.findingsGenerated} finding(s) generated.`);
      setTimeout(() => {
        setShowIngestModal(false);
        setIngestStatus(null);
        fetchTelemetry();
      }, 1500);
    } catch (err: any) {
      setIngestStatus(`Error: ${err.message}`);
    }
  };

  const filteredEvents = events.filter((ev) => {
    const provider = ev.event?.provider || '';
    if (providerFilter !== 'ALL' && !provider.toLowerCase().includes(providerFilter.toLowerCase())) {
      return false;
    }
    if (!search) return true;
    const s = search.toLowerCase();
    const host = ev.host?.name || '';
    const cmd = ev.process?.commandLine || '';
    const action = ev.event?.action || '';
    const user = ev.user?.name || '';
    const dst = ev.destination?.ip || '';
    return host.toLowerCase().includes(s) || cmd.toLowerCase().includes(s) || action.toLowerCase().includes(s) || user.toLowerCase().includes(s) || dst.includes(s);
  });

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#212738]">
        <div>
          <h1 className="text-xl font-bold font-mono uppercase tracking-wider text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-sky-400" />
            Live Telemetry Pipeline
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            High-throughput event normalization into Common Event Schema (CES v1.0.0)
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-medium border transition-colors ${
              autoRefresh
                ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-400'
                : 'bg-[#0c0e15] border-[#212738] text-slate-400'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${autoRefresh ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
            {autoRefresh ? 'STREAMING ACTIVE' : 'STREAM PAUSED'}
          </button>
          <button
            onClick={fetchTelemetry}
            className="p-1.5 bg-[#0c0e15] border border-[#212738] hover:border-slate-600 text-slate-300 rounded"
            title="Refresh now"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          </button>
          <button
            onClick={() => setShowIngestModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-mono font-medium transition"
          >
            <Upload className="w-3.5 h-3.5" />
            Ingest Telemetry
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Total Received</div>
          <div className="text-2xl font-bold text-white mt-1 font-mono">{stats.totalReceived || 0}</div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono">Raw events received</div>
        </div>
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Normalized (CES)</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono">{stats.totalNormalized || 0}</div>
          <div className="text-[11px] text-emerald-500/70 mt-0.5 font-mono">100% Schema Compliant</div>
        </div>
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Ring Buffer Store</div>
          <div className="text-2xl font-bold text-sky-400 mt-1 font-mono">{stats.bufferedCount || 0}</div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono">Capacity 1,000 in memory</div>
        </div>
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Dead-Letter Queue</div>
          <div className={`text-2xl font-bold mt-1 font-mono ${(stats.dlqCount || 0) > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
            {stats.dlqCount || 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono">Malformed / rejected events</div>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#11141d] p-3 rounded-md border border-[#212738]">
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-80">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search hostname, process, cmdline, IP, action..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-[#0c0e15] border border-[#212738] rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto font-mono">
          <span className="text-xs text-slate-400">Provider:</span>
          {['ALL', 'Sysmon', 'Linux-auditd', 'Suricata'].map((p) => (
            <button
              key={p}
              onClick={() => setProviderFilter(p)}
              className={`px-2.5 py-1 text-xs rounded font-medium border transition-colors ${
                providerFilter === p
                  ? 'bg-sky-950/60 border-sky-600 text-sky-400'
                  : 'bg-[#0c0e15] border-[#212738] text-slate-400 hover:border-slate-600'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-[#11141d] border border-[#212738] rounded-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#171b26] text-slate-400 font-mono text-[10px] border-b border-[#212738] uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Provider</th>
                <th className="py-2.5 px-4">Host / OS</th>
                <th className="py-2.5 px-4">Category</th>
                <th className="py-2.5 px-4">User</th>
                <th className="py-2.5 px-4">Activity Details</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#212738] text-slate-300">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-mono">
                    No telemetry events currently in buffer matching filter.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev, idx) => {
                  const provider = ev.event?.provider || 'Unknown';
                  const category = (ev.event?.category && ev.event.category[0]) || 'activity';
                  const host = ev.host?.name || 'LAB-HOST';
                  const os = ev.host?.osName || 'Unknown';
                  const user = ev.user?.name || '-';
                  const cmd = ev.process?.commandLine || ev.process?.name || (ev.destination?.ip ? `Egress -> ${ev.destination.ip}:${ev.destination.port}` : ev.event?.action);

                  return (
                    <tr key={ev.id || idx} className="hover:bg-[#181d2a] transition-colors">
                      <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                          provider === 'Sysmon' ? 'bg-sky-950/60 text-sky-400 border border-sky-800/50' :
                          provider.includes('auditd') ? 'bg-purple-950/60 text-purple-400 border border-purple-800/50' :
                          'bg-amber-950/60 text-amber-400 border border-amber-800/50'
                        }`}>
                          {provider}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-mono">
                        <div className="font-semibold text-white">{host}</div>
                        <div className="text-[10px] text-slate-500">{os}</div>
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="px-2 py-0.5 bg-[#0c0e15] border border-[#212738] text-slate-300 rounded text-[10px] uppercase font-mono">
                          {category}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-slate-300">{user}</td>
                      <td className="py-2.5 px-4 font-mono text-slate-300 max-w-md truncate" title={cmd}>
                        {cmd}
                      </td>
                      <td className="py-2.5 px-4 text-right">
                        <button
                          onClick={() => setSelectedEvent(ev)}
                          className="px-2.5 py-1 bg-[#0c0e15] hover:bg-[#181d2a] border border-[#212738] text-slate-300 rounded text-[11px] font-mono inline-flex items-center gap-1 transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5 text-sky-400" />
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* JSON Inspector Drawer Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#11141d] border border-[#212738] rounded-md w-full max-w-3xl max-h-[85vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-5 py-3 border-b border-[#212738] bg-[#171b26] rounded-t-md">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-sky-400" />
                <h3 className="font-mono text-xs uppercase font-bold text-white tracking-wider">
                  CES Schema Inspector
                </h3>
                <span className="text-[10px] font-mono text-slate-400 ml-2">ID: {selectedEvent.id}</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyJson}
                  className="px-2.5 py-1 bg-[#0c0e15] hover:bg-[#181d2a] text-slate-300 border border-[#212738] rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
                >
                  <Copy className="w-3.5 h-3.5" />
                  {copied ? 'Copied' : 'Copy JSON'}
                </button>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="p-1 text-slate-400 hover:text-white rounded"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="p-4 overflow-y-auto flex-1 font-mono text-xs text-emerald-400 bg-[#0c0e15] rounded-b-md">
              <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}

      {/* Ingest Telemetry Modal */}
      {showIngestModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#11141d] border border-[#212738] rounded-md w-full max-w-2xl flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-5 py-3 border-b border-[#212738] bg-[#171b26] rounded-t-md">
              <div className="flex items-center gap-2">
                <Upload className="w-4 h-4 text-sky-400" />
                <h3 className="font-mono text-xs uppercase font-bold text-white tracking-wider">Ingest Security Telemetry</h3>
              </div>
              <button
                onClick={() => setShowIngestModal(false)}
                className="p-1 text-slate-400 hover:text-white rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <p className="text-xs text-slate-400 font-mono">
                Input raw telemetry payload (Sysmon, Linux auditd, or Suricata). Evaluates against all 18 Sigma detection rules with multi-stage correlation.
              </p>
              <textarea
                rows={9}
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                className="w-full bg-[#0c0e15] border border-[#212738] rounded p-3 text-xs font-mono text-emerald-400 focus:outline-none focus:border-sky-500"
              />
              {ingestStatus && (
                <div className={`p-2.5 rounded text-xs font-mono ${
                  ingestStatus.startsWith('Success') ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/50' :
                  ingestStatus.startsWith('Error') ? 'bg-rose-950/80 text-rose-300 border border-rose-800/50' :
                  'bg-sky-950/80 text-sky-300'
                }`}>
                  {ingestStatus}
                </div>
              )}
              <div className="flex justify-end gap-2 pt-2 border-t border-[#212738]">
                <button
                  onClick={() => setShowIngestModal(false)}
                  className="px-3 py-1.5 bg-[#0c0e15] hover:bg-[#181d2a] text-slate-300 rounded text-xs font-mono border border-[#212738]"
                >
                  Cancel
                </button>
                <button
                  onClick={handleIngest}
                  className="px-3.5 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-mono font-medium flex items-center gap-1.5 transition"
                >
                  <Activity className="w-3.5 h-3.5" />
                  Normalize & Evaluate
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
