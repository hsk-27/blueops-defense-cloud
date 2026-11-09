import React, { useEffect, useState } from 'react';
import { Server, Search, RefreshCw, Shield, Clock, History, AlertCircle } from 'lucide-react';
import { api } from '../services/api';
import { Asset } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const AssetInventoryPage: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [history, setHistory] = useState<any[]>([]);

  const loadAssets = async () => {
    try {
      setLoading(true);
      const data = await api.getAssets();
      setAssets(data || []);
    } catch (err) {
      console.error('Failed to load assets:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, []);

  const handleSelectAsset = async (asset: Asset) => {
    setSelectedAsset(asset);
    try {
      const hist = await api.getAssetHistory(asset.id);
      setHistory(hist || []);
    } catch (err) {
      console.error('Failed to load asset status history:', err);
    }
  };

  const filtered = assets.filter(
    (a) =>
      a.hostname.toLowerCase().includes(search.toLowerCase()) ||
      a.persistentId.toLowerCase().includes(search.toLowerCase()) ||
      a.ipAddress.includes(search) ||
      a.osName.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[#11141d] border border-[#212738] p-4 rounded-md">
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
          <input
            type="text"
            placeholder="Search hostnames, persistent IDs, IPs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#0c0e15] border border-[#212738] rounded pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
          />
        </div>

        <button
          onClick={loadAssets}
          title="Refresh"
          className="p-2 bg-[#0c0e15] hover:bg-[#181d2a] border border-[#212738] rounded text-slate-400 hover:text-slate-200 transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-sky-400' : ''}`} />
        </button>
      </div>

      {/* Main Asset Table */}
      <div className="bg-[#11141d] border border-[#212738] rounded-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#171b26] text-slate-400 uppercase font-mono text-[10px] border-b border-[#212738]">
              <tr>
                <th className="py-2.5 px-4">Hostname</th>
                <th className="py-2.5 px-4">Persistent Asset ID</th>
                <th className="py-2.5 px-4">IP Address</th>
                <th className="py-2.5 px-4">Operating System</th>
                <th className="py-2.5 px-4">Criticality</th>
                <th className="py-2.5 px-4">Telemetry Health</th>
                <th className="py-2.5 px-4">Last Seen</th>
                <th className="py-2.5 px-4 text-right">History</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#212738]">
              {filtered.length > 0 ? (
                filtered.map((asset) => (
                  <tr key={asset.id} className="hover:bg-[#181d2a] transition-colors">
                    <td className="py-3 px-4 font-bold text-slate-100 flex items-center space-x-2">
                      <Server className="w-4 h-4 text-sky-400 shrink-0" />
                      <span>{asset.hostname}</span>
                    </td>
                    <td className="py-3 px-4 font-mono text-sky-400 font-semibold">{asset.persistentId}</td>
                    <td className="py-3 px-4 font-mono text-slate-300">{asset.ipAddress}</td>
                    <td className="py-3 px-4 text-slate-300">
                      {asset.osName} {asset.osVersion || ''}
                    </td>
                    <td className="py-3 px-4">
                      <span className="font-mono text-xs text-amber-400 font-semibold">{asset.criticality}</span>
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={asset.status} />
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      {asset.lastTelemetryAt ? new Date(asset.lastTelemetryAt).toLocaleTimeString() : 'Live'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleSelectAsset(asset)}
                        className="text-sky-400 hover:text-sky-300 text-xs font-mono font-medium inline-flex items-center space-x-1"
                      >
                        <History className="w-3.5 h-3.5" />
                        <span>Audit Log</span>
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-mono text-xs">
                    No monitored assets found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Asset History Modal */}
      {selectedAsset && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#11141d] border border-[#212738] rounded-md max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#212738] pb-3">
              <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-100 flex items-center space-x-2">
                <History className="w-4 h-4 text-sky-400" />
                <span>Asset Audit History: {selectedAsset.hostname}</span>
              </h3>
              <button
                onClick={() => setSelectedAsset(null)}
                className="text-slate-400 hover:text-slate-200 text-xs font-mono"
              >
                CLOSE
              </button>
            </div>

            <div className="space-y-3 max-h-72 overflow-y-auto">
              {history.length > 0 ? (
                history.map((h, idx) => (
                  <div key={idx} className="bg-[#0c0e15] border border-[#212738] p-3 rounded text-xs space-y-1">
                    <div className="flex justify-between text-slate-400 font-mono text-[11px]">
                      <span>Actor: {h.changed_by}</span>
                      <span>{new Date(h.changed_at).toLocaleTimeString()}</span>
                    </div>
                    <div className="flex items-center space-x-2 font-semibold">
                      <span className="text-slate-400">{h.previous_status}</span>
                      <span className="text-slate-600">→</span>
                      <span className="text-emerald-400">{h.new_status}</span>
                    </div>
                    {h.reason && <p className="text-slate-400 text-[11px] font-mono">{h.reason}</p>}
                  </div>
                ))
              ) : (
                <p className="text-xs text-slate-500 font-mono text-center py-4">No status transitions recorded.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
