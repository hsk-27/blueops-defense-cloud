import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Server,
  Binary,
  Clock,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  ArrowUpRight,
  RefreshCw,
  Activity
} from 'lucide-react';
import { api } from '../services/api';
import { SocOverviewMetrics } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';

export const OverviewPage: React.FC<{ onNavigateToIncident: (id: number) => void }> = ({ onNavigateToIncident }) => {
  const [metrics, setMetrics] = useState<SocOverviewMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    const loadData = async (isInitial = false) => {
      try {
        if (isInitial) setLoading(true);
        const data = await api.getSocOverview();
        if (isMounted) {
          setMetrics(data);
          setError(null);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err?.message || 'Failed to load SOC overview metrics');
        }
      } finally {
        if (isMounted && isInitial) setLoading(false);
      }
    };

    loadData(true);
    const interval = setInterval(() => loadData(false), 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  if (loading && !metrics) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[60vh] text-slate-400 space-x-3">
        <RefreshCw className="w-4 h-4 animate-spin text-sky-400" />
        <span className="font-mono text-xs uppercase tracking-wider text-slate-400">Loading Telemetry & SecOps State...</span>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {error && (
        <div role="alert" className="p-3 bg-rose-950/60 border border-rose-800 rounded-md flex items-center space-x-2 text-xs font-mono text-rose-200">
          <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0" />
          <span>Overview Metrics Error: {error}</span>
        </div>
      )}
      {/* Top Banner: Key Operations Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Active Incidents */}
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Active Incidents</span>
            <ShieldAlert className="w-4 h-4 text-rose-500" />
          </div>
          <div className="text-3xl font-extrabold text-slate-100 mb-2 font-mono">
            {metrics?.activeIncidents || 0}
          </div>
          <div className="flex items-center space-x-2 text-[11px] font-mono">
            <span className="text-rose-400 font-semibold">{metrics?.criticalIncidents || 0} Critical</span>
            <span className="text-slate-700">|</span>
            <span className="text-amber-400 font-semibold">{metrics?.highIncidents || 0} High</span>
            <span className="text-slate-700">|</span>
            <span className="text-yellow-400">{metrics?.mediumIncidents || 0} Med</span>
          </div>
        </div>

        {/* Assets Monitored */}
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Monitored Assets</span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-3xl font-extrabold text-slate-100 mb-2 font-mono">
            {metrics?.totalAssets || 0}
          </div>
          <p className="text-[11px] text-slate-400 font-mono">
            <span className="text-amber-400 font-semibold">{metrics?.assetsWithAlerts || 0}</span> with active detections
          </p>
        </div>

        {/* MTTD */}
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Mean Time to Detect (MTTD)</span>
            <Clock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-extrabold text-emerald-400 mb-2 font-mono">
            {metrics?.meanTimeToDetectSeconds != null ? `${metrics.meanTimeToDetectSeconds}s` : 'N/A'}
          </div>
          <p className="text-[11px] text-slate-500 font-mono">
            {metrics?.meanTimeToDetectSeconds != null ? 'Measured detection latency' : 'No empirical MTTD telemetry recorded'}
          </p>
        </div>

        {/* MTTR */}
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Mean Time to Respond (MTTR)</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-3xl font-extrabold text-indigo-400 mb-2 font-mono">
            {metrics?.meanTimeToRespondSeconds != null ? `${Math.round(metrics.meanTimeToRespondSeconds)}s` : 'N/A'}
          </div>
          <p className="text-[11px] text-slate-500 font-mono">
            {metrics?.meanTimeToRespondSeconds != null ? 'From contained incidents' : 'No contained incidents recorded yet'}
          </p>
        </div>
      </div>

      {/* Subsystem Health Grid */}
      <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
        <h3 className="text-[11px] font-mono uppercase text-slate-400 tracking-wider mb-3 flex items-center space-x-2">
          <span>Infrastructure & Telemetry Collector Status</span>
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {metrics?.subsystemHealth &&
            Object.entries(metrics.subsystemHealth).map(([key, val]) => {
              const upper = (val || '').toUpperCase();
              const isHealthy = upper.includes('UP') || upper.includes('HEALTHY') || upper.includes('ONLINE') || upper.includes('ACTIVE') || upper.includes('OPERATIONAL') || upper.includes('CONNECTED') || upper.includes('RECEIVING');
              const isDegraded = upper.includes('DEGRADED') || upper.includes('WARN') || upper.includes('STANDBY') || upper.includes('FALLBACK') || upper.includes('SIMULATION') || upper.includes('CONFIGURED');

              return (
                <div key={key} className="bg-[#0c0e15] border border-[#212738] rounded p-2.5">
                  <div className="text-[10px] text-slate-400 font-mono uppercase truncate">{key}</div>
                  <div className="flex items-center space-x-1.5 mt-1">
                    {isHealthy ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    ) : isDegraded ? (
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    ) : (
                      <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
                    )}
                    <span
                      className={`text-xs font-semibold font-mono ${
                        isHealthy ? 'text-emerald-300' : isDegraded ? 'text-amber-300' : 'text-rose-300'
                      }`}
                    >
                      {val}
                    </span>
                  </div>
                </div>
              );
            })}
        </div>
      </div>

      {/* 2-Column Section: Recent Incidents & MITRE Tactics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Incidents (2 cols) */}
        <div className="lg:col-span-2 bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-mono uppercase font-bold text-slate-200 flex items-center space-x-2 tracking-wider">
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              <span>Active Security Incidents</span>
            </h3>
            <span className="text-[10px] text-slate-500 font-mono uppercase tracking-wider">Live Pipeline Queue</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#171b26] text-slate-400 uppercase font-mono text-[10px] border-b border-[#212738]">
                <tr>
                  <th className="py-2.5 px-3">Incident</th>
                  <th className="py-2.5 px-3">Title</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#212738]">
                {metrics?.recentIncidents && metrics.recentIncidents.length > 0 ? (
                  metrics.recentIncidents.map((inc) => (
                    <tr key={inc.id} className="hover:bg-[#181d2a] transition-colors">
                      <td className="py-2.5 px-3 font-mono text-sky-400 font-medium">{inc.incidentNumber}</td>
                      <td className="py-2.5 px-3 text-slate-200 font-medium truncate max-w-xs">{inc.title}</td>
                      <td className="py-2.5 px-3">
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td className="py-2.5 px-3">
                        <StatusBadge status={inc.status} />
                      </td>
                      <td className="py-2.5 px-3">
                        <button
                          onClick={() => onNavigateToIncident(inc.id)}
                          className="text-sky-400 hover:text-sky-300 font-medium flex items-center space-x-1 font-mono text-[11px]"
                        >
                          <span>Investigate</span>
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 font-mono text-xs">
                      No active incidents reported. Telemetry pipeline normal.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* MITRE ATT&CK Tactic Distribution (1 col) */}
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <h3 className="text-xs font-mono uppercase font-bold text-slate-200 mb-3 flex items-center space-x-2 tracking-wider">
            <Binary className="w-4 h-4 text-emerald-400" />
            <span>Detection Tactic Coverage</span>
          </h3>

          <div className="space-y-3">
            {metrics?.detectionTacticDistribution && metrics.detectionTacticDistribution.length > 0 ? (
              metrics.detectionTacticDistribution.map((t, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-slate-300">{t.tactic}</span>
                    <span className="text-sky-400 font-bold">{t.count} rules</span>
                  </div>
                  <div className="w-full bg-[#0c0e15] h-1.5 rounded-full overflow-hidden border border-[#212738]">
                    <div
                      className="bg-indigo-500 h-full rounded-full"
                      style={{ width: `${Math.min(100, t.count * 25)}%` }}
                    ></div>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 font-mono">No detection rules loaded.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
