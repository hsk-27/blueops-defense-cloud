import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Server,
  Binary,
  Clock,
  CheckCircle2,
  AlertTriangle,
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

  const loadData = async () => {
    try {
      setLoading(true);
      const data = await api.getSocOverview();
      setMetrics(data);
    } catch (err) {
      console.error('Failed to load SOC overview:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !metrics) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[60vh] text-slate-400 space-x-3">
        <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />
        <span>Loading SOC Overview Telemetry...</span>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner: Key Operations Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Active Incidents */}
        <div className="bg-[#111726] border border-[#1e293b] rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Active Incidents</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-3xl font-extrabold text-slate-100 mb-2">
            {metrics?.activeIncidents || 0}
          </div>
          <div className="flex items-center space-x-2 text-[11px] font-mono">
            <span className="text-red-400 font-semibold">{metrics?.criticalIncidents || 0} Critical</span>
            <span className="text-slate-600">|</span>
            <span className="text-orange-400 font-semibold">{metrics?.highIncidents || 0} High</span>
            <span className="text-slate-600">|</span>
            <span className="text-yellow-400">{metrics?.mediumIncidents || 0} Med</span>
          </div>
        </div>

        {/* Assets Monitored */}
        <div className="bg-[#111726] border border-[#1e293b] rounded-xl p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Monitored Assets</span>
            <Server className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-3xl font-extrabold text-slate-100 mb-2">
            {metrics?.totalAssets || 0}
          </div>
          <p className="text-[11px] text-slate-400 font-mono">
            <span className="text-amber-400 font-semibold">{metrics?.assetsWithAlerts || 0}</span> with active detections
          </p>
        </div>

        {/* MTTD */}
        <div className="bg-[#111726] border border-[#1e293b] rounded-xl p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Mean Time to Detect (MTTD)</span>
            <Clock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-extrabold text-emerald-400 mb-2">
            {metrics?.meanTimeToDetectSeconds || 4.8}s
          </div>
          <p className="text-[11px] text-slate-400 font-mono">Real-time OpenSearch Security Analytics</p>
        </div>

        {/* MTTR */}
        <div className="bg-[#111726] border border-[#1e293b] rounded-xl p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Mean Time to Respond (MTTR)</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-3xl font-extrabold text-blue-400 mb-2">
            {Math.round(metrics?.meanTimeToRespondSeconds || 120)}s
          </div>
          <p className="text-[11px] text-slate-400 font-mono">Orchestrated Playbook Remediation</p>
        </div>
      </div>

      {/* Subsystem Health Grid */}
      <div className="bg-[#111726] border border-[#1e293b] rounded-xl p-5">
        <h3 className="text-xs font-mono uppercase text-slate-400 tracking-wider mb-4 flex items-center space-x-2">
          <span>Infrastructure & Telemetry Collector Health</span>
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {metrics?.subsystemHealth &&
            Object.entries(metrics.subsystemHealth).map(([key, val]) => (
              <div key={key} className="bg-[#0a0d14] border border-[#1e293b] rounded-lg p-3">
                <div className="text-[11px] text-slate-400 font-mono uppercase truncate">{key}</div>
                <div className="flex items-center space-x-1.5 mt-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-xs font-semibold text-emerald-300 font-mono">{val}</span>
                </div>
              </div>
            ))}
        </div>
      </div>

      {/* 2-Column Section: Recent Incidents & MITRE Tactics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Incidents (2 cols) */}
        <div className="lg:col-span-2 bg-[#111726] border border-[#1e293b] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              <span>Recent Security Incidents</span>
            </h3>
            <span className="text-xs text-slate-400 font-mono">Live Ingestion Stream</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0a0d14] text-slate-400 uppercase font-mono border-b border-[#1e293b]">
                <tr>
                  <th className="py-2.5 px-3">Incident</th>
                  <th className="py-2.5 px-3">Title</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e293b]">
                {metrics?.recentIncidents && metrics.recentIncidents.length > 0 ? (
                  metrics.recentIncidents.map((inc) => (
                    <tr key={inc.id} className="hover:bg-[#161f30] transition-colors">
                      <td className="py-3 px-3 font-mono text-blue-400 font-medium">{inc.incidentNumber}</td>
                      <td className="py-3 px-3 text-slate-200 font-medium truncate max-w-xs">{inc.title}</td>
                      <td className="py-3 px-3">
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td className="py-3 px-3">
                        <StatusBadge status={inc.status} />
                      </td>
                      <td className="py-3 px-3">
                        <button
                          onClick={() => onNavigateToIncident(inc.id)}
                          className="text-blue-400 hover:text-blue-300 font-medium flex items-center space-x-1"
                        >
                          <span>Investigate</span>
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 font-mono">
                      No active incidents reported. Telemetry normal.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* MITRE ATT&CK Tactic Distribution (1 col) */}
        <div className="bg-[#111726] border border-[#1e293b] rounded-xl p-5">
          <h3 className="text-sm font-bold text-slate-100 mb-4 flex items-center space-x-2">
            <Binary className="w-4 h-4 text-emerald-400" />
            <span>Detection Tactic Coverage</span>
          </h3>

          <div className="space-y-3">
            {metrics?.detectionTacticDistribution && metrics.detectionTacticDistribution.length > 0 ? (
              metrics.detectionTacticDistribution.map((t, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-slate-300">{t.tactic}</span>
                    <span className="text-blue-400 font-bold">{t.count} rules</span>
                  </div>
                  <div className="w-full bg-[#0a0d14] h-2 rounded-full overflow-hidden border border-[#1e293b]">
                    <div
                      className="bg-blue-500 h-full rounded-full"
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
