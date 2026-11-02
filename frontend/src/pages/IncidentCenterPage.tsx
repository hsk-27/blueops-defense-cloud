import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Plus,
  RefreshCw,
  ArrowRight,
  AlertCircle
} from 'lucide-react';
import { api } from '../services/api';
import { Incident, IncidentSeverity, IncidentStatus } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';

interface IncidentCenterProps {
  onSelectIncident: (id: number) => void;
}

export const IncidentCenterPage: React.FC<IncidentCenterProps> = ({ onSelectIncident }) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Form State
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newSeverity, setNewSeverity] = useState<IncidentSeverity>('HIGH');
  const [creating, setCreating] = useState(false);

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const res = await api.getIncidents({
        severity: selectedSeverity || undefined,
        status: selectedStatus || undefined,
        size: 50
      });
      setIncidents(res.content || []);
    } catch (err) {
      console.error('Failed to fetch incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [selectedSeverity, selectedStatus]);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    try {
      setCreating(true);
      await api.createIncident({
        title: newTitle,
        description: newDesc,
        severity: newSeverity,
      });
      setShowCreateModal(false);
      setNewTitle('');
      setNewDesc('');
      await fetchIncidents();
    } catch (err: any) {
      alert(err.message || 'Failed to create incident');
    } finally {
      setCreating(false);
    }
  };

  const filtered = incidents.filter((i) =>
    i.title.toLowerCase().includes(search.toLowerCase()) ||
    i.incidentNumber.toLowerCase().includes(search.toLowerCase()) ||
    (i.assignedTo && i.assignedTo.toLowerCase().includes(search.toLowerCase())) ||
    (i.primaryAssetHostname && i.primaryAssetHostname.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[#111726] border border-[#1e293b] p-4 rounded-xl">
        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              placeholder="Search incidents, assets, analyst..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-[#0a0d14] border border-[#1e293b] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-[#0a0d14] border border-[#1e293b] rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="bg-[#0a0d14] border border-[#1e293b] rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Statuses</option>
            <option value="NEW">New</option>
            <option value="TRIAGED">Triaged</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CONTAINMENT_PENDING">Containment Pending</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="REOPENED">Reopened</option>
          </select>
        </div>

        <div className="flex items-center space-x-3 w-full sm:w-auto justify-end">
          <button
            onClick={fetchIncidents}
            title="Refresh"
            className="p-2 bg-[#0a0d14] hover:bg-[#161f30] border border-[#1e293b] rounded-lg text-slate-400 hover:text-slate-200 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-blue-400' : ''}`} />
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs px-3 py-2 rounded-lg flex items-center space-x-1.5 transition"
          >
            <Plus className="w-4 h-4" />
            <span>Create Incident</span>
          </button>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="bg-[#111726] border border-[#1e293b] rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0a0d14] text-slate-400 uppercase font-mono border-b border-[#1e293b]">
              <tr>
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Title & Description</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Target Asset</th>
                <th className="py-3 px-4">Assigned Analyst</th>
                <th className="py-3 px-4">Findings</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e293b]">
              {filtered.length > 0 ? (
                filtered.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => onSelectIncident(inc.id)}
                    className="hover:bg-[#161f30] cursor-pointer transition-colors"
                  >
                    <td className="py-3.5 px-4 font-mono font-semibold text-blue-400">{inc.incidentNumber}</td>
                    <td className="py-3.5 px-4 max-w-sm">
                      <p className="font-semibold text-slate-100 truncate">{inc.title}</p>
                      {inc.description && <p className="text-[11px] text-slate-400 truncate mt-0.5">{inc.description}</p>}
                    </td>
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="py-3.5 px-4">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {inc.primaryAssetHostname ? (
                        <span>{inc.primaryAssetHostname}</span>
                      ) : (
                        <span className="text-slate-500 italic">Unassigned</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 font-medium">
                      {inc.assignedTo || <span className="text-slate-500 italic">Unassigned</span>}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="bg-[#0a0d14] border border-[#1e293b] px-2 py-0.5 rounded font-mono text-slate-300">
                        {inc.findingCount} alerts
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <span className="text-blue-400 hover:text-blue-300 font-semibold inline-flex items-center space-x-1">
                        <span>Investigate</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-mono">
                    No matching security incidents found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#111726] border border-[#1e293b] rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-blue-500" />
              <span>Create Security Incident</span>
            </h3>

            <form onSubmit={handleCreateIncident} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Incident Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Suspicious PowerShell Injection on LAB-WIN-01"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-[#0a0d14] border border-[#1e293b] rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Severity *</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as IncidentSeverity)}
                  className="w-full bg-[#0a0d14] border border-[#1e293b] rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                >
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Description & Initial Leads</label>
                <textarea
                  rows={3}
                  placeholder="Summary of observed attack telemetry and initial scope..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-[#0a0d14] border border-[#1e293b] rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-[#0a0d14] hover:bg-[#161f30] text-slate-400 hover:text-slate-200 text-xs rounded-lg border border-[#1e293b]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg disabled:opacity-50"
                >
                  {creating ? 'Creating...' : 'Create Incident'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
