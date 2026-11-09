import React from 'react';
import {
  Shield,
  LayoutDashboard,
  Radio,
  Server,
  Cpu,
  Zap,
  FileText,
  LogOut,
  Activity,
  Crosshair,
  ShieldAlert,
  Search
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const { user, logout } = useAuth();

  const navigationSections = [
    {
      heading: 'Operations',
      items: [
        { id: 'overview', label: 'Executive Dashboard', icon: LayoutDashboard },
        { id: 'incidents', label: 'Threat Triage Queue', icon: ShieldAlert },
        { id: 'telemetry', label: 'Live Telemetry Stream', icon: Activity },
      ]
    },
    {
      heading: 'Detection & Intel',
      items: [
        { id: 'detections', label: 'Detection Rules & MITRE', icon: Cpu },
        { id: 'threat-intel', label: 'Threat Intelligence (IOCs)', icon: Radio },
        { id: 'assets', label: 'Attack Surface & Assets', icon: Server },
      ]
    },
    {
      heading: 'Response & Validation',
      items: [
        { id: 'response', label: 'Response Orchestrator', icon: Zap },
        { id: 'simulation', label: 'Breach Simulation (BAS)', icon: Crosshair },
      ]
    },
    {
      heading: 'Governance',
      items: [
        { id: 'audit', label: 'Audit & Compliance Reports', icon: FileText },
      ]
    }
  ];

  return (
    <aside className="w-64 bg-[#090b11] border-r border-[#212738] flex flex-col justify-between shrink-0 h-screen sticky top-0 select-none">
      <div className="overflow-y-auto">
        {/* Enterprise Brand Logo */}
        <div className="p-5 border-b border-[#212738] flex items-center space-x-3 bg-[#0c0e15]">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-700 to-indigo-800 border border-blue-500/30 flex items-center justify-center text-white shadow-sm">
            <Shield className="w-4 h-4 text-blue-200" />
          </div>
          <div>
            <div className="flex items-center space-x-1.5">
              <h1 className="text-sm font-bold tracking-widest text-slate-100 font-mono">BLUEOPS</h1>
              <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 bg-blue-950 text-blue-400 border border-blue-800 rounded">CLOUD</span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono tracking-tight">Enterprise SecOps Platform</p>
          </div>
        </div>

        {/* Categorized Enterprise Navigation */}
        <nav className="p-3 space-y-5">
          {navigationSections.map((section, idx) => (
            <div key={idx} className="space-y-1">
              <div className="px-3 pb-1 text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">
                {section.heading}
              </div>
              {section.items.map((item) => {
                const Icon = item.icon;
                const active = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectTab(item.id)}
                    className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-md text-xs font-medium transition-all ${
                      active
                        ? 'bg-[#181d2a] text-white border-l-2 border-l-blue-500 font-semibold shadow-inner'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-[#121520]'
                    }`}
                  >
                    <Icon className={`w-4 h-4 ${active ? 'text-blue-400' : 'text-slate-500'}`} />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </div>

      {/* Operator Profile & Sign Out */}
      <div className="p-3.5 border-t border-[#212738] bg-[#0c0e15]">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2.5 min-w-0">
            <div className="w-7 h-7 rounded-md bg-[#161a26] border border-[#272e42] flex items-center justify-center text-xs font-mono font-bold text-slate-300">
              {user?.username?.substring(0, 2).toUpperCase() || 'OP'}
            </div>
            <div className="truncate">
              <p className="text-xs font-semibold text-slate-200 truncate">{user?.fullName || 'SecOps Operator'}</p>
              <div className="flex items-center space-x-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                <span className="text-[10px] text-slate-400 font-mono tracking-tight">{user?.role?.replace('ROLE_', '') || 'ANALYST'}</span>
              </div>
            </div>
          </div>
          <button
            onClick={logout}
            title="Sign out of SecOps session"
            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-[#1a131b] rounded border border-transparent hover:border-red-900/40 transition"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
};
