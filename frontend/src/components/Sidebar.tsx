import React from 'react';
import {
  ShieldAlert,
  LayoutDashboard,
  Radio,
  Server,
  Binary,
  Zap,
  FileText,
  LogOut,
  Flame,
  Activity,
  Skull
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const { user, logout } = useAuth();

  const navItems = [
    { id: 'overview', label: 'SOC Overview', icon: LayoutDashboard },
    { id: 'telemetry', label: 'Live Telemetry', icon: Activity },
    { id: 'simulation', label: 'Adversary Simulation', icon: Skull },
    { id: 'incidents', label: 'Incident Center', icon: ShieldAlert },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: Radio },
    { id: 'assets', label: 'Asset Inventory', icon: Server },
    { id: 'detections', label: 'Detection Rules', icon: Binary },
    { id: 'response', label: 'Response Hub', icon: Zap },
    { id: 'audit', label: 'Audit & Reports', icon: FileText },
  ];

  return (
    <aside className="w-64 bg-[#0d131f] border-r border-[#1e293b] flex flex-col justify-between shrink-0 h-screen sticky top-0">
      <div>
        {/* Brand */}
        <div className="p-5 border-b border-[#1e293b] flex items-center space-x-3">
          <div className="p-2 bg-blue-600/20 border border-blue-500/40 rounded-lg text-blue-400">
            <Flame className="w-5 h-5 text-blue-500" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-wider text-slate-100 flex items-center space-x-1.5">
              <span>BLUEOPS</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 bg-blue-900/60 text-blue-300 border border-blue-700/50 rounded">SOC</span>
            </h1>
            <p className="text-[11px] text-slate-400 font-mono">Threat Detection & IR</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#161f30]'
                }`}
              >
                <Icon className={`w-4 h-4 ${active ? 'text-blue-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* User profile & Logout */}
      <div className="p-4 border-t border-[#1e293b] bg-[#090d15]/50">
        <div className="flex items-center justify-between">
          <div className="truncate">
            <p className="text-xs font-semibold text-slate-200 truncate">{user?.fullName || 'Analyst'}</p>
            <p className="text-[11px] text-blue-400 font-mono">{user?.role?.replace('ROLE_', '') || 'ANALYST'}</p>
          </div>
          <button
            onClick={logout}
            title="Sign out"
            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-950/30 rounded border border-transparent hover:border-red-900/40 transition"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
};
