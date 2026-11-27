import React from 'react';
import { Activity, Shield, Command, Search, CheckCircle2, ChevronDown } from 'lucide-react';

interface HeaderProps {
  title: string;
  subtitle?: string;
}

export const Header: React.FC<HeaderProps> = ({ title, subtitle }) => {
  return (
    <header className="h-16 border-b border-[#212738] bg-[#0c0e15]/95 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30 shadow-sm">
      {/* Page Title & Breadcrumb */}
      <div className="space-y-0.5">
        <div className="flex items-center space-x-2">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-500 font-semibold">BlueOps SecOps</span>
          <span className="text-slate-700">/</span>
          <h2 className="text-sm font-bold text-slate-100 tracking-tight">{title}</h2>
        </div>
        {subtitle && <p className="text-[11px] text-slate-400 font-mono tracking-tight">{subtitle}</p>}
      </div>

      {/* Enterprise Control Toolbar */}
      <div className="flex items-center space-x-3">
        {/* Quick Search / Command Palette shortcut */}
        <div className="hidden md:flex items-center space-x-2 bg-[#121520] border border-[#212738] hover:border-slate-600 transition px-3 py-1.5 rounded-md text-xs text-slate-400 cursor-pointer">
          <Search className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400">Search entities, IOCs, CVEs...</span>
          <kbd className="ml-3 px-1.5 py-0.5 rounded bg-[#1a1f2e] text-[10px] font-mono text-slate-300 border border-slate-700">Ctrl K</kbd>
        </div>

        {/* Lab Environment Indicator */}
        <div className="hidden sm:flex items-center space-x-2 bg-[#121520] border border-[#212738] px-3 py-1.5 rounded-md text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-sky-500"></span>
          <span className="text-slate-300 font-semibold">Lab Containment</span>
          <ChevronDown className="w-3 h-3 text-slate-500" />
        </div>

        {/* Telemetry Status Pill */}
        <div className="flex items-center space-x-2 bg-[#121520] border border-[#212738] px-3 py-1.5 rounded-md text-xs font-mono">
          <Activity className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-slate-400">PIPELINE:</span>
          <span className="text-emerald-400 font-bold">CONNECTED</span>
        </div>
      </div>
    </header>
  );
};
