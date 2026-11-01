import React from 'react';
import { Activity, ShieldCheck, AlertTriangle } from 'lucide-react';

interface HeaderProps {
  title: string;
  subtitle?: string;
}

export const Header: React.FC<HeaderProps> = ({ title, subtitle }) => {
  return (
    <header className="h-16 border-b border-[#1e293b] bg-[#0c101a]/80 backdrop-blur px-8 flex items-center justify-between sticky top-0 z-10">
      <div>
        <h2 className="text-lg font-bold text-slate-100 tracking-tight">{title}</h2>
        {subtitle && <p className="text-xs text-slate-400 font-mono">{subtitle}</p>}
      </div>

      <div className="flex items-center space-x-4">
        {/* Environment Status Pills */}
        <div className="flex items-center space-x-2 text-xs font-mono bg-[#111726] border border-[#1e293b] px-3 py-1.5 rounded-md">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span className="text-slate-300">LAB CLUSTER:</span>
          <span className="text-emerald-400 font-semibold">ONLINE</span>
        </div>

        <div className="flex items-center space-x-1.5 text-xs font-mono bg-blue-950/40 border border-blue-800/50 text-blue-300 px-3 py-1.5 rounded-md">
          <Activity className="w-3.5 h-3.5 text-blue-400" />
          <span>INGESTION: 18.4 eps</span>
        </div>
      </div>
    </header>
  );
};
