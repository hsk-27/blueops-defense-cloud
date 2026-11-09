import React from 'react';
import { IncidentSeverity } from '../types';

export const SeverityBadge: React.FC<{ severity: IncidentSeverity | string }> = ({ severity }) => {
  const sev = (severity || '').toUpperCase();
  let style = 'bg-[#181d2a] text-slate-300 border-[#2b354c]';
  let dot = 'bg-slate-400';

  if (sev === 'CRITICAL') {
    style = 'bg-rose-950/60 text-rose-300 border-rose-800/80';
    dot = 'bg-rose-500 animate-pulse';
  } else if (sev === 'HIGH') {
    style = 'bg-amber-950/60 text-amber-300 border-amber-800/80';
    dot = 'bg-amber-500';
  } else if (sev === 'MEDIUM') {
    style = 'bg-yellow-950/50 text-yellow-300 border-yellow-800/60';
    dot = 'bg-yellow-500';
  } else if (sev === 'LOW' || sev === 'INFORMATIONAL') {
    style = 'bg-sky-950/50 text-sky-300 border-sky-800/60';
    dot = 'bg-sky-400';
  }

  return (
    <span className={`inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider border ${style}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      <span>{sev}</span>
    </span>
  );
};

