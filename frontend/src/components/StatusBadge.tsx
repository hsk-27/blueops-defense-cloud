import React from 'react';
import { IncidentStatus, AssetStatus } from '../types';

export const StatusBadge: React.FC<{ status: IncidentStatus | AssetStatus | string }> = ({ status }) => {
  const st = (status || '').toUpperCase();
  let style = 'bg-[#181d2a] text-slate-300 border-[#2b354c]';
  let dot = 'bg-slate-400';

  if (st === 'NEW' || st === 'SUSPICIOUS' || st === 'PENDING') {
    style = 'bg-amber-950/60 text-amber-300 border-amber-800/60';
    dot = 'bg-amber-400';
  } else if (st === 'INVESTIGATING' || st === 'IN_PROGRESS' || st === 'TRIAGED') {
    style = 'bg-sky-950/60 text-sky-300 border-sky-800/60';
    dot = 'bg-sky-400';
  } else if (st === 'CONTAINED' || st === 'HEALTHY' || st === 'SUCCEEDED' || st === 'ACTIVE') {
    style = 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60';
    dot = 'bg-emerald-400';
  } else if (st === 'RESOLVED' || st === 'CLOSED') {
    style = 'bg-[#181d2a] text-slate-300 border-[#2b354c]';
    dot = 'bg-slate-500';
  } else if (st === 'COMPROMISED' || st === 'FAILED' || st === 'OFFLINE') {
    style = 'bg-rose-950/60 text-rose-300 border-rose-800/60';
    dot = 'bg-rose-500 animate-pulse';
  } else if (st === 'ISOLATED' || st === 'CONTAINMENT_PENDING') {
    style = 'bg-purple-950/60 text-purple-300 border-purple-800/60';
    dot = 'bg-purple-400';
  }

  return (
    <span className={`inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${style}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      <span>{st.replace(/_/g, ' ')}</span>
    </span>
  );
};

