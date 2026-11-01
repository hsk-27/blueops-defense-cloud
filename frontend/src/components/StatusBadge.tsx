import React from 'react';
import { IncidentStatus, AssetStatus } from '../types';

export const StatusBadge: React.FC<{ status: IncidentStatus | AssetStatus | string }> = ({ status }) => {
  const st = status.toUpperCase();
  let color = 'bg-slate-800 text-slate-300 border-slate-700';

  if (st === 'NEW' || st === 'SUSPICIOUS') {
    color = 'bg-amber-950/70 text-amber-300 border-amber-800/60';
  } else if (st === 'INVESTIGATING' || st === 'IN_PROGRESS') {
    color = 'bg-blue-950/70 text-blue-300 border-blue-800/60';
  } else if (st === 'CONTAINED' || st === 'HEALTHY' || st === 'SUCCEEDED' || st === 'ACTIVE') {
    color = 'bg-emerald-950/70 text-emerald-300 border-emerald-800/60';
  } else if (st === 'RESOLVED') {
    color = 'bg-zinc-800 text-zinc-300 border-zinc-700';
  } else if (st === 'COMPROMISED' || st === 'FAILED' || st === 'OFFLINE') {
    color = 'bg-rose-950/70 text-rose-300 border-rose-800/60';
  } else if (st === 'ISOLATED') {
    color = 'bg-purple-950/70 text-purple-300 border-purple-800/60';
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${color}`}>
      {st.replace(/_/g, ' ')}
    </span>
  );
};
