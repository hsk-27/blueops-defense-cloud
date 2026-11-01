import React from 'react';
import { IncidentSeverity } from '../types';

export const SeverityBadge: React.FC<{ severity: IncidentSeverity | string }> = ({ severity }) => {
  const sev = severity.toUpperCase();
  let bg = 'bg-slate-800 text-slate-300 border-slate-700';

  if (sev === 'CRITICAL') {
    bg = 'bg-red-950/80 text-red-400 border-red-800/80 animate-pulse';
  } else if (sev === 'HIGH') {
    bg = 'bg-orange-950/80 text-orange-400 border-orange-800/80';
  } else if (sev === 'MEDIUM') {
    bg = 'bg-yellow-950/80 text-yellow-400 border-yellow-800/80';
  } else if (sev === 'LOW') {
    bg = 'bg-blue-950/80 text-blue-400 border-blue-800/80';
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border ${bg}`}>
      {sev}
    </span>
  );
};
