import React, { useState } from 'react';
import {
  ShieldCheck,
  BookOpen,
  Zap,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  FileCheck,
  ExternalLink,
  Layers,
  Sparkles,
  Copy,
  Check
} from 'lucide-react';
import { IncidentRecommendation, AuthoritativeSource, AdvisoryPriority } from '../types';

interface AuthoritativeAdvisorProps {
  recommendations: IncidentRecommendation[];
  loading?: boolean;
  onLaunchPlaybook?: (playbookCode: string, target: string) => void;
}

export const AuthoritativeAdvisor: React.FC<AuthoritativeAdvisorProps> = ({
  recommendations,
  loading = false,
  onLaunchPlaybook
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(
    recommendations.length > 0 ? recommendations[0].id : null
  );
  const [copied, setCopied] = useState(false);

  const handleCopyChecklist = () => {
    if (!recommendations || recommendations.length === 0) return;

    let text = `# Incident Response Action Plan: Authoritative Standard Operating Procedures\n`;
    text += `Generated: ${new Date().toUTCString()}\n`;
    text += `Frameworks: NIST SP 800-61 Rev. 2, CISA Federal IR Playbooks, MITRE D3FEND, SANS PICERL\n\n`;

    recommendations.forEach((rec, idx) => {
      text += `## ${idx + 1}. [${rec.priority}] ${rec.title}\n`;
      text += `- **Authoritative Source:** ${rec.citation}\n`;
      text += `- **Operational Phase:** ${rec.phase.replace(/_/g, ' ')}\n`;
      text += `- **Analysis & Rationale:** ${rec.rationale}\n`;
      if (rec.suggestedPlaybookCode) {
        text += `- **Mapped Playbook:** ${rec.suggestedPlaybookName || rec.suggestedPlaybookCode} (Target: ${rec.suggestedTarget || 'N/A'})\n`;
      }
      if (rec.actionableSteps && rec.actionableSteps.length > 0) {
        text += `- **Standard Operating Procedure Steps:**\n`;
        rec.actionableSteps.forEach(step => {
          text += `  - [ ] ${step}\n`;
        });
      }
      text += `\n`;
    });

    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2500);
      }).catch(err => {
        console.warn('Clipboard write failed:', err);
      });
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedId(prev => (prev === id ? null : id));
  };

  const getSourceBadge = (source: AuthoritativeSource) => {
    switch (source) {
      case 'NIST_SP_800_61R2':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-blue-950/80 text-blue-300 border border-blue-700/60">
            <BookOpen className="w-3 h-3 text-blue-400" />
            <span>NIST SP 800-61r2</span>
          </span>
        );
      case 'CISA_IR_PLAYBOOK':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-purple-950/80 text-purple-300 border border-purple-700/60">
            <ShieldCheck className="w-3 h-3 text-purple-400" />
            <span>CISA Federal IR</span>
          </span>
        );
      case 'MITRE_D3FEND':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-700/60">
            <Layers className="w-3 h-3 text-rose-400" />
            <span>MITRE D3FEND</span>
          </span>
        );
      case 'MITRE_ATTACK_MITIGATION':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-700/60">
            <Layers className="w-3 h-3 text-amber-400" />
            <span>MITRE ATT&CK</span>
          </span>
        );
      case 'SANS_PICERL':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-700/60">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            <span>SANS PICERL</span>
          </span>
        );
      case 'RFC_3227':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-700/60">
            <FileCheck className="w-3 h-3 text-cyan-400" />
            <span>IETF RFC 3227</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
            <span>Authoritative Guidance</span>
          </span>
        );
    }
  };

  const getPriorityBadge = (priority: AdvisoryPriority) => {
    switch (priority) {
      case 'IMMEDIATE_ACTION':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-900/60 text-red-300 border border-red-700/80 animate-pulse">
            <AlertTriangle className="w-2.5 h-2.5 text-red-400" />
            <span>IMMEDIATE ACTION</span>
          </span>
        );
      case 'HIGH_PRIORITY':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-900/60 text-amber-300 border border-amber-700/80">
            <span>HIGH PRIORITY</span>
          </span>
        );
      case 'RECOMMENDED_FOLLOW_UP':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-blue-900/60 text-blue-300 border border-blue-700/80">
            <span>FOLLOW-UP</span>
          </span>
        );
      case 'STRATEGIC_HARDENING':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
            <span>POST-INCIDENT HARDENING</span>
          </span>
        );
    }
  };

  if (loading) {
    return (
      <div className="bg-[#11141d] border border-[#212738] rounded-md p-6 text-center text-slate-400 space-y-3">
        <Sparkles className="w-4 h-4 text-sky-400 animate-spin mx-auto" />
        <p className="text-xs font-mono">Analyzing telemetry against NIST SP 800-61r2 and CISA advisories...</p>
      </div>
    );
  }

  if (recommendations.length === 0) {
    return (
      <div className="bg-[#11141d] border border-[#212738] rounded-md p-6 text-center text-slate-500 font-mono text-xs">
        No active authoritative recommendations recorded for this incident.
      </div>
    );
  }

  return (
    <div className="bg-[#11141d] border border-[#212738] rounded-md p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#212738] pb-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-1.5 bg-sky-950/70 border border-sky-800/80 rounded">
            <ShieldCheck className="w-4 h-4 text-sky-400" />
          </div>
          <div>
            <h3 className="text-xs font-bold font-mono uppercase text-slate-200 flex items-center space-x-2 tracking-wider">
              <span>Authoritative SecOps Advisor</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-900/40 text-sky-300 border border-sky-800/60">
                {recommendations.length} Steps
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">
              Procedural guidance synthesized from NIST SP 800-61r2, CISA KEV/CSA, MITRE D3FEND, and SANS PICERL.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={handleCopyChecklist}
          className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded text-xs font-mono font-medium bg-[#0c0e15] hover:bg-[#181d2a] text-slate-200 border border-[#212738] hover:border-slate-600 transition"
          title="Copy authoritative incident SOP checklist to clipboard"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400 font-mono text-[11px]">Copied SOP</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5 text-slate-400" />
              <span className="font-mono text-[11px]">Copy SOP</span>
            </>
          )}
        </button>
      </div>

      {/* Recommendations List */}
      <div className="space-y-3">
        {recommendations.map(rec => {
          const isExpanded = expandedId === rec.id;
          return (
            <div
              key={rec.id}
              className={`bg-[#0c0e15] border transition rounded p-3 space-y-2.5 ${
                rec.priority === 'IMMEDIATE_ACTION'
                  ? 'border-rose-900/60 hover:border-rose-700/80'
                  : 'border-[#212738] hover:border-slate-700'
              }`}
            >
              {/* Card Header */}
              <div
                className="flex items-start justify-between cursor-pointer gap-2"
                onClick={() => toggleExpand(rec.id)}
              >
                <div className="space-y-1.5 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    {getSourceBadge(rec.authoritativeSource)}
                    {getPriorityBadge(rec.priority)}
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-[#11141d] text-slate-400 border border-[#212738]">
                      {rec.phase.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <h4 className="text-xs font-semibold text-slate-100 flex items-center space-x-1.5">
                    <span>{rec.title}</span>
                  </h4>

                  <div className="text-[10px] font-mono text-slate-400 flex items-center space-x-1.5">
                    <span className="text-slate-500">Citation:</span>
                    <span className="text-sky-300 font-semibold">{rec.citation}</span>
                  </div>
                </div>

                <button
                  type="button"
                  aria-label={isExpanded ? 'Collapse advisory details' : 'Expand advisory details'}
                  className="text-slate-400 hover:text-slate-200 p-1"
                >
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>

              {/* Collapsible Body */}
              {isExpanded && (
                <div className="pt-2 border-t border-[#212738] space-y-3 text-xs">
                  {/* Rationale */}
                  <div className="bg-[#11141d] border border-[#212738] p-3 rounded text-slate-300 leading-relaxed text-[11px]">
                    <span className="font-semibold text-slate-200 block mb-1">Authoritative Analysis & Rationale:</span>
                    {rec.rationale}
                  </div>

                  {/* Actionable Steps Checklist */}
                  {rec.actionableSteps && rec.actionableSteps.length > 0 && (
                    <div className="space-y-1.5">
                      <span className="text-[11px] font-semibold text-slate-300 block">Recommended Standard Operating Procedure:</span>
                      <ul className="space-y-1 text-[11px] text-slate-300">
                        {rec.actionableSteps.map((step, idx) => (
                          <li key={idx} className="flex items-start space-x-2">
                            <span className="text-sky-400 font-mono font-bold mt-0.5">•</span>
                            <span>{step}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Playbook Quick Launch */}
                  {rec.suggestedPlaybookCode && onLaunchPlaybook && (
                    <div className="pt-2 flex items-center justify-between bg-indigo-950/20 border border-indigo-800/40 p-2.5 rounded">
                      <div className="space-y-0.5">
                        <span className="text-[10px] font-mono text-indigo-300 uppercase font-bold block">
                          Mapped Response Playbook:
                        </span>
                        <span className="text-xs font-semibold text-slate-200">
                          {rec.suggestedPlaybookName || rec.suggestedPlaybookCode}
                        </span>
                        {rec.suggestedTarget && (
                          <div className="text-[10px] font-mono text-slate-400">
                            Target: <span className="text-indigo-300 font-semibold">{rec.suggestedTarget}</span>
                          </div>
                        )}
                      </div>

                      <button
                        onClick={() => onLaunchPlaybook(rec.suggestedPlaybookCode!, rec.suggestedTarget || '')}
                        className="bg-indigo-600 hover:bg-indigo-500 text-white font-mono font-medium text-xs px-2.5 py-1 rounded flex items-center space-x-1.5 transition"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>Launch Playbook</span>
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
