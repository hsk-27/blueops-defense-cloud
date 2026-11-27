import React, { useState } from 'react';
import { 
  Crosshair, Play, ShieldCheck, Terminal, AlertTriangle, 
  CheckCircle2, Clock, Zap, ExternalLink, ArrowRight, RefreshCw 
} from 'lucide-react';
import { api } from '../services/api';

interface AttackScenarioDef {
  id: string;
  name: string;
  category: string;
  severity: string;
  mitreTechniques: string[];
  description: string;
  stages: string[];
}

const SCENARIOS: AttackScenarioDef[] = [
  {
    id: 'C002',
    name: 'Windows Multi-Stage APT Execution Chain',
    category: 'Advanced Persistent Threat',
    severity: 'CRITICAL',
    mitreTechniques: ['T1059.001', 'T1059', 'T1071', 'T1070.001'],
    description: 'Spearphishing Word document with embedded macro spawns cmd.exe, initiates an encoded PowerShell download cradle, beacons to external C2 (port 4444), and clears security event logs.',
    stages: [
      'Stage 1: Office document (winword.exe) spawns cmd.exe (D009)',
      'Stage 2: Execution of obfuscated Base64 PowerShell download cradle (D008)',
      'Stage 3: Outbound egress to non-standard port 4444 matching IOC IP (D014, D015)',
      'Stage 4: Execution of wevtutil.exe to clear Windows Security Event Log (D013)',
      'Stage 5: Correlation evaluation triggers CORR-002 (ready for analyst promotion)'
    ]
  },
  {
    id: 'C001',
    name: 'Linux Account Compromise & Privilege Escalation',
    category: 'Account Takeover',
    severity: 'CRITICAL',
    mitreTechniques: ['T1110', 'T1078', 'T1548.003', 'T1562.001'],
    description: 'Adversary executes slow-and-low password spraying against Linux server, succeeds with valid account, immediately executes sudo -i interactive shell, and disables auditd.',
    stages: [
      'Stage 1: Repeated SSH authentication failures across accounts (D001)',
      'Stage 2: Successful SSH login with compromised credentials (D002)',
      'Stage 3: Interactive root shell spawned via sudo (D004)',
      'Stage 4: Tampering with kernel audit subsystem (auditctl -D) (D006)',
      'Stage 5: Correlation evaluation triggers CORR-001 (ready for analyst promotion)'
    ]
  },
  {
    id: 'credential-dump',
    name: 'LSASS Memory Dumping / Credential Harvesting',
    category: 'Credential Access',
    severity: 'CRITICAL',
    mitreTechniques: ['T1003.001'],
    description: 'Adversary abuses Windows LOLBAS comsvcs.dll MiniDump or native Mimikatz sekurlsa to dump plaintext passwords and Kerberos tickets from lsass.exe process memory.',
    stages: [
      'Stage 1: In-memory process memory read targeted at lsass.exe',
      'Stage 2: Deterministic detection trigger Rule D011 (LSASS Memory Access)',
      'Stage 3: High-priority security finding generated & automated notification'
    ]
  },
  {
    id: 'threat-intel-c2',
    name: 'Threat Intel Active Indicator Beaconing',
    category: 'Command and Control',
    severity: 'HIGH',
    mitreTechniques: ['T1071'],
    description: 'Workstation generates DNS queries and outbound TCP egress toward a confirmed malicious IP listed in AlienVault OTX Threat Intelligence feed.',
    stages: [
      'Stage 1: Outbound egress connection to 198.51.100.24:443',
      'Stage 2: Real-time Threat Intelligence engine indicator match (D015)',
      'Stage 3: Correlation trigger C003 (Known IOC with Secondary Activity)'
    ]
  }
];

interface AdversaryConsoleProps {
  onNavigateTab?: (tab: string) => void;
}

export const AdversaryConsolePage: React.FC<AdversaryConsoleProps> = ({ onNavigateTab }) => {
  const [selectedScenario, setSelectedScenario] = useState<AttackScenarioDef>(SCENARIOS[0]);
  const [running, setRunning] = useState(false);
  const [executionLogs, setExecutionLogs] = useState<string[]>([]);
  const [simulationResult, setSimulationResult] = useState<any | null>(null);

  const handleRunSimulation = async () => {
    setRunning(true);
    setExecutionLogs([]);
    setSimulationResult(null);

    const log = (msg: string) => {
      setExecutionLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
    };

    log(`Initializing simulation environment for ${selectedScenario.name}...`);
    log(`Target Host: WIN-WORKSTATION-01 (192.168.56.101)`);

    for (let i = 0; i < selectedScenario.stages.length; i++) {
      await new Promise((res) => setTimeout(res, 600));
      log(`Executing ${selectedScenario.stages[i]}...`);
    }

    try {
      log('Injecting security telemetry sequence into BlueOps ingestion pipeline...');
      const res = await api.simulateAttack(selectedScenario.id);
      log(`Injection complete: ${res.eventsInjected} events ingested, ${res.findingsGenerated} findings generated, ${res.correlationsGenerated ?? 0} correlation(s) created.`);
      setSimulationResult(res);
    } catch (err: any) {
      log(`Simulation error: ${err.message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#212738]">
        <div>
          <h1 className="text-xl font-bold font-mono uppercase tracking-wider text-white flex items-center gap-2">
            <Crosshair className="w-5 h-5 text-rose-500" />
            Adversary Emulation Engine (BAS)
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Automated MITRE ATT&CK adversary emulation & continuous detection validation
          </p>
        </div>
        <div className="flex items-center gap-3">
          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('incidents')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0c0e15] border border-[#212738] hover:border-slate-600 text-slate-300 rounded text-xs font-mono font-medium transition-colors"
            >
              Incident Center
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Live Emulation Telemetry Summary (No Hardcoded Benchmark Claims) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Selected Scenario</div>
          <div className="text-2xl font-bold text-rose-400 mt-1 font-mono">{selectedScenario.id}</div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono">{selectedScenario.severity} severity</div>
        </div>
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Events Injected</div>
          <div className="text-2xl font-bold text-sky-400 mt-1 font-mono">{simulationResult ? simulationResult.eventsInjected : '--'}</div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono">{simulationResult ? 'Last emulation run' : 'Run scenario to measure'}</div>
        </div>
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Findings Generated</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono">{simulationResult ? simulationResult.findingsGenerated : '--'}</div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono">{simulationResult ? 'Evaluated via Sigma & IOC' : 'Awaiting run'}</div>
        </div>
        <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Correlations Created</div>
          <div className="text-2xl font-bold text-indigo-400 mt-1 font-mono">{simulationResult ? (simulationResult.correlationsGenerated ?? 0) : '--'}</div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono">Authoritative CorrelationService</div>
        </div>
      </div>

      {/* Main Simulation Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Scenario Selector */}
        <div className="lg:col-span-5 space-y-4">
          <h2 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            Available Emulation Scenarios
          </h2>
          <div className="space-y-3">
            {SCENARIOS.map((sc) => {
              const isSelected = selectedScenario.id === sc.id;
              return (
                <div
                  key={sc.id}
                  onClick={() => !running && setSelectedScenario(sc)}
                  className={`p-3.5 rounded-md border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-rose-950/20 border-rose-500/70 shadow-lg shadow-rose-950/20'
                      : 'bg-[#11141d] border-[#212738] hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 bg-[#0c0e15] border border-[#212738] text-rose-400 rounded">
                      {sc.id}
                    </span>
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 bg-rose-950/60 text-rose-300 border border-rose-800/40 rounded uppercase">
                      {sc.severity}
                    </span>
                  </div>
                  <h3 className="font-semibold text-white text-xs mt-2">{sc.name}</h3>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{sc.description}</p>
                  <div className="flex flex-wrap gap-1 mt-3">
                    {sc.mitreTechniques.map((tech) => (
                      <span key={tech} className="text-[10px] font-mono px-1.5 py-0.5 bg-[#0c0e15] text-slate-300 border border-[#212738] rounded">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Execution Console */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-[#11141d] border border-[#212738] rounded-md p-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#212738]">
              <div>
                <span className="text-[10px] font-mono text-rose-400 font-semibold">{selectedScenario.id}</span>
                <h2 className="text-sm font-bold text-white mt-0.5">{selectedScenario.name}</h2>
              </div>
              <button
                onClick={handleRunSimulation}
                disabled={running}
                className={`px-3 py-1.5 rounded font-mono text-xs font-semibold flex items-center gap-2 transition-all ${
                  running
                    ? 'bg-[#0c0e15] text-slate-500 border border-[#212738] cursor-not-allowed'
                    : 'bg-rose-600 hover:bg-rose-500 text-white'
                }`}
              >
                {running ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                {running ? 'Running Emulation...' : 'Execute Emulation'}
              </button>
            </div>

            {/* Stages Breakdown */}
            <div className="mt-4 space-y-2">
              <div className="text-[10px] font-mono uppercase font-semibold text-slate-400 tracking-wider">Attack Sequence Stages:</div>
              <div className="space-y-1.5">
                {selectedScenario.stages.map((stg, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-xs text-slate-300 font-mono bg-[#0c0e15] px-3 py-1.5 rounded border border-[#212738]">
                    <span className="w-4 h-4 rounded-full bg-[#181d2a] text-slate-400 flex items-center justify-center text-[10px] font-bold">
                      {idx + 1}
                    </span>
                    {stg}
                  </div>
                ))}
              </div>
            </div>

            {/* Terminal Live Output */}
            <div className="mt-4">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  Execution Terminal Stream
                </span>
                <span className="text-[10px] text-slate-500 font-mono">TELEMETRY INGESTION BUS</span>
              </div>
              <div className="bg-[#0c0e15] border border-[#212738] rounded p-3 font-mono text-xs text-emerald-400 h-64 overflow-y-auto space-y-1">
                {executionLogs.length === 0 ? (
                  <div className="text-slate-600 italic">
                    Adversary validation engine idle. Select an attack scenario and click "Execute Emulation" to trigger verification.
                  </div>
                ) : (
                  executionLogs.map((l, i) => <div key={i}>{l}</div>)
                )}
              </div>
            </div>

            {/* Simulation Findings Result Box */}
            {simulationResult && (
              <div className="mt-4 p-3.5 bg-emerald-950/30 border border-emerald-500/50 rounded space-y-2">
                <div className="flex items-center gap-2 text-emerald-400 font-mono font-bold text-xs uppercase tracking-wider">
                  <CheckCircle2 className="w-4 h-4" />
                  Validation Complete: {simulationResult.findingsGenerated} Finding(s) Generated
                </div>
                <p className="text-xs text-slate-300 font-mono">
                  {simulationResult.message}
                </p>
                <div className="flex items-center gap-3 pt-1">
                  {onNavigateTab && (
                    <>
                      <button
                        onClick={() => onNavigateTab('incidents')}
                        className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-mono font-medium flex items-center gap-1.5 transition-colors"
                      >
                        Inspect Correlated Incident
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => onNavigateTab('telemetry')}
                        className="px-2.5 py-1 bg-[#0c0e15] hover:bg-[#181d2a] border border-[#212738] text-slate-200 rounded text-xs font-mono transition-colors"
                      >
                        Inspect Raw Events
                      </button>
                    </>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
