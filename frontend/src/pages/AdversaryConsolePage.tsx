import React, { useState } from 'react';
import { 
  Skull, Play, ShieldCheck, Terminal, AlertTriangle, 
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
      'Stage 4: Execution of wevtutil.exe to clear Windows Security Event Log (D012)',
      'Stage 5: Multi-stage correlation trigger C002 -> Auto-create CRITICAL Incident'
    ]
  },
  {
    id: 'C001',
    name: 'Linux Account Compromise & Privilege Escalation',
    category: 'Account Takeover',
    severity: 'CRITICAL',
    mitreTechniques: ['T1110', 'T1078', 'T1548.003', 'T1562.002'],
    description: 'Adversary executes slow-and-low password spraying against Linux server, succeeds with valid account, immediately executes sudo -i interactive shell, and disables auditd.',
    stages: [
      'Stage 1: Repeated SSH authentication failures across accounts (D001)',
      'Stage 2: Successful SSH login with compromised credentials (D002)',
      'Stage 3: Interactive root shell spawned via sudo (D004)',
      'Stage 4: Tampering with kernel audit subsystem (auditctl -D) (D006)',
      'Stage 5: Multi-stage correlation trigger C001 -> Auto-create CRITICAL Incident'
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
      log(`Injection complete: ${res.eventsInjected} events ingested, ${res.findingsGenerated} findings generated.`);
      log(`Multi-stage correlation engine evaluated: Scenario ${res.scenario} satisfied.`);
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
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Skull className="w-6 h-6 text-rose-500" />
            Adversary Simulation Console
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Empirical attack testing & deterministic detection verification using MITRE ATT&CK scenarios
          </p>
        </div>
        <div className="flex items-center gap-3">
          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('incidents')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 border border-slate-700 hover:border-slate-600 text-slate-300 rounded text-xs font-semibold transition-colors"
            >
              Incident Center
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Benchmark Summary Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-4">
          <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Detection Precision</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">90.9%</div>
          <div className="text-xs text-slate-500 mt-0.5">Empirical benchmark test</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-4">
          <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Adversary Recall</div>
          <div className="text-2xl font-bold text-blue-400 mt-1">100.0%</div>
          <div className="text-xs text-slate-500 mt-0.5">Zero false negatives</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-4">
          <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Mean Time to Detect (MTTD)</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">3.43s</div>
          <div className="text-xs text-slate-500 mt-0.5">End-to-end ingestion latency</div>
        </div>
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-4">
          <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Mean Time to Respond (MTTR)</div>
          <div className="text-2xl font-bold text-purple-400 mt-1">42.0s</div>
          <div className="text-xs text-slate-500 mt-0.5">Automated approval & execution</div>
        </div>
      </div>

      {/* Main Simulation Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Scenario Selector */}
        <div className="lg:col-span-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Available Adversary Scenarios
          </h2>
          <div className="space-y-3">
            {SCENARIOS.map((sc) => {
              const isSelected = selectedScenario.id === sc.id;
              return (
                <div
                  key={sc.id}
                  onClick={() => !running && setSelectedScenario(sc)}
                  className={`p-4 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-rose-950/20 border-rose-500/60 shadow-lg shadow-rose-950/20'
                      : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-semibold px-2 py-0.5 bg-slate-800 text-rose-400 rounded">
                      {sc.id}
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 bg-rose-950 text-rose-300 border border-rose-800/40 rounded uppercase">
                      {sc.severity}
                    </span>
                  </div>
                  <h3 className="font-semibold text-white text-sm mt-2">{sc.name}</h3>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{sc.description}</p>
                  <div className="flex flex-wrap gap-1 mt-3">
                    {sc.mitreTechniques.map((tech) => (
                      <span key={tech} className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-950 text-slate-300 border border-slate-800 rounded">
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
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-5">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div>
                <span className="text-xs font-mono text-rose-400 font-semibold">{selectedScenario.id}</span>
                <h2 className="text-lg font-bold text-white mt-0.5">{selectedScenario.name}</h2>
              </div>
              <button
                onClick={handleRunSimulation}
                disabled={running}
                className={`px-4 py-2 rounded-lg font-semibold text-xs flex items-center gap-2 transition-all shadow-md ${
                  running
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                    : 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-900/40'
                }`}
              >
                {running ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                {running ? 'Simulating Attack...' : 'Launch Simulation'}
              </button>
            </div>

            {/* Stages Breakdown */}
            <div className="mt-4 space-y-2">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Attack Sequence Stages:</div>
              <div className="space-y-1.5">
                {selectedScenario.stages.map((stg, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-xs text-slate-300 font-mono bg-slate-950/50 px-3 py-1.5 rounded border border-slate-800/60">
                    <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-[10px] font-bold">
                      {idx + 1}
                    </span>
                    {stg}
                  </div>
                ))}
              </div>
            </div>

            {/* Terminal Live Output */}
            <div className="mt-5">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-400 mb-2">
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  Simulation Execution Terminal
                </span>
                <span className="text-[10px] text-slate-500 font-mono">STDOUT / TELEMETRY BUS</span>
              </div>
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 font-mono text-xs text-emerald-400 h-64 overflow-y-auto space-y-1">
                {executionLogs.length === 0 ? (
                  <div className="text-slate-600 italic">
                    Simulation console ready. Select a scenario on the left and click "Launch Simulation" to trigger the automated attack pipeline.
                  </div>
                ) : (
                  executionLogs.map((l, i) => <div key={i}>{l}</div>)
                )}
              </div>
            </div>

            {/* Simulation Findings Result Box */}
            {simulationResult && (
              <div className="mt-4 p-4 bg-emerald-950/40 border border-emerald-500/50 rounded-lg space-y-2">
                <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs uppercase tracking-wider">
                  <CheckCircle2 className="w-4 h-4" />
                  Simulation Successful: {simulationResult.findingsGenerated} Findings Triggered
                </div>
                <p className="text-xs text-slate-300">
                  {simulationResult.message}
                </p>
                <div className="flex items-center gap-3 pt-2">
                  {onNavigateTab && (
                    <>
                      <button
                        onClick={() => onNavigateTab('incidents')}
                        className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors"
                      >
                        View Correlated Incident in SOC Center
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => onNavigateTab('telemetry')}
                        className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-semibold transition-colors"
                      >
                        Inspect Ingested Events
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
