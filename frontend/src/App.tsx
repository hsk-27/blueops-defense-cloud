import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { LoginPage } from './pages/LoginPage';
import { OverviewPage } from './pages/OverviewPage';
import { IncidentCenterPage } from './pages/IncidentCenterPage';
import { InvestigationWorkspacePage } from './pages/InvestigationWorkspacePage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { AssetInventoryPage } from './pages/AssetInventoryPage';
import { DetectionManagementPage } from './pages/DetectionManagementPage';
import { ResponseManagementPage } from './pages/ResponseManagementPage';
import { AuditReportsPage } from './pages/AuditReportsPage';
import { LiveTelemetryPage } from './pages/LiveTelemetryPage';
import { AdversaryConsolePage } from './pages/AdversaryConsolePage';

const MainLayout: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const [currentTab, setCurrentTab] = useState('overview');
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);

  // Response pre-fill state
  const [responseContext, setResponseContext] = useState<{
    playbookCode?: string;
    target?: string;
    incidentId?: number;
  }>({});

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  const navigateToIncident = (id: number) => {
    setSelectedIncidentId(id);
    setCurrentTab('investigation');
  };

  const navigateToResponse = (playbookCode: string, target: string, incId: number) => {
    setResponseContext({ playbookCode, target, incidentId: incId });
    setCurrentTab('response');
  };

  const getPageTitle = () => {
    switch (currentTab) {
      case 'overview': return { title: 'Executive Security Dashboard', subtitle: 'Enterprise Threat Telemetry & SecOps Health' };
      case 'telemetry': return { title: 'Live Telemetry Ingestion Pipeline', subtitle: 'Real-Time Common Event Schema (CES v1.0.0) Normalization' };
      case 'simulation': return { title: 'Breach & Attack Simulation (BAS) Engine', subtitle: 'Continuous Adversary Validation & MITRE ATT&CK Evaluation' };
      case 'incidents': return { title: 'Threat Triage & Incident Queue', subtitle: 'Correlated Security Cases & Forensic Lifecycle' };
      case 'investigation': return { title: 'Forensic Investigation Workspace', subtitle: `Case #${selectedIncidentId} • Authoritative Incident Advisory System` };
      case 'threat-intel': return { title: 'Threat Intelligence & IOC Management', subtitle: 'Global Indicator Feeds & In-Stream Hash/IP Matching' };
      case 'assets': return { title: 'Attack Surface & Asset Inventory', subtitle: 'Monitored Host Telemetry, Kernel Sensors & Perimeter TAPs' };
      case 'detections': return { title: 'Detection Engineering & Sigma Analytics', subtitle: 'Production Sigma Detection Rules & ATT&CK Heatmap' };
      case 'response': return { title: 'Autonomous Response Orchestration', subtitle: 'Cryptographically Signed & Reversible Remediation Playbooks' };
      case 'audit': return { title: 'Forensic Audit & Compliance Ledger', subtitle: 'Immutable Event Trail & Regulatory Reporting' };
      default: return { title: 'BlueOps Enterprise SecOps Cloud', subtitle: 'Autonomous Threat Detection & Response' };
    }
  };

  const { title, subtitle } = getPageTitle();

  return (
    <div className="flex bg-[#090a0f] min-h-screen text-slate-100 font-sans selection:bg-rose-900 selection:text-white">
      <Sidebar
        currentTab={currentTab === 'investigation' ? 'incidents' : currentTab}
        onSelectTab={(tab) => {
          setSelectedIncidentId(null);
          setCurrentTab(tab);
        }}
      />

      <main className="flex-1 flex flex-col min-w-0">
        <Header title={title} subtitle={subtitle} />

        <div className="flex-1 p-6">
          {currentTab === 'overview' && <OverviewPage onNavigateToIncident={navigateToIncident} />}
          {currentTab === 'telemetry' && <LiveTelemetryPage />}
          {currentTab === 'simulation' && <AdversaryConsolePage onNavigateTab={(tab) => setCurrentTab(tab)} />}
          {currentTab === 'incidents' && <IncidentCenterPage onSelectIncident={navigateToIncident} />}
          {currentTab === 'investigation' && selectedIncidentId && (
            <InvestigationWorkspacePage
              incidentId={selectedIncidentId}
              onBack={() => {
                setSelectedIncidentId(null);
                setCurrentTab('incidents');
              }}
              onNavigateToResponse={navigateToResponse}
            />
          )}
          {currentTab === 'threat-intel' && <ThreatIntelPage />}
          {currentTab === 'assets' && <AssetInventoryPage />}
          {currentTab === 'detections' && <DetectionManagementPage />}
          {currentTab === 'response' && (
            <ResponseManagementPage
              initialPlaybook={responseContext.playbookCode}
              initialTarget={responseContext.target}
              initialIncidentId={responseContext.incidentId}
            />
          )}
          {currentTab === 'audit' && <AuditReportsPage />}
        </div>
      </main>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <MainLayout />
    </AuthProvider>
  );
};

export default App;
