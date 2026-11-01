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
      case 'overview': return { title: 'Security Operations Center Overview', subtitle: 'Live Telemetry Analytics & Metrics' };
      case 'telemetry': return { title: 'Live Telemetry Event Stream', subtitle: 'Ingestion & Normalization into Common Event Schema (CES v1.0.0)' };
      case 'simulation': return { title: 'Adversary Simulation Console', subtitle: 'Empirical Attack Testing & Detection Benchmark' };
      case 'incidents': return { title: 'Incident Center', subtitle: 'Threat Triage & Lifecycle Queue' };
      case 'investigation': return { title: 'Incident Investigation Workspace', subtitle: `Deep-Dive Case Analysis #${selectedIncidentId}` };
      case 'threat-intel': return { title: 'Threat Intelligence & IOC Hub', subtitle: 'Indicator Management & Telemetry Matching' };
      case 'assets': return { title: 'Asset Inventory & Telemetry Health', subtitle: 'Monitored Endpoints & Perimeter Sensors' };
      case 'detections': return { title: 'Detection Rule Management', subtitle: 'Sigma Analytics & MITRE ATT&CK Mapping' };
      case 'response': return { title: 'Automated Incident Response Hub', subtitle: 'Constrained Reversible Playbooks' };
      case 'audit': return { title: 'Compliance Audit & Reports', subtitle: 'System Audit Logs & Empirical Attack Coverage' };
      default: return { title: 'BlueOps SOC Platform', subtitle: 'Enterprise Security' };
    }
  };

  const { title, subtitle } = getPageTitle();

  return (
    <div className="flex bg-[#0a0d14] min-h-screen text-slate-100 font-sans">
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
