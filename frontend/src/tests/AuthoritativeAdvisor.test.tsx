import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { AuthoritativeAdvisor } from '../components/AuthoritativeAdvisor';
import { IncidentRecommendation } from '../types';

describe('AuthoritativeAdvisor Component', () => {
  const mockRecommendations: IncidentRecommendation[] = [
    {
      id: 'ADV-NET-001',
      title: 'Apply Perimeter Drop Rule for Malicious C2 Communication',
      phase: 'CONTAINMENT',
      priority: 'IMMEDIATE_ACTION',
      authoritativeSource: 'CISA_IR_PLAYBOOK',
      citation: 'CISA IR Playbook §3.3',
      rationale: 'Block adversary egress to known C2 indicator.',
      actionableSteps: ['Apply firewall drop rule', 'Inspect DNS query logs'],
      suggestedPlaybookCode: 'P001',
      suggestedPlaybookName: 'Block Suspicious Lab IP',
      suggestedTarget: '198.51.100.24',
      applicableTechniques: ['T1071']
    },
    {
      id: 'ADV-IAM-001',
      title: 'Invalidate Sessions and Disable Potentially Compromised Accounts',
      phase: 'CONTAINMENT',
      priority: 'IMMEDIATE_ACTION',
      authoritativeSource: 'NIST_SP_800_61R2',
      citation: 'NIST SP 800-61r2 §3.3.1',
      rationale: 'Lock credentials upon observing credential dumping.',
      actionableSteps: ['Disable user account', 'Terminate active Kerberos tickets'],
      suggestedPlaybookCode: 'P002',
      suggestedPlaybookName: 'Disable Compromised Test Account',
      suggestedTarget: 'analyst',
      applicableTechniques: ['T1003.001']
    }
  ];

  it('renders advisor header and recommendations count', () => {
    render(<AuthoritativeAdvisor recommendations={mockRecommendations} />);
    expect(screen.getByText('Authoritative Incident Advisor')).toBeDefined();
    expect(screen.getByText('2 Actionable Steps')).toBeDefined();
    expect(screen.getByText('NIST SP 800-61r2')).toBeDefined();
    expect(screen.getByText('CISA Federal IR')).toBeDefined();
  });

  it('renders playbook quick launch and triggers handler', () => {
    const handleLaunch = vi.fn();
    render(
      <AuthoritativeAdvisor
        recommendations={mockRecommendations}
        onLaunchPlaybook={handleLaunch}
      />
    );

    const launchButtons = screen.getAllByText('Launch Playbook');
    expect(launchButtons.length).toBeGreaterThan(0);

    fireEvent.click(launchButtons[0]);
    expect(handleLaunch).toHaveBeenCalledWith('P001', '198.51.100.24');
  });
});
