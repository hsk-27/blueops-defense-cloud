import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ResponseManagementPage } from '../pages/ResponseManagementPage';
import { api } from '../services/api';

let currentRole = 'ROLE_ANALYST';
let currentUsername = 'analyst';

vi.mock('../context/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 1, username: currentUsername, email: 'u@blueops.local', fullName: 'User', role: currentRole, enabled: true },
    token: 'tok',
    login: vi.fn(),
    logout: vi.fn(),
    isAuthenticated: true,
    isAdmin: currentRole === 'ROLE_ADMIN'
  })
}));

describe('ResponseManagementPage governance & truthful verification', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    currentRole = 'ROLE_ANALYST';
    currentUsername = 'analyst';
  });

  it('renders SIMULATION_ONLY / SIMULATED honestly without claiming independent verification', async () => {
    vi.spyOn(api, 'getResponseProposals').mockResolvedValue({
      content: [
        {
          id: 1,
          proposalUuid: 'PROP-SIM-01',
          actionCode: 'ACT-001',
          actionName: 'Block Lab IP',
          actionType: 'DEFENSIVE_CONTAINMENT',
          targetIdentifier: '198.51.100.24',
          targetType: 'IP',
          proposedBy: 'analyst',
          proposedAt: '2026-11-27T10:00:00Z',
          riskLevel: 'MODERATE',
          executionMode: 'SIMULATION',
          policyOutcome: 'REQUIRE_APPROVAL',
          status: 'SIMULATED',
          requiresApproval: true,
          createdAt: '2026-11-27T10:00:00Z',
          updatedAt: '2026-11-27T10:00:00Z',
          verification: {
            id: 10,
            verificationUuid: 'VER-001',
            proposalId: 1,
            status: 'SIMULATION_ONLY',
            verificationMethod: 'SIMULATION_DRY_RUN',
            expectedOutcome: '[Simulation dry-run] DROP',
            observedOutcome: 'Simulation only (dry-run): no host mutation occurred',
            verifiedAt: '2026-11-27T10:00:01Z',
            isSimulation: true
          }
        }
      ],
      totalElements: 1
    });
    vi.spyOn(api, 'getResponseCatalog').mockResolvedValue([]);
    vi.spyOn(api, 'getResponseTargets').mockResolvedValue([]);

    render(<ResponseManagementPage />);

    await waitFor(() => expect(screen.getByText('PROP-SIM-01')).toBeDefined());
    expect(screen.getByText('SIMULATED ONLY')).toBeDefined();
    expect(screen.queryByText('INDEPENDENTLY VERIFIED')).toBeNull();
  });

  it('hides mutation controls from VIEWER and hides Approve/Deny/Execute from ANALYST', async () => {
    const pendingProposal = {
      id: 2,
      proposalUuid: 'PROP-PND-02',
      actionCode: 'ACT-002',
      actionName: 'Disable User',
      actionType: 'ACCESS_CONTROL',
      targetIdentifier: 'CORP\\analyst',
      targetType: 'USERNAME',
      proposedBy: 'analyst',
      proposedAt: '2026-11-27T10:00:00Z',
      riskLevel: 'HIGH' as const,
      executionMode: 'SIMULATION' as const,
      policyOutcome: 'REQUIRE_APPROVAL' as const,
      status: 'PENDING_APPROVAL' as const,
      requiresApproval: true,
      createdAt: '2026-11-27T10:00:00Z',
      updatedAt: '2026-11-27T10:00:00Z'
    };

    vi.spyOn(api, 'getResponseProposals').mockResolvedValue({ content: [pendingProposal], totalElements: 1 });
    vi.spyOn(api, 'getResponseCatalog').mockResolvedValue([]);
    vi.spyOn(api, 'getResponseTargets').mockResolvedValue([]);

    currentRole = 'ROLE_VIEWER';
    currentUsername = 'viewer';
    const { rerender } = render(<ResponseManagementPage />);
    await waitFor(() => expect(screen.getByText('PROP-PND-02')).toBeDefined());
    expect(screen.queryByText('New Response Proposal')).toBeNull();
    expect(screen.queryByText('Approve')).toBeNull();
    expect(screen.queryByText('Cancel')).toBeNull();

    currentRole = 'ROLE_ANALYST';
    currentUsername = 'analyst';
    rerender(<ResponseManagementPage />);
    await waitFor(() => expect(screen.getByText('New Response Proposal')).toBeDefined());
    expect(screen.getByText('Cancel')).toBeDefined();
    expect(screen.queryByText('Approve')).toBeNull();
    expect(screen.queryByText('Deny')).toBeNull();
  });

  it('surfaces explicit error state rather than masking failed SOAR API requests', async () => {
    vi.spyOn(api, 'getResponseProposals').mockRejectedValue(new Error('SOAR backend unreachable'));
    vi.spyOn(api, 'getResponseCatalog').mockResolvedValue([]);
    vi.spyOn(api, 'getResponseTargets').mockResolvedValue([]);

    render(<ResponseManagementPage />);
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('SOAR backend unreachable'));
  });
});
