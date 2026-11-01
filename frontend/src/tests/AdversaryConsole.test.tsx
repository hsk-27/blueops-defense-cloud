import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { AdversaryConsolePage } from '../pages/AdversaryConsolePage';

// Mock api
vi.mock('../services/api', () => ({
  api: {
    simulateAttack: vi.fn().mockResolvedValue({
      scenario: 'C002',
      eventsInjected: 4,
      findingsGenerated: 3,
      message: 'Simulated attack sequence successfully ingested.'
    })
  }
}));

describe('AdversaryConsolePage', () => {
  it('renders adversary console title and scenarios list', () => {
    render(<AdversaryConsolePage />);
    expect(screen.getByText('Adversary Simulation Console')).toBeDefined();
    expect(screen.getAllByText('Windows Multi-Stage APT Execution Chain').length).toBeGreaterThan(0);
    expect(screen.getByText('Linux Account Compromise & Privilege Escalation')).toBeDefined();
    expect(screen.getByText('Launch Simulation')).toBeDefined();
  });
});
