import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { LiveTelemetryPage } from '../pages/LiveTelemetryPage';
import { api } from '../services/api';

describe('LiveTelemetryPage pipeline contract & error handling', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders raw telemetry events and stats returned directly by backend', async () => {
    vi.spyOn(api, 'getRecentTelemetry').mockResolvedValue([
      {
        id: 'evt-fb-1',
        timestamp: '2026-11-27T10:00:00Z',
        event: { provider: 'Sysmon', category: ['process'], action: 'process_creation' },
        host: { name: 'WIN-WORKSTATION-01' },
        user: { name: 'analyst.dev' },
        process: { commandLine: 'powershell.exe -enc test' },
        blueops: { collector: 'fluent-bit', normalizationStatus: 'success' }
      }
    ]);
    vi.spyOn(api, 'getTelemetryStats').mockResolvedValue({
      totalReceived: 1,
      totalNormalized: 1,
      bufferedCount: 1,
      dlqCount: 0
    });
    vi.spyOn(api, 'getDeadLetterQueue').mockResolvedValue([]);

    render(<LiveTelemetryPage />);

    await waitFor(() => expect(screen.getByText('WIN-WORKSTATION-01')).toBeDefined());
    expect(screen.getAllByText('Sysmon').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('powershell.exe -enc test')).toBeDefined();
  });

  it('displays explicit error banner when telemetry API fails instead of silent empty state', async () => {
    vi.spyOn(api, 'getRecentTelemetry').mockRejectedValue(new Error('403 Forbidden'));
    vi.spyOn(api, 'getTelemetryStats').mockResolvedValue({ totalReceived: 0, totalNormalized: 0, bufferedCount: 0, dlqCount: 0 });
    vi.spyOn(api, 'getDeadLetterQueue').mockResolvedValue([]);

    render(<LiveTelemetryPage />);

    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('403 Forbidden'));
  });
});
