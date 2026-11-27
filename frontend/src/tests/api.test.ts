import { describe, it, expect, beforeEach, vi } from 'vitest';
import { api, ApiError } from '../services/api';

describe('api contract handling', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('unwraps ApiResponse<T> envelopes cleanly', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          success: true,
          message: 'Authentication successful',
          data: { accessToken: 'acc-123', username: 'analyst' },
          timestamp: '2026-11-27T10:00:00Z'
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = await api.login({ username: 'analyst', password: 'pw' });
    expect(result).toEqual({ accessToken: 'acc-123', username: 'analyst' });
  });

  it('preserves raw payloads for non-wrapped endpoints (telemetry, health, soar)', async () => {
    const rawEvents = [{ id: 'evt-1', host: { name: 'WIN-01' } }];
    const health = { status: 'UP', database: 'CONNECTED', rulesEngine: 'OPERATIONAL', rulesCount: 18 };
    const pagedProposals = { content: [{ id: 1, proposalUuid: 'PROP-1' }], totalElements: 1 };

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(rawEvents), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(health), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(pagedProposals), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    expect(await api.getRecentTelemetry(50)).toEqual(rawEvents);
    expect(await api.getSystemHealth()).toEqual(health);
    expect(await api.getResponseProposals()).toEqual(pagedProposals);
  });

  it('handles 204 and empty body responses without JSON parse failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    await expect(api.deleteIoc(42)).resolves.toBeUndefined();
  });

  it('throws ApiError on HTTP error and clears tokens on 401', async () => {
    localStorage.setItem('blueops_token', 'stale');
    localStorage.setItem('blueops_refresh_token', 'stale-ref');
    localStorage.setItem('blueops_user', '{"username":"analyst"}');

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ message: 'Unauthorized token' }), { status: 401 })
      )
    );

    await expect(api.getSystemDiagnostics()).rejects.toBeInstanceOf(ApiError);
    expect(localStorage.getItem('blueops_token')).toBeNull();
    expect(localStorage.getItem('blueops_refresh_token')).toBeNull();
    expect(localStorage.getItem('blueops_user')).toBeNull();
  });
});
