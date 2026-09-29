import { describe, it, expect, vi, beforeEach } from 'vitest';
import { systemApi, forecastApi, analysisApi } from '../api';

/* These assert RELATIVE request paths. The client used to default to an absolute
   http://127.0.0.1:8000, which meant a dashboard opened from another device over the LAN called
   back to that device's own loopback and silently failed. The deployed setup serves the built
   dashboard from the API itself, so a relative path is correct on localhost, on a LAN IP and
   behind a proxy alike. VITE_API_BASE_URL still overrides it for split development. */

describe('Frontend API Client Layer', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('systemApi.getStatus calls /api/v1/system/status', async () => {
    const mockResponse = { status: 'healthy', active_model: 'XGBoost+Markov', uptime: 3600 };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockResponse,
    });

    const res = await systemApi.getStatus();
    expect(global.fetch).toHaveBeenCalledWith(
      '/api/v1/system/status',
      expect.objectContaining({
        headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
      })
    );
    expect(res).toEqual(mockResponse);
  });

  it('forecastApi.predict calls /api/v1/forecast/predict with host_ip and horizon', async () => {
    const mockForecast = {
      host_ip: '10.0.4.5',
      k_steps: 5,
      infiltration_probs: [0.08, 0.14, 0.27, 0.41, 0.63],
      predicted_stages: ['RECON', 'RECON', 'WEAPONIZATION', 'EXPLOITATION', 'LATERAL_MOVEMENT'],
      stage_is_heuristic: false,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockForecast,
    });

    const res = await forecastApi.predict('10.0.4.5', 5);
    expect(global.fetch).toHaveBeenCalledWith(
      '/api/v1/forecast/predict',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ host_ip: '10.0.4.5', horizon: 5 }),
      })
    );
    expect(res.infiltration_probs).toHaveLength(5);
  });

  it('analysisApi.uploadFile sends FormData to /api/v1/analysis/upload', async () => {
    const mockUploadRes = {
      status: 'success',
      message: 'Ingested capture file test.pcap',
      new_host_ip: '10.0.4.99',
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockUploadRes,
    });

    const file = new File(['fake pcap content'], 'test.pcap', { type: 'application/vnd.tcpdump.pcap' });
    const res = await analysisApi.uploadFile(file);

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/v1/analysis/upload',
      expect.objectContaining({
        method: 'POST',
        body: expect.any(FormData),
      })
    );
    expect(res.status).toBe('success');
  });

  it('handles HTTP error responses gracefully', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => 'Internal Server Error',
    });

    await expect(systemApi.getStatus()).rejects.toThrow();
  });
});
