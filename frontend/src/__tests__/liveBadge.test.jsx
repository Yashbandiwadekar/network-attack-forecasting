import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import LiveBadge, { describeLive } from '../components/LiveBadge/LiveBadge';
import { liveApi } from '../api/live';

vi.mock('../api/live', () => ({ liveApi: { getStatus: vi.fn() } }));

describe('LiveBadge', () => {
  beforeEach(() => vi.clearAllMocks());

  it.each([
    ['LIVE', 'LIVE'],
    ['REPLAY', 'REPLAY'],
    ['STALE', 'STALE'],
    ['OFF', 'NO LIVE FEED'],
  ])('renders the %s state distinctly', async (state, label) => {
    liveApi.getStatus.mockResolvedValue({
      state, source: 'x', packets_per_s: 12.5, hosts_scored: 2, hosts_warming_up: 1, lag_seconds: 3, seconds_since_data: 44,
    });
    render(<LiveBadge pollMs={100000} />);
    await waitFor(() => expect(screen.getByTestId('live-badge-state')).toHaveTextContent(label));
    expect(screen.getByTestId('live-badge')).toHaveAttribute('data-state', state);
  });

  it('shows throughput, warm-up and lag details for a running feed', () => {
    const { detail } = describeLive({ state: 'REPLAY', source: 'REPLAY:a.pcap', packets_per_s: 100, hosts_scored: 3, hosts_warming_up: 2, lag_seconds: 1.5 });
    expect(detail).toMatch(/REPLAY:a.pcap/);
    expect(detail).toMatch(/100 pkt\/s/);
    expect(detail).toMatch(/3 scored \/ 2 warming up/);
    expect(detail).toMatch(/lag 1.5s/);
  });

  it('falls back to an explicit unknown state when the status call fails', async () => {
    liveApi.getStatus.mockRejectedValue(new Error('down'));
    render(<LiveBadge pollMs={100000} />);
    await waitFor(() => expect(screen.getByTestId('live-badge')).toHaveAttribute('data-state', 'UNKNOWN'));
  });
});
