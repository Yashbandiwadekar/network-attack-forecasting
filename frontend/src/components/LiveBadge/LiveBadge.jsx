import React, { useEffect, useState } from 'react';
import { liveApi } from '../../api/live';

/* Feed-state badge for the dashboard header (docs/11). Polls /api/v1/live/status with the same 5 s
   cadence as the host list. The point is that a REPLAY must never be mistaken for live traffic:
     LIVE   green  - tailing a dumpcap ring, data arriving
     REPLAY amber  - a recorded capture is being replayed (labelled, never styled as live)
     STALE  red    - the feed is running but no data for more than 30 s
     OFF    grey   - no live engine; the dashboard shows whatever was uploaded */

const STYLE = {
  LIVE: { color: '#22c55e', label: 'LIVE' },
  REPLAY: { color: '#f59e0b', label: 'REPLAY' },
  STALE: { color: '#ef4444', label: 'STALE' },
  OFF: { color: '#6b7280', label: 'NO LIVE FEED' },
  UNKNOWN: { color: '#6b7280', label: 'FEED UNKNOWN' },
};

export function describeLive(status) {
  if (!status) return { state: 'UNKNOWN', detail: '' };
  const state = status.state || 'OFF';
  if (state === 'OFF') return { state, detail: 'upload mode' };
  const bits = [];
  if (status.source) bits.push(status.source);
  if (typeof status.packets_per_s === 'number') bits.push(`${status.packets_per_s} pkt/s`);
  if (typeof status.hosts_scored === 'number') {
    bits.push(`${status.hosts_scored} scored / ${status.hosts_warming_up ?? 0} warming up`);
  }
  if (status.last_window_time) bits.push(`last window ${status.last_window_time}`);
  if (typeof status.lag_seconds === 'number') bits.push(`lag ${status.lag_seconds}s`);
  if (status.state === 'STALE' && status.seconds_since_data != null) bits.push(`no data for ${status.seconds_since_data}s`);
  if (status.finished) bits.push('replay finished');
  const dropped = status.dropped
    ? (status.dropped.late_packets || 0) + (status.dropped.buffer_overflow_packets || 0) + (status.dropped.files_failed || 0)
    : 0;
  if (dropped) bits.push(`${dropped} dropped`);
  return { state, detail: bits.join(' · ') };
}

const LiveBadge = ({ pollMs = 5000 }) => {
  const [status, setStatus] = useState(null);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const s = await liveApi.getStatus();
        if (alive) setStatus(s);
      } catch {
        if (alive) setStatus(null);
      }
    };
    poll();
    const id = setInterval(poll, pollMs);
    return () => { alive = false; clearInterval(id); };
  }, [pollMs]);

  const { state, detail } = describeLive(status);
  const st = STYLE[state] || STYLE.UNKNOWN;
  return (
    <span className="font-mono" data-testid="live-badge" data-state={state}
      title={detail || st.label}
      style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem' }}>
      <strong data-testid="live-badge-state"
        style={{ color: '#fff', background: st.color, borderRadius: 4, padding: '0.15rem 0.55rem', letterSpacing: '0.05em' }}>
        {st.label}
      </strong>
      {detail && <span data-testid="live-badge-detail" style={{ color: 'var(--text-3)' }}>{detail}</span>}
    </span>
  );
};

export default LiveBadge;
