import React from 'react';
import './TelemetryStrip.css';

const fmt = (n) => (typeof n === 'number' ? n.toLocaleString() : '—');

/**
 * Telemetry readout, driven entirely by /api/v1/system/status.
 *
 * This used to hold six hardcoded values (12,482 flows, 19 high-risk hosts, ...) which stayed
 * on screen even when a real capture was loaded, so the strip contradicted the host table
 * directly beneath it. It now renders whatever the caller passes: live status on the dashboard,
 * a recorded run on the landing page, and an explicit idle state when nothing is loaded.
 *
 * @param {object|null} status  A /system/status payload.
 * @param {number} hostCount    Scored hosts (falls back to status.active_monitored_hosts).
 */
const TelemetryStrip = ({ status = null, hostCount = null }) => {
  const hasData = status && (status.total_active_flows || status.active_monitored_hosts);

  const readouts = hasData
    ? [
        { label: 'FLOWS ANALYSED', value: fmt(status.total_active_flows), status: 'normal' },
        { label: 'MONITORED HOSTS', value: fmt(hostCount ?? status.active_monitored_hosts), status: 'normal' },
        {
          label: 'HIGH-RISK HOSTS',
          value: fmt(status.high_risk_hosts),
          status: status.high_risk_hosts > 0 ? 'critical' : 'normal',
        },
        {
          label: 'FORECAST HORIZON',
          value: status.horizon_seconds ? `${status.horizon_seconds}s` : '—',
          status: 'forecast',
        },
        {
          label: 'AUDIT LEDGER',
          value:
            typeof status.ledger_entries === 'number'
              ? `${status.ledger_entries} ${status.ledger_intact ? '✓' : '✗'}`
              : '—',
          status: status.ledger_intact === false ? 'critical' : 'normal',
        },
        {
          label: 'MODEL',
          value: status.model_loaded ? 'LOADED' : 'NOT LOADED',
          status: status.model_loaded ? 'normal' : 'warning',
        },
      ]
    : [
        { label: 'FLOWS ANALYSED', value: '—', status: 'normal' },
        { label: 'MONITORED HOSTS', value: '—', status: 'normal' },
        { label: 'HIGH-RISK HOSTS', value: '—', status: 'normal' },
        { label: 'FORECAST HORIZON', value: '60s', status: 'forecast' },
        { label: 'AUDIT LEDGER', value: '—', status: 'normal' },
        { label: 'MODEL', value: status?.model_loaded ? 'LOADED' : 'STANDBY', status: 'normal' },
      ];

  return (
    <div className="telemetry-strip-container">
      <div className="telemetry-strip">
        {readouts.map((item) => (
          <div key={item.label} className={`telemetry-item ${item.status}`}>
            <span className="telemetry-label">{item.label}</span>
            <span className="telemetry-val">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default TelemetryStrip;
