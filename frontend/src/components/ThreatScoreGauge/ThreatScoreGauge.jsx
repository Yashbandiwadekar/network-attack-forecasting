import React from 'react';
import './ThreatScoreGauge.css';

const ThreatScoreGauge = () => {
  return (
    <div className="threat-gauge-panel">
      <div className="gauge-header">
        <span className="panel-mono-title">TELEMETRY THREAT SCORE</span>
        <span className="panel-status-tag critical">ALERT HIGH RISK</span>
      </div>

      <div className="gauge-body">
        <div className="gauge-metric-box">
          <span className="gauge-score">0.87</span>
          <span className="gauge-scale">/ 1.00</span>
        </div>

        <div className="gauge-details">
          <div className="gauge-detail-row">
            <span className="detail-label">Attack Family</span>
            <span className="detail-val text-red">Command & Control</span>
          </div>
          <div className="gauge-detail-row">
            <span className="detail-label">Forecast Horizon</span>
            <span className="detail-val text-amber">K = 5</span>
          </div>
          <div className="gauge-detail-row">
            <span className="detail-label">Model Confidence</span>
            <span className="detail-val text-orange">91.2%</span>
          </div>
        </div>
      </div>

      <div className="gauge-evidence-box">
        <span className="evidence-title">OBSERVED EVIDENCE RATIONALE</span>
        <ul className="evidence-list">
          <li>Packet burst rate exceeds baseline threshold (&gt; 145 pkts/sec)</li>
          <li>Persistent lateral session targeting destination 10.0.4.5:443</li>
          <li>Sequential transition probability aligns with ATT&CK T1071</li>
        </ul>
      </div>
    </div>
  );
};

export default ThreatScoreGauge;
