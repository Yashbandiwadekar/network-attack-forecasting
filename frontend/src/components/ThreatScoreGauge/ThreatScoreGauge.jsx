import React from 'react';
import './ThreatScoreGauge.css';

const ThreatScoreGauge = ({
  score = 0.87,
  horizon = 6,
  confidence = null,
  attackFamily = 'Command & Control',
  rationale = [
    'Packet burst rate exceeds baseline threshold (> 145 pkts/sec)',
    'Persistent lateral session targeting destination 10.0.4.5:443',
    'Sequential transition probability aligns with ATT&CK T1071'
  ]
}) => {
  const displayScore = typeof score === 'number' ? score.toFixed(2) : '0.00';
  const displayConfidence = confidence !== null && confidence !== undefined 
    ? (typeof confidence === 'number' ? `${(confidence * 100).toFixed(1)}%` : confidence)
    : `${(score * 100).toFixed(1)}%`;

  const isHighRisk = score >= 0.65;

  return (
    <div className="threat-gauge-panel">
      <div className="gauge-header">
        <span className="panel-mono-title">TELEMETRY THREAT SCORE</span>
        <span className={`panel-status-tag ${isHighRisk ? 'critical' : 'warning'}`}>
          {isHighRisk ? 'ALERT HIGH RISK' : 'MODERATE RISK'}
        </span>
      </div>

      <div className="gauge-body">
        <div className="gauge-metric-box">
          <span className="gauge-score">{displayScore}</span>
          <span className="gauge-scale">/ 1.00</span>
        </div>

        <div className="gauge-details">
          <div className="gauge-detail-row">
            <span className="detail-label">Attack Family</span>
            <span className="detail-val text-red">{attackFamily}</span>
          </div>
          <div className="gauge-detail-row">
            <span className="detail-label">Forecast Horizon</span>
            <span className="detail-val text-amber">K = {horizon} (60s)</span>
          </div>
          <div className="gauge-detail-row">
            <span className="detail-label">Model Confidence</span>
            <span className="detail-val text-orange">{displayConfidence}</span>
          </div>
        </div>
      </div>

      <div className="gauge-evidence-box">
        <span className="evidence-title">OBSERVED EVIDENCE RATIONALE</span>
        <ul className="evidence-list">
          {rationale.map((item, idx) => (
            <li key={idx}>{item}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default ThreatScoreGauge;
