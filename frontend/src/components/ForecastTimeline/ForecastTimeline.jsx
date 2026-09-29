import React from 'react';
import './ForecastTimeline.css';

const ForecastTimeline = () => {
  const observed = [
    { stage: 'Reconnaissance', desc: 'Port Scan / Host Discovery', status: 'observed' },
    { stage: 'Initial Access', desc: 'Exploit Public App (10.0.4.5)', status: 'observed' },
    { stage: 'Execution', desc: 'Command Shell Invocation', status: 'observed' },
    { stage: 'Command & Control', desc: 'Active C2 Beaconing (Port 443)', status: 'active' },
  ];

  const forecast = [
    { stage: 'Predicted C2 Escalation', desc: 'Multi-host Lateral Movement', confidence: '91.2%', risk: 'HIGH' },
    { stage: 'Predicted Data Exfiltration', desc: 'Staged Archive Transfer', confidence: '87.4%', risk: 'CRITICAL' },
    { stage: 'Predicted Impact', desc: 'Service Interruption Target', confidence: '79.8%', risk: 'HIGH' },
  ];

  return (
    <div className="forecast-timeline-panel">
      <div className="timeline-column observed-column">
        <div className="column-title">OBSERVED TRAFFIC STATES</div>
        {observed.map((item, idx) => (
          <div key={idx} className={`timeline-card ${item.status}`}>
            <div className="card-top">
              <span className="card-stage">{item.stage}</span>
              <span className="badge-observed">OBSERVED</span>
            </div>
            <p className="card-desc">{item.desc}</p>
          </div>
        ))}
      </div>

      <div className="horizon-divider">
        <div className="divider-line"></div>
        <span className="divider-label">FORECAST HORIZON (K = 5)</span>
        <div className="divider-line"></div>
      </div>

      <div className="timeline-column forecast-column">
        <div className="column-title">PREDICTED FUTURE THREAT STATES</div>
        {forecast.map((item, idx) => (
          <div key={idx} className="timeline-card forecast">
            <div className="card-top">
              <span className="card-stage">{item.stage}</span>
              <span className={`badge-risk ${item.risk.toLowerCase()}`}>{item.risk} RISK</span>
            </div>
            <p className="card-desc">{item.desc}</p>
            <div className="card-meta">
              <span>Transition Prob: <strong className="val">{item.confidence}</strong></span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ForecastTimeline;
