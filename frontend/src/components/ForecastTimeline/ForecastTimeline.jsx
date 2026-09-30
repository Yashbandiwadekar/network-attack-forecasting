import React from 'react';
import './ForecastTimeline.css';

const ForecastTimeline = ({
  probabilities = [],
  predictedStages = [],
  stageIsHeuristic = [],
  horizon = 6,
  observed = [
    { stage: 'Reconnaissance', desc: 'Port Scan / Host Discovery', status: 'observed' },
    { stage: 'Initial Access', desc: 'Exploit Public App Endpoint', status: 'observed' },
    { stage: 'Execution', desc: 'Command Shell Invocation', status: 'observed' },
    { stage: 'Command & Control', desc: 'Active C2 Beaconing (Port 443)', status: 'active' },
  ]
}) => {
  // If probabilities passed from API, format forecast items dynamically
  const forecastItems = probabilities.length > 0
    ? probabilities.map((prob, idx) => {
        const stageName = predictedStages[idx] || `Predicted Stage ${idx + 1}`;
        const isHeuristic = Array.isArray(stageIsHeuristic) 
          ? stageIsHeuristic[idx] 
          : (typeof stageIsHeuristic === 'boolean' ? stageIsHeuristic : false);

        let risk = 'LOW';
        if (prob >= 0.65) risk = 'CRITICAL';
        else if (prob >= 0.35) risk = 'HIGH';

        return {
          stage: `Step K=${idx + 1}: ${stageName}`,
          desc: isHeuristic ? 'Heuristic Rule-Based Prediction' : 'ML Sequence Model Forecast',
          confidence: `${(prob * 100).toFixed(1)}%`,
          risk,
          isHeuristic
        };
      })
    : [
        { stage: 'Step K=1: C2 Escalation', desc: 'Multi-host Lateral Movement', confidence: '41.2%', risk: 'HIGH' },
        { stage: 'Step K=2: Data Exfiltration', desc: 'Staged Archive Transfer', confidence: '63.4%', risk: 'HIGH' },
        { stage: 'Step K=3: Impact Execution', desc: 'Service Interruption Target', confidence: '71.8%', risk: 'CRITICAL' },
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
        <span className="divider-label">FORECAST HORIZON (K = {horizon} / 60s)</span>
        <div className="divider-line"></div>
      </div>

      <div className="timeline-column forecast-column">
        <div className="column-title">PREDICTED FUTURE THREAT STATES</div>
        {forecastItems.map((item, idx) => (
          <div key={idx} className="timeline-card forecast">
            <div className="card-top">
              <span className="card-stage">{item.stage}</span>
              <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                {item.isHeuristic && (
                  <span className="badge-risk low" style={{ background: 'rgba(255, 170, 0, 0.2)', color: 'var(--c-amber-2)', borderColor: 'var(--c-amber-2)' }}>
                    RULE-BASED
                  </span>
                )}
                <span className={`badge-risk ${item.risk.toLowerCase()}`}>{item.risk} RISK</span>
              </div>
            </div>
            <p className="card-desc">{item.desc}</p>
            <div className="card-meta">
              <span>Infiltration Prob: <strong className="val">{item.confidence}</strong></span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ForecastTimeline;
