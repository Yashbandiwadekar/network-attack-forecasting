import React from 'react';
import './ForecastTimeline.css';

// Both columns render ONLY what the API returned for the selected host:
//   observedHistory  <- POST /api/v1/forecast/predict `observed_history` (the 12 input windows,
//                       collapsed into runs of equal observed stage)
//   probabilities / predictedStages / stageIsHeuristic <- the same response's K-step forecast
// With nothing loaded each column shows an explicit empty state. There are no placeholder stages or
// percentages: the previous defaults (a fixed Reconnaissance -> C2 chain, 41.2% / 63.4% / 71.8%)
// were invented and never changed with the data.

// Same tiers as the backend (app/service.py): ALERT_THRESHOLD 0.40, CRITICAL_THRESHOLD 0.70.
const riskFor = (prob) => (prob >= 0.7 ? 'CRITICAL' : prob >= 0.4 ? 'HIGH' : 'LOW');

const fmtTime = (iso) => (typeof iso === 'string' ? iso.replace('T', ' ').slice(0, 19) : '');

const ForecastTimeline = ({
  probabilities = [],
  predictedStages = [],
  stageIsHeuristic = [],
  horizon = 6,
  horizonSeconds = null,
  observedHistory = null,
  hostIp = '',
}) => {
  const runs = Array.isArray(observedHistory?.runs) ? observedHistory.runs : [];
  const hasProbs = Array.isArray(probabilities) && probabilities.length > 0;

  const forecastItems = hasProbs
    ? probabilities.map((prob, idx) => {
        const stageName = predictedStages?.[idx] || `Predicted Stage ${idx + 1}`;
        const isHeuristic = Array.isArray(stageIsHeuristic)
          ? Boolean(stageIsHeuristic[idx])
          : (typeof stageIsHeuristic === 'boolean' ? stageIsHeuristic : false);
        return {
          stage: `Step K=${idx + 1}: ${stageName}`,
          desc: isHeuristic ? 'Heuristic Rule-Based Prediction' : 'ML Sequence Model Forecast',
          confidence: `${(prob * 100).toFixed(1)}%`,
          risk: riskFor(prob),
          isHeuristic,
        };
      })
    : [];

  const emptyReason = hostIp
    ? `No forecast loaded for ${hostIp} yet.`
    : 'No host selected. Upload a capture (or load a demo scenario) under Ingestion & Flows and select a host.';
  const horizonLabel = horizonSeconds ? `${horizon} / ${horizonSeconds}s` : `${horizon}`;

  return (
    <div className="forecast-timeline-panel">
      <div className="timeline-column observed-column">
        <div className="column-title">OBSERVED TRAFFIC STATES</div>
        {runs.length === 0 && (
          <div className="timeline-card empty-state" data-testid="observed-empty">
            <p className="card-desc">{emptyReason}</p>
          </div>
        )}
        {runs.map((run, idx) => {
          const isLatest = idx === runs.length - 1;
          const unlabelled = run.observed === false;
          return (
            <div key={idx} className={`timeline-card ${isLatest ? 'active' : 'observed'}`} data-testid="observed-run">
              <div className="card-top">
                <span className="card-stage">{run.stage}</span>
                <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                  {run.may_be_heuristic && (
                    <span className="badge-observed" title="Reconnaissance here comes from the port-scan heuristic, not a label">
                      HEURISTIC
                    </span>
                  )}
                  <span className="badge-observed">
                    {unlabelled ? 'NO LABELS' : (isLatest ? 'LATEST' : 'OBSERVED')}
                  </span>
                </div>
              </div>
              <p className="card-desc">
                {fmtTime(run.from)} to {fmtTime(run.to)}
              </p>
              <div className="card-meta">
                <span>{run.n_windows} window{run.n_windows === 1 ? '' : 's'} · {run.flow_count} flows</span>
              </div>
              {unlabelled && (
                <p className="card-desc" style={{ marginTop: '0.4rem' }}>
                  This capture has no ground-truth labels, so the observed stage is unknown.
                </p>
              )}
            </div>
          );
        })}
      </div>

      <div className="horizon-divider">
        <div className="divider-line"></div>
        <span className="divider-label">FORECAST HORIZON (K = {horizonLabel})</span>
        <div className="divider-line"></div>
      </div>

      <div className="timeline-column forecast-column">
        <div className="column-title">PREDICTED FUTURE THREAT STATES</div>
        {forecastItems.length === 0 && (
          <div className="timeline-card empty-state" data-testid="forecast-empty">
            <p className="card-desc">{emptyReason}</p>
          </div>
        )}
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
