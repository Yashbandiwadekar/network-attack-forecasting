import React, { useState } from 'react';
import './ForecastProbabilityCurve.css';

/**
 * K-step infiltration probability curve.
 *
 * Additive props over the original: `stepSeconds` puts the x-axis in wall-clock seconds rather
 * than step indices (the model forecasts 6 steps of 10s = 60 seconds, which is the headline
 * capability and was previously invisible), `stages` labels each step with its predicted MITRE
 * stage, and `heuristicFlags` marks the individual steps whose stage came from a rule rather
 * than the trained classifier. The older `stage_is_heuristic` boolean still works.
 *
 * Stage is deliberately secondary to probability: the stage head can output "Benign" on a step
 * whose infiltration probability is 0.99, and printing that stage in large type next to the
 * number would misrepresent the model. Probability is the primary visual.
 */
const ForecastProbabilityCurve = ({
  probabilities = [],
  timestamps = [],
  stepSeconds = [],
  stages = [],
  heuristicFlags = [],
  disclosureNotes = [],
  horizonSeconds = null,
  currentStep = 1,
  stage_is_heuristic = false,
  isLoading = false,
  error = null,
  title = "K-STEP INFILTRATION PROBABILITY CURVE"
}) => {
  const [hoveredPoint, setHoveredPoint] = useState(null);

  if (isLoading) {
    return (
      <div className="forecast-curve-card loading">
        <div className="forecast-curve-header">
          <span className="forecast-curve-title">{title}</span>
        </div>
        <div className="forecast-curve-placeholder">
          <div className="spinner" />
          <span>Loading forecast models...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="forecast-curve-card error">
        <div className="forecast-curve-header">
          <span className="forecast-curve-title">{title}</span>
        </div>
        <div className="forecast-curve-placeholder error-text">
          <span>⚠️ {error}</span>
        </div>
      </div>
    );
  }

  if (!probabilities || probabilities.length === 0) {
    return (
      <div className="forecast-curve-card empty">
        <div className="forecast-curve-header">
          <span className="forecast-curve-title">{title}</span>
        </div>
        <div className="forecast-curve-placeholder">
          <span>No forecast available for this analysis.</span>
        </div>
      </div>
    );
  }

  const hasSeconds = stepSeconds.length === probabilities.length;
  const hasStages = stages.length === probabilities.length;

  // Taller than the original to make room for the stage lane beneath the axis.
  const width = 600;
  const height = hasStages ? 300 : 240;
  const padding = { top: 30, right: 30, bottom: hasStages ? 96 : 40, left: 50 };
  const graphWidth = width - padding.left - padding.right;
  const graphHeight = height - padding.top - padding.bottom;

  const K = probabilities.length;

  const points = probabilities.map((prob, idx) => {
    const x = padding.left + (K === 1 ? graphWidth / 2 : (idx / (K - 1)) * graphWidth);
    const clampedProb = Math.max(0, Math.min(1, prob));
    const y = padding.top + graphHeight * (1 - clampedProb);
    return {
      x,
      y,
      prob: clampedProb,
      step: idx + 1,
      seconds: hasSeconds ? stepSeconds[idx] : null,
      stage: hasStages ? stages[idx] : null,
      heuristic: Boolean(heuristicFlags[idx]),
      note: disclosureNotes[idx] || '',
      time: timestamps[idx] || `Step ${idx + 1}`,
    };
  });

  const linePath = points.reduce((acc, pt, i) => {
    return i === 0 ? `M ${pt.x} ${pt.y}` : `${acc} L ${pt.x} ${pt.y}`;
  }, '');

  const areaPath = `${linePath} L ${points[points.length - 1].x} ${padding.top + graphHeight} L ${points[0].x} ${padding.top + graphHeight} Z`;

  const peakProb = Math.max(...probabilities);
  const getRiskLabel = (val) => {
    if (val >= 0.65) return { label: 'CRITICAL', color: '#e53935' };
    if (val >= 0.35) return { label: 'ELEVATED', color: '#ff7b00' };
    return { label: 'LOW', color: '#ffaa00' };
  };

  const peakRisk = getRiskLabel(peakProb);
  const peakPoint = points.find((p) => p.prob === peakProb);
  const anyHeuristic = stage_is_heuristic || points.some((p) => p.heuristic);
  const notes = [...new Set(points.filter((p) => p.heuristic && p.note).map((p) => p.note))];

  return (
    <div className="forecast-curve-card">
      <div className="forecast-curve-header">
        <div className="title-group">
          <span className="forecast-curve-title">{title}</span>
          {anyHeuristic && (
            <span className="heuristic-badge" title="Stage classification derived from heuristic fallback rules prior to ML model inference">
              ⚠️ HEURISTIC STAGE PREDICTION
            </span>
          )}
        </div>

        <div className="forecast-meta-summary font-mono">
          <span>HORIZON K = {K}</span>
          {horizonSeconds && <span className="horizon-seconds">{horizonSeconds} SECONDS AHEAD</span>}
          <span>
            PEAK RISK:{' '}
            <strong style={{ color: peakRisk.color }}>
              {(peakProb * 100).toFixed(1)}% ({peakRisk.label})
            </strong>
            {peakPoint?.seconds ? <span className="peak-at"> at t+{peakPoint.seconds}s</span> : null}
          </span>
        </div>
      </div>

      <div className="forecast-svg-wrapper">
        <svg viewBox={`0 0 ${width} ${height}`} className="forecast-svg" preserveAspectRatio="xMidYMid meet">
          <defs>
            <linearGradient id="forecastAreaGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#e53935" stopOpacity="0.45" />
              <stop offset="50%" stopColor="#ff7b00" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#ffaa00" stopOpacity="0.02" />
            </linearGradient>
            <linearGradient id="forecastLineGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#ffaa00" />
              <stop offset="50%" stopColor="#ff7b00" />
              <stop offset="100%" stopColor="#e53935" />
            </linearGradient>
          </defs>

          {[0, 0.25, 0.5, 0.75, 1.0].map((val) => {
            const y = padding.top + graphHeight * (1 - val);
            return (
              <g key={val} className="grid-line-group">
                <line
                  x1={padding.left}
                  y1={y}
                  x2={width - padding.right}
                  y2={y}
                  stroke={val === 0.35 || val === 0.65 ? 'rgba(255,255,255,0.15)' : 'rgba(255,255,255,0.06)'}
                  strokeDasharray={val === 0.35 || val === 0.65 ? '3 3' : 'none'}
                />
                <text x={padding.left - 8} y={y + 4} textAnchor="end" className="svg-label font-mono">
                  {(val * 100).toFixed(0)}%
                </text>
              </g>
            );
          })}

          <line
            x1={padding.left}
            y1={padding.top + graphHeight * (1 - 0.65)}
            x2={width - padding.right}
            y2={padding.top + graphHeight * (1 - 0.65)}
            stroke="#e53935"
            strokeDasharray="4 4"
            strokeOpacity="0.4"
          />

          <path d={areaPath} fill="url(#forecastAreaGrad)" />
          <path d={linePath} fill="none" stroke="url(#forecastLineGrad)" strokeWidth="3" strokeLinecap="round" />

          {points.map((pt) => {
            const risk = getRiskLabel(pt.prob);
            const isSelected = hoveredPoint?.step === pt.step;
            return (
              <g key={pt.step} className="data-node" onMouseEnter={() => setHoveredPoint(pt)} onMouseLeave={() => setHoveredPoint(null)}>
                {/* Vertical drop to the stage lane, so a step reads as one column. */}
                {hasStages && (
                  <line
                    x1={pt.x}
                    y1={pt.y}
                    x2={pt.x}
                    y2={padding.top + graphHeight}
                    stroke="rgba(255,255,255,0.10)"
                    strokeWidth="1"
                  />
                )}

                <circle
                  cx={pt.x}
                  cy={pt.y}
                  r={isSelected ? 8 : 5}
                  fill="#080808"
                  stroke={risk.color}
                  strokeWidth={isSelected ? 3 : 2}
                  style={{ transition: 'all 0.15s ease' }}
                />
                <circle cx={pt.x} cy={pt.y} r={isSelected ? 4 : 2.5} fill={risk.color} />

                {/* Axis label: seconds when the caller supplies them, step index otherwise.
                    The K= form is what the component's tests assert, so it stays as the default. */}
                <text
                  x={pt.x}
                  y={padding.top + graphHeight + 18}
                  textAnchor="middle"
                  className="svg-label font-mono"
                  fill={isSelected ? '#ffffff' : '#999999'}
                >
                  {pt.seconds ? `t+${pt.seconds}s` : `K=${pt.step}`}
                </text>

                {hasStages && (
                  <>
                    <text
                      x={pt.x}
                      y={padding.top + graphHeight + 38}
                      textAnchor="middle"
                      className="svg-stage-label font-mono"
                      fill={pt.prob >= 0.65 ? '#ff6a00' : '#888888'}
                    >
                      {String(pt.stage).length > 12 ? `${String(pt.stage).slice(0, 11)}…` : pt.stage}
                    </text>
                    {pt.heuristic && (
                      <text
                        x={pt.x}
                        y={padding.top + graphHeight + 52}
                        textAnchor="middle"
                        className="svg-stage-label font-mono"
                        fill="#ffaa00"
                      >
                        ⚠ rule
                      </text>
                    )}
                  </>
                )}
              </g>
            );
          })}

          {!hasSeconds && (
            <text x={width / 2} y={height - 6} textAnchor="middle" className="svg-label font-mono" fill="#888888">
              forecast step
            </text>
          )}
        </svg>

        {hoveredPoint && (
          <div
            className="forecast-tooltip font-mono"
            style={{
              left: `${(hoveredPoint.x / width) * 100}%`,
              top: `${(hoveredPoint.y / height) * 100}%`
            }}
          >
            <div className="tooltip-step">
              {hoveredPoint.seconds ? `t + ${hoveredPoint.seconds}s` : `STEP K = ${hoveredPoint.step}`}
            </div>
            <div className="tooltip-prob" style={{ color: getRiskLabel(hoveredPoint.prob).color }}>
              PROB: {(hoveredPoint.prob * 100).toFixed(1)}%
            </div>
            <div className="tooltip-risk">RISK: {getRiskLabel(hoveredPoint.prob).label}</div>
            {hoveredPoint.stage && <div className="tooltip-risk">STAGE: {hoveredPoint.stage}</div>}
          </div>
        )}
      </div>

      {notes.length > 0 && (
        <div className="forecast-disclosure font-mono">
          {notes.map((n) => (
            <div key={n}>⚠ {n}</div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ForecastProbabilityCurve;
