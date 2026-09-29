import React, { useState } from 'react';
import './ForecastProbabilityCurve.css';

const ForecastProbabilityCurve = ({
  probabilities = [],
  timestamps = [],
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

  // Dimensions for SVG rendering
  const width = 600;
  const height = 240;
  const padding = { top: 30, right: 30, bottom: 40, left: 50 };
  const graphWidth = width - padding.left - padding.right;
  const graphHeight = height - padding.top - padding.bottom;

  const K = probabilities.length;

  const points = probabilities.map((prob, idx) => {
    const x = padding.left + (K === 1 ? graphWidth / 2 : (idx / (K - 1)) * graphWidth);
    // Y scale: 0 at graphHeight + padding.top, 1 at padding.top
    const clampedProb = Math.max(0, Math.min(1, prob));
    const y = padding.top + graphHeight * (1 - clampedProb);
    return { x, y, prob: clampedProb, step: idx + 1, time: timestamps[idx] || `Step ${idx + 1}` };
  });

  // SVG path generation
  const linePath = points.reduce((acc, pt, i) => {
    return i === 0 ? `M ${pt.x} ${pt.y}` : `${acc} L ${pt.x} ${pt.y}`;
  }, '');

  const areaPath = `${linePath} L ${points[points.length - 1].x} ${padding.top + graphHeight} L ${points[0].x} ${padding.top + graphHeight} Z`;

  // Determine peak risk level
  const peakProb = Math.max(...probabilities);
  const getRiskLabel = (val) => {
    if (val >= 0.65) return { label: 'CRITICAL', color: '#e53935' };
    if (val >= 0.35) return { label: 'ELEVATED', color: '#ff7b00' };
    return { label: 'LOW', color: '#ffaa00' };
  };

  const peakRisk = getRiskLabel(peakProb);

  return (
    <div className="forecast-curve-card">
      <div className="forecast-curve-header">
        <div className="title-group">
          <span className="forecast-curve-title">{title}</span>
          {stage_is_heuristic && (
            <span className="heuristic-badge" title="Stage classification derived from heuristic fallback rules prior to ML model inference">
              ⚠️ HEURISTIC STAGE PREDICTION
            </span>
          )}
        </div>

        <div className="forecast-meta-summary font-mono">
          <span>HORIZON K = {K}</span>
          <span>
            PEAK RISK:{' '}
            <strong style={{ color: peakRisk.color }}>
              {(peakProb * 100).toFixed(1)}% ({peakRisk.label})
            </strong>
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

          {/* Y-Axis Grid Lines & Labels (0.0, 0.25, 0.50, 0.75, 1.0) */}
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

          {/* Danger threshold line (0.65) */}
          <line
            x1={padding.left}
            y1={padding.top + graphHeight * (1 - 0.65)}
            x2={width - padding.right}
            y2={padding.top + graphHeight * (1 - 0.65)}
            stroke="#e53935"
            strokeDasharray="4 4"
            strokeOpacity="0.4"
          />

          {/* Area fill under curve */}
          <path d={areaPath} fill="url(#forecastAreaGrad)" />

          {/* Probability curve line */}
          <path d={linePath} fill="none" stroke="url(#forecastLineGrad)" strokeWidth="3" strokeLinecap="round" />

          {/* X-Axis Data Points & Interactive Nodes */}
          {points.map((pt) => {
            const risk = getRiskLabel(pt.prob);
            const isSelected = hoveredPoint?.step === pt.step;
            return (
              <g key={pt.step} className="data-node" onMouseEnter={() => setHoveredPoint(pt)} onMouseLeave={() => setHoveredPoint(null)}>
                {/* Node Outer Halo */}
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

                {/* X-Axis Labels */}
                <text x={pt.x} y={height - 10} textAnchor="middle" className="svg-label font-mono" fill={isSelected ? '#ffffff' : '#999999'}>
                  K={pt.step}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Hover Tooltip Overlay */}
        {hoveredPoint && (
          <div
            className="forecast-tooltip font-mono"
            style={{
              left: `${(hoveredPoint.x / width) * 100}%`,
              top: `${(hoveredPoint.y / height) * 100}%`
            }}
          >
            <div className="tooltip-step">STEP K = {hoveredPoint.step}</div>
            <div className="tooltip-prob" style={{ color: getRiskLabel(hoveredPoint.prob).color }}>
              PROB: {(hoveredPoint.prob * 100).toFixed(1)}%
            </div>
            <div className="tooltip-risk">RISK: {getRiskLabel(hoveredPoint.prob).label}</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ForecastProbabilityCurve;
