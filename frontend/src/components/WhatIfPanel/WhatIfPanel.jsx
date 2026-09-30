import React, { useEffect, useState } from 'react';
import { forecastApi } from '../../api';
import './WhatIfPanel.css';

/**
 * Competitive-parity item 4 (2026-09-30): counterfactual "what-if" rollout control.
 *
 * Lets an analyst pick one curated feature and a scale factor, re-runs the model's own K-step
 * rollout with that feature perturbed in the most recent observed window, and hands the result up
 * to the parent (which overlays it on ForecastProbabilityCurve via `onResult`).
 *
 * Deliberately not a causal simulator: the backend's own `caveat` field is surfaced verbatim in
 * the result, and this panel never claims the counterfactual curve is a guaranteed outcome.
 */
const WhatIfPanel = ({ hostIp, onResult, onClear }) => {
  const [features, setFeatures] = useState([]);
  const [feature, setFeature] = useState('');
  const [scale, setScale] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    forecastApi.getWhatIfFeatures()
      .then((body) => {
        if (cancelled) return;
        setFeatures(body.curated_features || []);
        if (body.curated_features?.length) setFeature(body.curated_features[0].feature);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const runWhatIf = async () => {
    if (!hostIp || !feature) return;
    setLoading(true);
    setError(null);
    try {
      const body = await forecastApi.whatIf(hostIp, feature, scale);
      onResult?.(body);
    } catch (e) {
      setError(e?.message || 'What-if request failed');
      onClear?.();
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    onClear?.();
  };

  if (!features.length) return null;

  return (
    <div className="what-if-panel font-mono">
      <div className="what-if-title">WHAT-IF SCENARIO</div>
      <div className="what-if-controls">
        <select
          value={feature}
          onChange={(e) => setFeature(e.target.value)}
          className="what-if-select"
          disabled={loading}
        >
          {features.map((f) => (
            <option key={f.feature} value={f.feature}>{f.label}</option>
          ))}
        </select>

        <label className="what-if-scale-label">
          scale ×{scale.toFixed(2)}
          <input
            type="range"
            min="0"
            max="2"
            step="0.1"
            value={scale}
            onChange={(e) => setScale(parseFloat(e.target.value))}
            disabled={loading}
          />
        </label>

        <button type="button" onClick={runWhatIf} disabled={loading || !hostIp} className="what-if-run">
          {loading ? 'RUNNING…' : 'RUN'}
        </button>
        <button type="button" onClick={clear} disabled={loading} className="what-if-clear">
          CLEAR
        </button>
      </div>
      {error && <div className="what-if-error">⚠ {error}</div>}
    </div>
  );
};

export default WhatIfPanel;
