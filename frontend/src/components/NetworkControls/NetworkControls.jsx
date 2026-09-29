import React from 'react';
import './NetworkControls.css';

const NetworkControls = ({ mode, onModeChange, density, onDensityChange }) => {
  const modes = [
    { id: 'threat', label: 'Threat', color: '#c83b32' },
    { id: 'activity', label: 'Activity', color: '#ff6a00' },
    { id: 'forecast', label: 'Forecast', color: '#ffb000' },
    { id: 'network', label: 'Network', color: '#888888' },
  ];

  return (
    <div className="network-controls-panel">
      <div className="panel-title">NETWORK MODE</div>
      
      <div className="mode-list">
        {modes.map((m) => (
          <button
            key={m.id}
            className={`mode-btn ${mode === m.id ? 'active' : ''}`}
            onClick={() => onModeChange(m.id)}
          >
            <span className="mode-dot" style={{ backgroundColor: m.color }} />
            <span className="mode-label">{m.label}</span>
          </button>
        ))}
      </div>

      <div className="density-slider-group">
        <div className="density-header">
          <span>Density</span>
          <span className="density-val">{Math.round(density * 100)}%</span>
        </div>
        <input
          type="range"
          min="0.2"
          max="1.0"
          step="0.05"
          value={density}
          onChange={(e) => onDensityChange(parseFloat(e.target.value))}
          className="density-input"
        />
      </div>
    </div>
  );
};

export default NetworkControls;
