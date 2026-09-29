import React from 'react';
import './HUD.css';

const HUD = () => {
  return (
    <div className="hero-hud-panel">
      <div className="hud-header">
        <span className="hud-brand">PHOENIX IDPS</span>
        <span className="hud-sub">THREAT FORECAST NETWORK</span>
      </div>
      <p className="hud-instructions">
        Click or tap to inject network activity.<br />
        Drag to explore the forecast field.
      </p>
    </div>
  );
};

export default HUD;
