import React from 'react';
import './TelemetryStrip.css';

const TelemetryStrip = () => {
  const readouts = [
    { label: 'ACTIVE FLOWS', value: '12,482', status: 'normal' },
    { label: 'SUSPICIOUS FLOWS', value: '327', status: 'warning' },
    { label: 'HIGH-RISK HOSTS', value: '19', status: 'critical' },
    { label: 'FORECASTED EVENTS', value: '8', status: 'forecast' },
    { label: 'MODEL CHECKPOINT', value: '447 KB', status: 'normal' },
    { label: 'TRAINING SEQUENCES', value: '1.24M', status: 'normal' },
  ];

  return (
    <div className="telemetry-strip-container">
      <div className="telemetry-strip">
        {readouts.map((item, idx) => (
          <div key={idx} className={`telemetry-item ${item.status}`}>
            <span className="telemetry-label">{item.label}</span>
            <span className="telemetry-val">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default TelemetryStrip;
