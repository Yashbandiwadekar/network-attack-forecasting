import React from 'react';
import './WorkflowPipeline.css';

const WorkflowPipeline = () => {
  const steps = [
    { title: 'PCAP / CSV TRAFFIC', sub: 'RAW NETWORK DATA', type: 'input' },
    { title: 'FLOW EXTRACTION', sub: '5-TUPLE / PACKET STATS', type: 'process' },
    { title: 'FEATURE NORMALIZATION', sub: 'ENCODING & SCALING', type: 'process' },
    { title: 'THREAT DETECTION', sub: 'ANOMALY & RISK SCORING', type: 'detection' },
    { title: 'ATTACK CLASSIFICATION', sub: 'TACTICAL STAGE MAPPING', type: 'detection' },
    { title: 'K-STEP FORECAST', sub: 'SEQUENCE MODELING', type: 'forecast' },
    { title: 'MITRE ATT&CK MAPPING', sub: 'TECHNIQUE MAPPING', type: 'output' },
    { title: 'EXPLAINABLE REPORT', sub: 'EVIDENCE RATIONALE', type: 'output' }
  ];

  return (
    <div className="pipeline-container">
      <div className="pipeline-grid">
        {steps.map((s, idx) => (
          <React.Fragment key={idx}>
            <div className={`pipeline-node ${s.type}`}>
              <span className="node-step">STAGE 0{idx + 1}</span>
              <span className="node-title">{s.title}</span>
              <span className="node-sub">{s.sub}</span>
            </div>
            {idx < steps.length - 1 && (
              <div className="pipeline-connector">
                <span className="connector-line"></span>
                <span className="connector-arrow">▼</span>
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
};

export default WorkflowPipeline;
