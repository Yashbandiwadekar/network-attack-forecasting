import React from 'react';
import './DatasetTable.css';

const DatasetTable = () => {
  const datasets = [
    { name: 'CIC-IDS-2017', flows: '2,830,743', type: 'Full PCAP / Flow Records', purpose: 'Primary Evaluation Baseline', role: 'Train / Test Split' },
    { name: 'UNSW-NB15', flows: '2,540,044', type: 'Network Synthetic & Real', purpose: 'Cross-Dataset Evaluation', role: 'Generalization Test' },
    { name: 'CTU-13', flows: '13 Scenarios', type: 'Botnet Traffic Captures', purpose: 'Botnet State Validation', role: 'Holdout Validation' },
  ];

  return (
    <div className="dataset-table-container">
      <table className="dataset-table">
        <thead>
          <tr>
            <th>DATASET</th>
            <th>FLOW COUNT</th>
            <th>TRAFFIC TYPE</th>
            <th>EVALUATION PURPOSE</th>
            <th>BENCHMARK ROLE</th>
          </tr>
        </thead>
        <tbody>
          {datasets.map((d, idx) => (
            <tr key={idx}>
              <td className="dataset-name">{d.name}</td>
              <td className="dataset-mono">{d.flows}</td>
              <td className="dataset-sub">{d.type}</td>
              <td className="dataset-sub">{d.purpose}</td>
              <td><span className="badge-role">{d.role}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default DatasetTable;
