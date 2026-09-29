import React from 'react';
import './DatasetTable.css';

/**
 * Datasets and their real evaluation status.
 *
 * The previous version listed CIC-IDS-2017 as the "Primary Evaluation Baseline / Train-Test
 * Split" and CTU-13 as "Holdout Validation". Neither is true: the shipped model is trained on
 * CIC-IDS-**2018**, and the CTU-13 transfer result was withdrawn as unreproducible (audit G1).
 * Counts below come from data/processed_real/metadata.json.
 */
const DatasetTable = () => {
  const datasets = [
    {
      name: 'CIC-IDS-2018',
      flows: '1,256,931 sequences',
      type: 'Real flow records, 10 days',
      purpose: 'Training and evaluation',
      role: 'Primary',
      roleClass: 'badge-role',
      note: 'Day-disjoint split (876,989 train / 185,310 val / 194,632 test). Flow-level features only — no PCAP at this scale.',
    },
    {
      name: 'CIC-IDS-2017',
      flows: '8 days on disk',
      type: 'Full PCAP / flow records',
      purpose: 'Per-host evaluation, planned',
      role: 'Prepared',
      roleClass: 'badge-role badge-role-pending',
      note: 'Has real per-host IPs on every day, which CIC-IDS-2018 largely lacks. Not yet trained or evaluated.',
    },
    {
      name: 'UNSW-NB15',
      flows: 'Adapter + pilot',
      type: 'Synthetic and real traffic',
      purpose: 'Cross-dataset comparison',
      role: 'No checkpoint',
      roleClass: 'badge-role badge-role-pending',
      note: 'Feature adapter and a packet-aware pilot exist; no model is shipped for this dataset.',
    },
    {
      name: 'CTU-13',
      flows: '13 scenarios',
      type: 'Botnet captures',
      purpose: 'Transfer test — result withdrawn',
      role: 'Withdrawn',
      roleClass: 'badge-role badge-role-withdrawn',
      note: 'An earlier zero-shot F1 of 0.534 could not be reproduced against the shipped checkpoint and was withdrawn (audit G1).',
    },
  ];

  return (
    <div className="dataset-table-container">
      <table className="dataset-table">
        <thead>
          <tr>
            <th>DATASET</th>
            <th>SCALE</th>
            <th>TRAFFIC TYPE</th>
            <th>EVALUATION PURPOSE</th>
            <th>STATUS</th>
          </tr>
        </thead>
        <tbody>
          {datasets.map((d) => (
            <tr key={d.name}>
              <td className="dataset-name">
                {d.name}
                <span className="dataset-note">{d.note}</span>
              </td>
              <td className="dataset-mono">{d.flows}</td>
              <td className="dataset-sub">{d.type}</td>
              <td className="dataset-sub">{d.purpose}</td>
              <td><span className={d.roleClass}>{d.role}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default DatasetTable;
