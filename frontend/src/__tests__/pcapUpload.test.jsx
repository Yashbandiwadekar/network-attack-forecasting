import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Dashboard from '../pages/Dashboard';
import { MemoryRouter } from 'react-router-dom';
import * as api from '../api';

vi.mock('../api', () => ({
  systemApi: {
    getStatus: vi.fn().mockResolvedValue({ status: 'healthy', active_model: 'XGBoost+Markov' }),
  },
  datasetApi: {
    getDatasets: vi.fn().mockResolvedValue({ active_dataset: 'CIC-IDS-2018', datasets: [{ id: 'CIC-IDS-2018', name: 'CIC-IDS-2018' }] }),
    selectDataset: vi.fn().mockResolvedValue({ status: 'success' }),
  },
  forecastApi: {
    getHosts: vi.fn().mockResolvedValue({ hosts: [{ host_ip: '10.0.4.5', flow_count: 120, peak_prob: 0.8, current_stage: 'EXPLOITATION', predicted_stage: 'EXFILTRATION', severity: 'CRITICAL' }] }),
    predict: vi.fn().mockResolvedValue({ infiltration_probs: [0.1, 0.2, 0.4], predicted_stages: ['RECON', 'WEAPONIZATION', 'EXPLOITATION'] }),
  },
  explainApi: {
    getAttribution: vi.fn().mockResolvedValue({ feature_attributions: [] }),
    getNarrative: vi.fn().mockResolvedValue({ narrative: 'Test narrative', cve_details: [] }),
    getMitre: vi.fn().mockResolvedValue({ techniques: [] }),
  },
  analysisApi: {
    uploadFile: vi.fn(),
  },
  reportApi: {
    generateReport: vi.fn(),
  },
}));

describe('PCAP File Ingestion Workflow', () => {
  it('handles file selection and displays upload success status', async () => {
    api.analysisApi.uploadFile.mockResolvedValueOnce({
      status: 'success',
      message: 'Ingested capture file attack_traffic.pcap',
      new_host_ip: '10.0.4.99',
    });

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    // Switch to Ingestion & Flows tab
    const analysisTabBtn = screen.getAllByText(/INGESTION & FLOWS/i)[0];
    fireEvent.click(analysisTabBtn);

    expect(screen.getByText(/TRAFFIC CAPTURE INGESTION WORKSPACE/i)).toBeInTheDocument();

    const fileInput = screen.getByLabelText(/Upload PCAP, PCAPNG, or Flow CSV File/i, { selector: 'input' });
    const file = new File(['mock binary pcap content'], 'attack_traffic.pcap', { type: 'application/vnd.tcpdump.pcap' });

    fireEvent.change(fileInput, { target: { files: [file] } });

    await waitFor(() => {
      expect(api.analysisApi.uploadFile).toHaveBeenCalledWith(file);
      expect(screen.getByText(/Ingested capture file attack_traffic.pcap/i)).toBeInTheDocument();
    });
  });
});
