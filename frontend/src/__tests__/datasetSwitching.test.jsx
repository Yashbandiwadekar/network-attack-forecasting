import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Dashboard from '../pages/Dashboard';
import { MemoryRouter } from 'react-router-dom';
import * as api from '../api';

vi.mock('../api', () => ({
  systemApi: {
    getStatus: vi.fn().mockResolvedValue({ status: 'healthy', active_model: 'Transformer' }),
  },
  datasetApi: {
    getDatasets: vi.fn().mockResolvedValue({
      active_dataset: 'CIC-IDS-2018',
      datasets: [
        { id: 'CIC-IDS-2018', name: 'CIC-IDS-2018', checkpoint_available: true, checkpoint_loaded: true },
        { id: 'UNSW-NB15', name: 'UNSW-NB15', checkpoint_available: false, checkpoint_loaded: false },
        { id: 'CTU-13', name: 'CTU-13', checkpoint_available: false, checkpoint_loaded: false },
      ],
    }),
    selectDataset: vi.fn(),
  },
  forecastApi: {
    getHosts: vi.fn().mockResolvedValue({ hosts: [] }),
    predict: vi.fn().mockResolvedValue({ infiltration_probs: [], predicted_stages: [] }),
  },
  explainApi: {
    getAttribution: vi.fn().mockResolvedValue({ feature_attributions: [] }),
    getNarrative: vi.fn().mockResolvedValue({ narrative: '', cve_details: [] }),
    getMitre: vi.fn().mockResolvedValue({ techniques: [] }),
  },
  analysisApi: {
    uploadFile: vi.fn(),
  },
  reportApi: {
    generateReport: vi.fn(),
  },
  evalApi: {
    getMetrics: vi.fn().mockResolvedValue({ n_seeds: 3, split: 'test', macro_f1: 0.91 }),
  },
}));

/** Shared dataset list used by both getDatasets and selectDataset responses */
const ALL_DATASETS = [
  { id: 'CIC-IDS-2018', name: 'CIC-IDS-2018', checkpoint_available: true, checkpoint_loaded: true },
  { id: 'UNSW-NB15', name: 'UNSW-NB15', checkpoint_available: false, checkpoint_loaded: false },
  { id: 'CTU-13', name: 'CTU-13', checkpoint_available: false, checkpoint_loaded: false },
];

describe('DATA SOURCE CONTEXT Switching Workflow', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Default: CIC-IDS-2018 is active
    api.datasetApi.getDatasets.mockResolvedValue({
      active_dataset: 'CIC-IDS-2018',
      datasets: ALL_DATASETS,
    });
    api.systemApi.getStatus.mockResolvedValue({ status: 'healthy', active_model: 'Transformer' });
    api.forecastApi.getHosts.mockResolvedValue({ hosts: [] });
    api.evalApi.getMetrics.mockResolvedValue({ n_seeds: 3, split: 'test', macro_f1: 0.91 });
  });

  it('renders all configured datasets in the selector dropdown', async () => {
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    await waitFor(() => {
      const select = screen.getByRole('combobox');
      expect(select).toBeInTheDocument();
      expect(screen.getByRole('option', { name: /CIC-IDS-2018/i })).toBeInTheDocument();
      expect(screen.getByRole('option', { name: /UNSW-NB15/i })).toBeInTheDocument();
      expect(screen.getByRole('option', { name: /CTU-13/i })).toBeInTheDocument();
    });
  });

  it('switches dataset successfully when selecting an available dataset', async () => {
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    // Wait for initial render to complete and dropdown to appear
    const select = await screen.findByRole('combobox');
    await screen.findByRole('option', { name: /UNSW-NB15/i });

    // After a successful selectDataset, fetchInitialData will re-call getDatasets.
    // We must update the mock BEFORE the change event so the re-fetch reflects the new state.
    api.datasetApi.selectDataset.mockResolvedValueOnce({
      status: 'success',
      active_dataset: 'UNSW-NB15',
    });
    api.datasetApi.getDatasets.mockResolvedValue({
      active_dataset: 'UNSW-NB15',
      datasets: ALL_DATASETS,
    });

    await act(async () => {
      fireEvent.change(select, { target: { value: 'UNSW-NB15' } });
    });

    await waitFor(() => {
      expect(api.datasetApi.selectDataset).toHaveBeenCalledWith('UNSW-NB15');
      expect(select.value).toBe('UNSW-NB15');
    });
  });

  it('retains previous dataset and displays informative error banner when switch fails', async () => {
    // Simulate the backend rejecting a switch because the checkpoint is missing
    api.datasetApi.selectDataset.mockRejectedValueOnce(
      new Error('HTTP 409: UNSW-NB15 could not be activated because its forecasting checkpoint is not available on this installation.')
    );

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    const select = await screen.findByRole('combobox');
    await screen.findByRole('option', { name: /UNSW-NB15/i });
    expect(select.value).toBe('CIC-IDS-2018');

    await act(async () => {
      fireEvent.change(select, { target: { value: 'UNSW-NB15' } });
    });

    await waitFor(() => {
      expect(api.datasetApi.selectDataset).toHaveBeenCalled();
      // The error banner must contain the stripped message
      expect(screen.getByText(/could not be activated/i)).toBeInTheDocument();
    });

    // The selector must retain the previous valid dataset (not roll forward to UNSW-NB15)
    expect(select.value).toBe('CIC-IDS-2018');
  });
});
