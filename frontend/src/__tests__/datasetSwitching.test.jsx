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

/** A server that also has a second trained model (e.g. a dev machine). */
const TWO_MODELS = [
  { id: 'CIC-IDS-2018', name: 'CIC-IDS-2018', checkpoint_available: true, checkpoint_loaded: true },
  { id: 'UNSW-NB15', name: 'UNSW-NB15', checkpoint_available: true, checkpoint_loaded: true },
  { id: 'CTU-13', name: 'CTU-13', checkpoint_available: false, checkpoint_loaded: false },
];

const renderDashboard = () =>
  render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>
  );

describe('ACTIVE MODEL selector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.datasetApi.getDatasets.mockResolvedValue({ active_dataset: 'CIC-IDS-2018', datasets: ALL_DATASETS });
    api.systemApi.getStatus.mockResolvedValue({ status: 'healthy', active_model: 'Transformer' });
    api.forecastApi.getHosts.mockResolvedValue({ hosts: [] });
    api.evalApi.getMetrics.mockResolvedValue({ n_seeds: 3, split: 'test', macro_f1: 0.91 });
  });

  it('shows a plain label, not a dropdown, when only one model exists on the server', async () => {
    renderDashboard();

    const label = await screen.findByTestId('active-model-label');
    expect(label).toHaveTextContent('CIC-IDS-2018');
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    // Models that are not deployed here are not offered at all.
    expect(screen.queryByText(/UNSW-NB15/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/CTU-13/i)).not.toBeInTheDocument();
  });

  it('lists only models whose checkpoint is present when there is more than one', async () => {
    api.datasetApi.getDatasets.mockResolvedValue({ active_dataset: 'CIC-IDS-2018', datasets: TWO_MODELS });
    renderDashboard();

    await screen.findByRole('combobox');
    expect(screen.getByRole('option', { name: 'CIC-IDS-2018' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'UNSW-NB15' })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /CTU-13/i })).not.toBeInTheDocument();
  });

  it('switches model successfully when two are available', async () => {
    api.datasetApi.getDatasets.mockResolvedValue({ active_dataset: 'CIC-IDS-2018', datasets: TWO_MODELS });
    renderDashboard();

    const select = await screen.findByRole('combobox');
    api.datasetApi.selectDataset.mockResolvedValueOnce({ status: 'success', active_dataset: 'UNSW-NB15' });
    api.datasetApi.getDatasets.mockResolvedValue({ active_dataset: 'UNSW-NB15', datasets: TWO_MODELS });

    await act(async () => {
      fireEvent.change(select, { target: { value: 'UNSW-NB15' } });
    });

    await waitFor(() => {
      expect(api.datasetApi.selectDataset).toHaveBeenCalledWith('UNSW-NB15');
      expect(select.value).toBe('UNSW-NB15');
    });
  });

  it('keeps the previous model and shows an error banner when a switch fails', async () => {
    api.datasetApi.getDatasets.mockResolvedValue({ active_dataset: 'CIC-IDS-2018', datasets: TWO_MODELS });
    api.datasetApi.selectDataset.mockRejectedValueOnce(
      new Error('HTTP 409: UNSW-NB15 could not be activated because its forecasting checkpoint failed to load.')
    );
    renderDashboard();

    const select = await screen.findByRole('combobox');
    expect(select.value).toBe('CIC-IDS-2018');

    await act(async () => {
      fireEvent.change(select, { target: { value: 'UNSW-NB15' } });
    });

    await waitFor(() => {
      expect(api.datasetApi.selectDataset).toHaveBeenCalled();
      expect(screen.getByText(/could not be activated/i)).toBeInTheDocument();
    });
    expect(select.value).toBe('CIC-IDS-2018');
  });
});
