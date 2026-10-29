import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import DemoScenarios from '../components/DemoScenarios/DemoScenarios';
import Dashboard from '../pages/Dashboard';
import * as api from '../api';

vi.mock('../api', () => ({
  systemApi: { getStatus: vi.fn().mockResolvedValue({ status: 'healthy' }) },
  datasetApi: {
    getDatasets: vi.fn().mockResolvedValue({ active_dataset: 'CIC-IDS-2018', datasets: [] }),
    selectDataset: vi.fn(),
  },
  forecastApi: {
    getHosts: vi.fn().mockResolvedValue({ hosts: [] }),
    predict: vi.fn().mockResolvedValue({ infiltration_probs: [0.2], predicted_stages: ['Benign'] }),
  },
  explainApi: {
    getAttribution: vi.fn().mockResolvedValue({ feature_attributions: [] }),
    getNarrative: vi.fn().mockResolvedValue({ narrative: 'n', cve_details: [] }),
    getMitre: vi.fn().mockResolvedValue({ techniques: [] }),
  },
  analysisApi: { uploadFile: vi.fn() },
  reportApi: { generateReport: vi.fn() },
  evalApi: { getMetrics: vi.fn().mockResolvedValue(null) },
  demoApi: { listScenarios: vi.fn(), loadScenario: vi.fn() },
}));

const scenarios = [
  { id: 'botnet', title: 'Botnet C2', description: 'Zeus/Ares bot traffic', available: true,
    source: { dataset: 'CIC-IDS-2018', day: '2 Mar 2018' }, split_tag: 'TRAIN DAY (in-sample)', size_mb: 12.4,
    expected_behaviour: { verdict: 'flagged', text: 'Peak 0.97 on the served model (in-sample day).' } },
  { id: 'web', title: 'Web attacks', description: 'Sparse web attacks', available: true,
    source: { dataset: 'CIC-IDS-2018', day: '23 Feb 2018' }, split_tag: 'TEST DAY', size_mb: 11.0,
    expected_behaviour: { verdict: 'missed', text: 'Peak 0.05; see docs/17.' } },
  { id: 'gone', title: 'Not copied yet', description: 'x', available: false,
    source: { dataset: 'CIC-IDS-2018', day: '-' }, expected_behaviour: { verdict: 'missed', text: 'y' } },
];

beforeEach(() => {
  api.demoApi.listScenarios.mockResolvedValue({ scenarios });
  api.demoApi.loadScenario.mockReset();
});

describe('DemoScenarios cards', () => {
  it('renders title, description, source, tag and the honest expected-behaviour note', async () => {
    render(<DemoScenarios onLoad={() => {}} />);
    const cards = await screen.findAllByTestId('demo-card');
    expect(cards).toHaveLength(3);
    expect(within(cards[0]).getByText('Botnet C2')).toBeInTheDocument();
    expect(within(cards[0]).getByText(/CIC-IDS-2018 · 2 Mar 2018/)).toBeInTheDocument();
    expect(within(cards[0]).getByText('TRAIN DAY (in-sample)')).toBeInTheDocument();
    expect(within(cards[0]).getByText(/MODEL FLAGS THIS/)).toBeInTheDocument();
    expect(within(cards[1]).getByText(/MODEL MISSES THIS/)).toBeInTheDocument();
    expect(within(cards[1]).getByText(/see docs\/17/)).toBeInTheDocument();
    expect(within(cards[2]).getByRole('button')).toBeDisabled();
    expect(within(cards[2]).getByRole('button')).toHaveTextContent('Not installed');
  });

  it('shows an empty state when the server has no scenarios', async () => {
    api.demoApi.listScenarios.mockResolvedValueOnce({ scenarios: [] });
    render(<DemoScenarios onLoad={() => {}} />);
    expect(await screen.findByText(/No demo scenarios are installed/)).toBeInTheDocument();
  });

  it('shows progress on the loading card and disables the others', async () => {
    const { rerender } = render(<DemoScenarios onLoad={() => {}} loadingId="web" />);
    const cards = await screen.findAllByTestId('demo-card');
    expect(within(cards[1]).getByRole('button')).toHaveTextContent('Loading...');
    expect(within(cards[0]).getByRole('button')).toBeDisabled();
    rerender(<DemoScenarios onLoad={() => {}} loadingId={null} />);
    expect(within(cards[0]).getByRole('button')).toBeEnabled();
  });
});

describe('Dashboard demo loading', () => {
  const openIngestion = () => {
    render(<MemoryRouter><Dashboard /></MemoryRouter>);
    fireEvent.click(screen.getAllByText(/INGESTION & FLOWS/i)[0]);
  };

  it('loads a scenario by id and shows the same success state as an upload', async () => {
    api.demoApi.loadScenario.mockResolvedValueOnce({
      status: 'success', message: 'Ingested demo-botnet.csv (12.40 MB): 40,000 flow records',
      new_host_ip: 'NETWORK-2018-03-02', scenario_id: 'botnet' });
    openIngestion();
    const cards = await screen.findAllByTestId('demo-card');
    fireEvent.click(within(cards[0]).getByRole('button'));
    await waitFor(() => expect(api.demoApi.loadScenario).toHaveBeenCalledWith('botnet'));
    expect(await screen.findByText(/Ingested demo-botnet.csv/)).toBeInTheDocument();
    await waitFor(() => expect(api.forecastApi.predict).toHaveBeenCalledWith('NETWORK-2018-03-02', 6));
  });

  it('shows the server error when a load fails', async () => {
    api.demoApi.loadScenario.mockRejectedValueOnce(new Error('HTTP 409: A live/replay session is active'));
    openIngestion();
    const cards = await screen.findAllByTestId('demo-card');
    fireEvent.click(within(cards[1]).getByRole('button'));
    expect(await screen.findByText(/live\/replay session is active/)).toBeInTheDocument();
  });
});
