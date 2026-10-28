import React from 'react';
import { render, screen, within } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Dashboard from '../pages/Dashboard';
import { MemoryRouter } from 'react-router-dom';
import * as api from '../api';

vi.mock('../api', () => ({
  systemApi: { getStatus: vi.fn().mockResolvedValue({ status: 'healthy', active_model: 'Transformer' }) },
  datasetApi: {
    getDatasets: vi.fn().mockResolvedValue({
      active_dataset: 'CIC-IDS-2018',
      datasets: [{ id: 'CIC-IDS-2018', name: 'CIC-IDS-2018', checkpoint_available: true, checkpoint_loaded: true }],
    }),
    selectDataset: vi.fn(),
  },
  forecastApi: { getHosts: vi.fn().mockResolvedValue({ hosts: [] }), predict: vi.fn() },
  explainApi: { getAttribution: vi.fn(), getNarrative: vi.fn(), getMitre: vi.fn() },
  analysisApi: { uploadFile: vi.fn() },
  reportApi: { generateReport: vi.fn() },
  evalApi: { getMetrics: vi.fn() },
}));

const sc = (a) => ({ auroc: a, auprc: 0.3 });
const day = (d, trunc, ep, a) => ({
  day: d, n_sequences: 100, n_positive: 10, episodes: ep, truncated_source: trunc,
  scores: { seed1: sc(a), persistence_oracle: sc(0.99), flow_count: sc(0.6), HGB_last: sc(0.7), LR_last: sc(0.65) },
});
const block = (days) => ({
  n_sequences: 200, n_positive: 20, n_episodes: 10, days,
  mean_of_days: { seed1: sc(0.75), persistence_oracle: sc(0.9), flow_count: sc(0.7), HGB_last: sc(0.74), LR_last: sc(0.66) },
});

describe('per-day results panel (docs/17)', () => {
  beforeEach(() => {
    api.evalApi.getMetrics.mockResolvedValue({
      n_seeds: 3, split: 'day-disjoint', n_test_sequences: 7191, n_test_positive: 1482,
      auroc: { mean: 0.794, sd: 0.043 }, source: 'x',
      per_day_v4: {
        truncation_note: 'The processed CIC-2018 CSVs stop at 1,048,575 rows on 7 of 10 days.',
        test: block([day('2018-02-16', true, 2, 0.989), day('2018-03-01', false, 2, 0.778)]),
        val: block([day('2018-02-15', true, 5, 0.692)]),
      },
    });
  });

  it('shows per-day rows with episodes, baselines beside the served model, and the truncation note', async () => {
    render(<MemoryRouter><Dashboard /></MemoryRouter>);
    const test = await screen.findByTestId('per-day-test');
    const rows = within(test).getAllByRole('row');
    expect(within(test).getByText('0.989')).toBeInTheDocument();
    expect(rows.some((r) => r.textContent.includes('02-16 †'))).toBe(true);
    expect(rows.some((r) => r.textContent.startsWith('03-01') && !r.textContent.includes('†'))).toBe(true);
    expect(within(test).getByText('HGB')).toBeInTheDocument();
    expect(within(test).getByText('FLOW_COUNT')).toBeInTheDocument();
    expect(screen.getByTestId('per-day-val')).toBeInTheDocument();
    expect(screen.getByTestId('per-day-results')).toHaveTextContent('1,048,575 rows on 7 of 10 days');
    expect(screen.getByText(/AUROC \(POOLED, SECONDARY\)/)).toBeInTheDocument();
  });
});
