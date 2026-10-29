import React from 'react';
import { render, screen, within } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import ForecastTimeline from '../components/ForecastTimeline/ForecastTimeline';

const history = {
  observed: true,
  window_seconds: 10,
  runs: [
    { stage: 'Benign', stage_id: 'benign', observed: true, may_be_heuristic: false,
      from: '2018-03-02T10:00:00', to: '2018-03-02T10:00:50', n_windows: 5, flow_count: 321 },
    { stage: 'Command & Control', stage_id: 'command_and_control', observed: true, may_be_heuristic: false,
      from: '2018-03-02T10:00:50', to: '2018-03-02T10:02:00', n_windows: 7, flow_count: 4567 },
  ],
};

describe('ForecastTimeline', () => {
  it('renders the real observed runs and highlights the most recent one', () => {
    render(<ForecastTimeline observedHistory={history} hostIp="10.0.0.1" probabilities={[0.12, 0.55]}
                             predictedStages={['Benign', 'Impact']} stageIsHeuristic={[false, true]} />);
    const runs = screen.getAllByTestId('observed-run');
    expect(runs).toHaveLength(2);
    expect(within(runs[0]).getByText('Benign')).toBeInTheDocument();
    expect(within(runs[0]).getByText(/5 windows · 321 flows/)).toBeInTheDocument();
    expect(within(runs[1]).getByText('Command & Control')).toBeInTheDocument();
    expect(within(runs[1]).getByText(/7 windows · 4567 flows/)).toBeInTheDocument();
    expect(within(runs[1]).getByText(/2018-03-02 10:00:50 to 2018-03-02 10:02:00/)).toBeInTheDocument();
    expect(runs[0].className).not.toMatch(/active/);
    expect(runs[1].className).toMatch(/active/);
    expect(within(runs[1]).getByText('LATEST')).toBeInTheDocument();
  });

  it('never shows the old hardcoded chain or numbers', () => {
    const { container, rerender } = render(<ForecastTimeline />);
    const banned = [/Reconnaissance/, /Initial Access/, /Execution/, /Port Scan/, /Beaconing/,
      /41\.2/, /63\.4/, /71\.8/, /Exfiltration/, /Lateral Movement/];
    for (const re of banned) expect(container.textContent).not.toMatch(re);
    rerender(<ForecastTimeline observedHistory={history} probabilities={[0.12]} predictedStages={['Benign']} />);
    for (const re of [/Execution/, /41\.2/, /63\.4/, /71\.8/]) expect(container.textContent).not.toMatch(re);
  });

  it('shows an honest empty state with no host and with no forecast', () => {
    const { rerender } = render(<ForecastTimeline />);
    expect(screen.getByTestId('observed-empty')).toHaveTextContent(/No host selected/);
    expect(screen.getByTestId('forecast-empty')).toHaveTextContent(/No host selected/);
    expect(screen.queryByTestId('observed-run')).toBeNull();
    expect(screen.queryByText(/Infiltration Prob/)).toBeNull();
    expect(screen.queryByText(/%/)).toBeNull();

    rerender(<ForecastTimeline hostIp="10.0.0.9" />);
    expect(screen.getByTestId('observed-empty')).toHaveTextContent(/No forecast loaded for 10\.0\.0\.9/);
    expect(screen.queryByText(/%/)).toBeNull();
  });

  it('labels unlabelled captures as unknown rather than benign', () => {
    const unl = { observed: false, runs: [{ stage: 'Unlabelled', stage_id: null, observed: false,
      may_be_heuristic: false, from: '2018-03-02T10:00:00', to: '2018-03-02T10:02:00', n_windows: 12, flow_count: 99 }] };
    render(<ForecastTimeline observedHistory={unl} hostIp="h" probabilities={[0.1]} predictedStages={['Benign']} />);
    expect(screen.getByText('Unlabelled')).toBeInTheDocument();
    expect(screen.getByText(/no ground-truth labels/)).toBeInTheDocument();
    expect(screen.getByText('NO LABELS')).toBeInTheDocument();
  });

  it('renders the K-step forecast from the API values only, with backend risk tiers', () => {
    render(<ForecastTimeline probabilities={[0.1, 0.45, 0.9]} predictedStages={['Benign', 'Impact', 'Impact']}
                             stageIsHeuristic={[false, false, true]} horizon={3} horizonSeconds={30} hostIp="h" />);
    expect(screen.getByText('10.0%')).toBeInTheDocument();
    expect(screen.getByText('45.0%')).toBeInTheDocument();
    expect(screen.getByText('90.0%')).toBeInTheDocument();
    expect(screen.getByText('LOW RISK')).toBeInTheDocument();
    expect(screen.getByText('HIGH RISK')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL RISK')).toBeInTheDocument();
    expect(screen.getByText('RULE-BASED')).toBeInTheDocument();
    expect(screen.getByText(/FORECAST HORIZON \(K = 3 \/ 30s\)/)).toBeInTheDocument();
  });
});
