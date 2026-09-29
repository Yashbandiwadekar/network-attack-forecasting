import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import ForecastProbabilityCurve from '../components/ForecastProbabilityCurve/ForecastProbabilityCurve';

describe('ForecastProbabilityCurve Component', () => {
  it('renders K-step forecast curve with correct number of data points', () => {
    const probs = [0.08, 0.14, 0.27, 0.41, 0.63, 0.71];
    render(<ForecastProbabilityCurve probabilities={probs} />);

    expect(screen.getByText(/K-STEP INFILTRATION PROBABILITY CURVE/i)).toBeInTheDocument();
    expect(screen.getByText(/HORIZON K = 6/i)).toBeInTheDocument();
    expect(screen.getByText(/71.0%/i)).toBeInTheDocument();

    // Verify all 6 step labels exist
    for (let k = 1; k <= 6; k++) {
      expect(screen.getByText(`K=${k}`)).toBeInTheDocument();
    }
  });

  it('renders loading state when isLoading prop is true', () => {
    render(<ForecastProbabilityCurve isLoading={true} />);
    expect(screen.getByText(/Loading forecast models.../i)).toBeInTheDocument();
  });

  it('renders empty state when probabilities array is empty', () => {
    render(<ForecastProbabilityCurve probabilities={[]} />);
    expect(screen.getByText(/No forecast available for this analysis/i)).toBeInTheDocument();
  });

  it('renders error message when error prop is passed', () => {
    render(<ForecastProbabilityCurve error="Failed to fetch model weights" />);
    expect(screen.getByText(/⚠️ Failed to fetch model weights/i)).toBeInTheDocument();
  });

  it('displays heuristic warning badge when stage_is_heuristic is true', () => {
    const probs = [0.15, 0.30, 0.45];
    render(<ForecastProbabilityCurve probabilities={probs} stage_is_heuristic={true} />);
    expect(screen.getByText(/HEURISTIC STAGE PREDICTION/i)).toBeInTheDocument();
  });
});
