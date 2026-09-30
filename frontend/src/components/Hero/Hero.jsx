import React, { useState, lazy, Suspense } from 'react';
import { useNavigate } from 'react-router-dom';
import BottomControls from '../BottomControls/BottomControls';
import './Hero.css';

const ParticleNetwork = lazy(() => import('../ParticleNetwork/ParticleNetwork'));

const Hero = () => {
  const navigate = useNavigate();
  const [mode, setMode] = useState('threat');
  const [density, setDensity] = useState(0.78);
  const [isPaused, setIsPaused] = useState(false);
  const [resetTrigger, setResetTrigger] = useState(0);
  const [formationIndex, setFormationIndex] = useState(0);
  const [clickPulse, setClickPulse] = useState(0);

  const handleResetView = () => {
    setMode('threat');
    setDensity(0.78);
    setFormationIndex(0);
    setIsPaused(false);
    setResetTrigger((prev) => prev + 1);
  };

  const handleCanvasClick = () => {
    setClickPulse((prev) => prev + 1);
  };

  const particleConfig = {
    density,
    chaos: 0.5,
    speed: 0.65,
    spread: 55.0
  };

  return (
    <div className="hero-section">
      <Suspense fallback={<div className="particle-container" style={{ background: 'var(--bg-void)' }} />}>
        <ParticleNetwork
          controlsConfig={particleConfig}
          isPaused={isPaused}
          mode={mode}
          resetTrigger={resetTrigger}
          onCanvasClick={handleCanvasClick}
          clickPulse={clickPulse}
          formationIndex={formationIndex}
        />
      </Suspense>

      <BottomControls
        isPaused={isPaused}
        onPauseToggle={() => setIsPaused(!isPaused)}
        onResetView={handleResetView}
      />

      {/* High-End Technical Hero Copy Redesign */}
      <div className="hero-overlay-content">
        <div className="hero-eyebrow">
          PHOENIX IDPS · THREAT FORECASTING ENGINE
        </div>

        <h1 className="hero-title">
          <span className="hero-line1">SEE THE ATTACK.</span>
          <span className="hero-line2">FORECAST WHAT COMES NEXT.</span>
        </h1>

        <p className="hero-description">
          Phoenix IDPS transforms network traffic into an evolving threat state — detecting hostile behavior, classifying attack stages, and forecasting how an intrusion may propagate next.
        </p>

        <div className="hero-pipeline-strip font-mono">
          <span className="pipeline-step">PCAP</span>
          <span className="pipeline-sep">/</span>
          <span className="pipeline-step">FLOW</span>
          <span className="pipeline-sep">/</span>
          <span className="pipeline-step">DETECT</span>
          <span className="pipeline-sep">/</span>
          <span className="pipeline-step">CLASSIFY</span>
          <span className="pipeline-sep">/</span>
          <span className="pipeline-step">FORECAST</span>
        </div>

        <div className="hero-actions">
          <button
            className="btn-primary hero-btn"
            onClick={() => navigate(localStorage.getItem('auth') === 'true' ? '/dashboard' : '/login')}
          >
            OPEN DASHBOARD
          </button>
          <button
            className="btn-ghost hero-btn"
            onClick={() => {
              const el = document.getElementById('how-it-works') || document.getElementById('platform');
              if (el) el.scrollIntoView({ behavior: 'smooth' });
            }}
          >
            EXPLORE PLATFORM
          </button>
        </div>
      </div>
    </div>
  );
};

export default Hero;
