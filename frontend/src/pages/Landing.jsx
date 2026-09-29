import React from 'react';
import { useNavigate } from 'react-router-dom';
import Hero from '../components/Hero/Hero';
import TelemetryStrip from '../components/TelemetryStrip/TelemetryStrip';
import WorkflowPipeline from '../components/WorkflowPipeline/WorkflowPipeline';
import ForecastTimeline from '../components/ForecastTimeline/ForecastTimeline';
import DatasetTable from '../components/DatasetTable/DatasetTable';
import ThreatScoreGauge from '../components/ThreatScoreGauge/ThreatScoreGauge';
import './Landing.css';

const Landing = () => {
  const navigate = useNavigate();

  return (
    <div className="landing-page">
      {/* 1. Strictly Rebuilt Hero Network Canvas */}
      <Hero />

      {/* 2. Live Telemetry Strip Readout */}
      <TelemetryStrip />

      {/* 3. System Architecture & Workflow Pipeline */}
      <div id="platform" className="section-technical">
        <div className="section-header">
          <span className="section-mono-tag">SYSTEM ARCHITECTURE PIPELINE</span>
          <h2>End-to-End Threat Forecasting Pipeline</h2>
          <p className="section-desc">
            Raw network flow records undergo feature normalization, sequential model evaluation,
            and state-transition forecasting to generate explainable security intelligence.
          </p>
        </div>
        <WorkflowPipeline />
      </div>

      {/* 4. Threat State Forecast Horizon & Timeline */}
      <div id="how-it-works" className="section-technical alt-bg">
        <div className="section-header">
          <span className="section-mono-tag">STATE TRANSITION MODELING</span>
          <h2>Observed Traffic vs. K-Step Threat Forecast</h2>
          <p className="section-desc">
            Contrasting verified past flow evidence against predicted future attack stage transitions (Horizon K = 5).
          </p>
        </div>
        <ForecastTimeline />
      </div>

      {/* 5. Live Telemetry Risk Score & Evidence Chain */}
      <div className="section-technical">
        <div className="section-header">
          <span className="section-mono-tag">EXPLAINABLE RISK EVALUATION</span>
          <h2>Threat Scoring & Evidence Chain</h2>
          <p className="section-desc">
            Every predicted threat state links directly to observable flow-level feature contributions.
          </p>
        </div>
        <ThreatScoreGauge />
      </div>

      {/* 6. Datasets Benchmark Evaluation */}
      <div id="datasets" className="section-technical alt-bg">
        <div className="section-header">
          <span className="section-mono-tag">RESEARCH BENCHMARK EVALUATION</span>
          <h2>Cross-Dataset Validation Baselines</h2>
          <p className="section-desc">
            Model performance is evaluated across diverse real and synthetic flow benchmarks to guarantee cross-dataset generalization.
          </p>
        </div>
        <DatasetTable />
      </div>

      {/* 7. Security Assurance & Deployment */}
      <div id="research" className="section-technical">
        <div className="section-header">
          <span className="section-mono-tag">DEPLOYMENT ARCHITECTURE</span>
          <h2>On-Premises Security Where Your Data Stays Offline</h2>
          <p className="section-desc">
            Built for enterprise SOCs, MSSPs, and isolated critical infrastructure environments requiring offline PCAP/CSV analysis with zero external telemetry.
          </p>
        </div>
        <div className="deployment-grid">
          <div className="deployment-panel">
            <span className="panel-mono-tag">ENTERPRISE SOC</span>
            <h3>Real-Time SOC Integration</h3>
            <p>Accelerate triage and incident response through early threat forecasting and explainable evidence chains.</p>
          </div>
          <div className="deployment-panel">
            <span className="panel-mono-tag">MSSP PLATFORM</span>
            <h3>Multi-Tenant Managed Security</h3>
            <p>Provide early warning forecast services for multiple client network enclaves from a unified engine.</p>
          </div>
          <div className="deployment-panel">
            <span className="panel-mono-tag">ISOLATED INFRASTRUCTURE</span>
            <h3>Air-Gapped Critical Networks</h3>
            <p>Operate 100% offline on local hardware with zero cloud dependencies or mandatory external API calls.</p>
          </div>
        </div>
      </div>

      {/* 8. Restrained CTA */}
      <div className="section-technical cta-section">
        <span className="section-mono-tag">READY FOR DEPLOYMENT</span>
        <h2>See threats before they escalate.</h2>
        <p className="section-desc">Analyze network traffic, understand attack behavior, and explore the forecast field.</p>
        <div className="cta-actions">
          <button className="btn-primary" onClick={() => navigate('/login')}>Open Dashboard</button>
          <button className="btn-ghost" onClick={() => navigate('/login')}>View Research Docs</button>
        </div>
      </div>

      {/* 9. Minimal Technical Footer */}
      <footer className="footer-technical">
        <div className="footer-inner">
          <div className="footer-left">
            <span className="footer-brand">PHOENIX IDPS</span>
            <span className="footer-desc">Intelligent Intrusion Detection & Prevention System</span>
          </div>
          <div className="footer-right">
            <a href="#platform">Platform</a>
            <a href="#how-it-works">Forecast Timeline</a>
            <a href="#datasets">Datasets</a>
            <a href="/login">Demo Access</a>
            <a href="/dashboard">Dashboard</a>
          </div>
        </div>
        <div className="footer-sub font-mono">© 2026 Phoenix IDPS — All Rights Reserved.</div>
      </footer>
    </div>
  );
};

export default Landing;
