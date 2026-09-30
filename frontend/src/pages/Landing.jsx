import React from 'react';
import { useNavigate } from 'react-router-dom';
import Hero from '../components/Hero/Hero';
import TelemetryStrip from '../components/TelemetryStrip/TelemetryStrip';
import WorkflowPipeline from '../components/WorkflowPipeline/WorkflowPipeline';
import DatasetTable from '../components/DatasetTable/DatasetTable';
import ThreatScoreGauge from '../components/ThreatScoreGauge/ThreatScoreGauge';
import ForecastProbabilityCurve from '../components/ForecastProbabilityCurve/ForecastProbabilityCurve';
import AuditLedger from '../components/AuditLedger/AuditLedger';
import showcase from '../data/showcase.json';
import './Landing.css';

/* The landing page is public and pre-login, so it has no capture loaded and cannot show live
   telemetry. It used to fill that gap with invented figures. It now renders a *recorded* run
   instead: src/data/showcase.json is produced by scripts/record_showcase.py against the running
   API on real CIC-IDS-2018 traffic, so every number here came out of the actual model. */
const Landing = () => {
  const navigate = useNavigate();

  const { status, predict, hosts, report, capture } = showcase;
  const topHost = hosts?.[0];
  const provenance = `Recorded run · ${capture.dataset} · ${capture.day} · ${showcase.upload.extracted_flows.toLocaleString()} flows`;

  return (
    <div className="landing-page">
      {/* 1. Strictly Rebuilt Hero Network Canvas */}
      <Hero />

      {/* 2. Telemetry from the recorded run */}
      <TelemetryStrip status={status} hostCount={hosts?.length} />
      <p className="sample-data-note">{provenance}</p>

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

      {/* 4. The real 60-second forecast -- the project's headline capability */}
      <div id="how-it-works" className="section-technical alt-bg">
        <div className="section-header">
          <span className="section-mono-tag">STATE TRANSITION MODELING</span>
          <h2>A 60-Second Forecast, From Real Traffic</h2>
          <p className="section-desc">
            The world model rolls its own predicted state forward six times, ten seconds per step,
            producing an infiltration probability and an attack stage for every step of the next
            minute. Below is an actual forecast for the busiest host in a real CIC-IDS-2018 capture.
          </p>
        </div>

        <div className="showcase-forecast">
          <ForecastProbabilityCurve
            probabilities={predict.infiltration_probs}
            stepSeconds={predict.step_seconds}
            stages={predict.predicted_stages}
            heuristicFlags={predict.stage_is_heuristic}
            disclosureNotes={predict.stage_disclosure_notes}
            horizonSeconds={predict.horizon_seconds}
            title={`INFILTRATION FORECAST — ${predict.host_ip}`}
          />
          <p className="sample-data-note">{provenance}</p>
        </div>

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
        <ThreatScoreGauge
          score={topHost.peak_prob}
          horizon={predict.horizon_k}
          confidence={null}
          attackFamily={topHost.predicted_stage}
          rationale={showcase.attribution.feature_attributions.slice(0, 3).map(
            (a) => `${a.feature}: ${a.contribution >= 0 ? '+' : ''}${a.contribution.toFixed(4)} contribution to the infiltration score`
          )}
        />
        <p className="sample-data-note">
          {provenance} — feature contributions are gradient × input attributions over the model's
          own 41-feature vector.
        </p>
      </div>

      {/* 5b. Tamper-evident audit trail + CERT-In reporting */}
      <div className="section-technical">
        <div className="section-header">
          <span className="section-mono-tag">EVIDENTIARY INTEGRITY</span>
          <h2>Every Alert Is Hash-Chained and Reportable</h2>
          <p className="section-desc">
            Each alert an analyst sees is appended to an append-only SHA-256 chain, so a record
            cannot be quietly altered or deleted afterwards. Reportable incidents are drafted
            against CERT-In's six-hour disclosure window, offline, with no external service.
          </p>
        </div>
        <div className="showcase-ledger">
          <AuditLedger report={report} status={status} />
          <p className="sample-data-note">{provenance}</p>
        </div>
      </div>

      {/* 6. Datasets Benchmark Evaluation */}
      <div id="datasets" className="section-technical alt-bg">
        <div className="section-header">
          <span className="section-mono-tag">RESEARCH BENCHMARK EVALUATION</span>
          <h2>Datasets and Evaluation Status</h2>
          <p className="section-desc">
            What the model is actually trained and evaluated on. Generalisation to unseen attack
            families is measured rather than assumed — and on three of four families it is not yet
            distinguishable from chance. The dashboard reports those figures with error bars.
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
