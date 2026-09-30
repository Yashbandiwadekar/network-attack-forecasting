import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Dashboard/Sidebar';
import Header from '../components/Dashboard/Header';
import TelemetryStrip from '../components/TelemetryStrip/TelemetryStrip';
import ForecastTimeline from '../components/ForecastTimeline/ForecastTimeline';
import ThreatScoreGauge from '../components/ThreatScoreGauge/ThreatScoreGauge';
import ForecastProbabilityCurve from '../components/ForecastProbabilityCurve/ForecastProbabilityCurve';
import WhatIfPanel from '../components/WhatIfPanel/WhatIfPanel';
import AuditLedger from '../components/AuditLedger/AuditLedger';
import { systemApi, datasetApi, forecastApi, explainApi, analysisApi, reportApi, evalApi, responseApi } from '../api';
import { UploadCloud, CheckCircle, AlertTriangle, FileText, Activity, ShieldCheck, Database, RefreshCw } from 'lucide-react';
import './Dashboard.css';

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [systemStatus, setSystemStatus] = useState(null);
  const [datasetsData, setDatasetsData] = useState(null);
  const [activeDataset, setActiveDataset] = useState('CIC-IDS-2018');
  const [hosts, setHosts] = useState([]);
  const [selectedHostIp, setSelectedHostIp] = useState('');
  const [forecastData, setForecastData] = useState(null);
  const [attributionData, setAttributionData] = useState(null);
  const [narrativeData, setNarrativeData] = useState(null);
  const [mitreData, setMitreData] = useState(null);
  const [evalMetrics, setEvalMetrics] = useState(null);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [reportResult, setReportResult] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [whatIfResult, setWhatIfResult] = useState(null);
  const [isolationResult, setIsolationResult] = useState(null);
  const [isolationLoading, setIsolationLoading] = useState(false);

  // Initial load & 5-second polling loop
  useEffect(() => {
    fetchInitialData();

    const interval = setInterval(() => {
      fetchSilentUpdates();
    }, 5000);

    return () => clearInterval(interval);
  }, [activeDataset]);

  useEffect(() => {
    if (selectedHostIp) {
      fetchHostDetails(selectedHostIp);
    }
    setWhatIfResult(null); // a counterfactual from a different host is meaningless here
    setIsolationResult(null);
  }, [selectedHostIp]);

  const fetchInitialData = async () => {
    setIsRefreshing(true);
    try {
      const [sys, ds, hList, metrics] = await Promise.all([
        systemApi.getStatus(),
        datasetApi.getDatasets(),
        forecastApi.getHosts(),
        // Measured evaluation results, served from docs/v2_converged_seed_results.json.
        // Never hardcode these in the UI: the project withdrew a 0.917 F1 for exactly this
        // reason (audit E1), and a stale literal here silently contradicts the README.
        evalApi.getMetrics().catch(() => null)
      ]);
      setSystemStatus(sys);
      setDatasetsData(ds);
      setEvalMetrics(metrics);
      if (ds && ds.active_dataset) setActiveDataset(ds.active_dataset);

      const returnedHosts = hList?.hosts || (Array.isArray(hList) ? hList : []);
      setHosts(returnedHosts);

      if (returnedHosts.length > 0) {
        setSelectedHostIp((prev) => prev || returnedHosts[0].host_ip);
      }
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      console.warn('Dashboard initial fetch notice:', err.message);
    } finally {
      setIsRefreshing(false);
    }
  };

  const fetchSilentUpdates = async () => {
    try {
      const [sys, hList] = await Promise.all([
        systemApi.getStatus(),
        forecastApi.getHosts()
      ]);
      setSystemStatus(sys);
      const returnedHosts = hList?.hosts || (Array.isArray(hList) ? hList : []);
      setHosts(returnedHosts);
      if (returnedHosts.length > 0 && !selectedHostIp) {
        setSelectedHostIp(returnedHosts[0].host_ip);
      }
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      console.warn('Background update notice:', err.message);
    }
  };

  const fetchHostDetails = async (ip) => {
    try {
      const [predict, attr, narr, mitre] = await Promise.all([
        forecastApi.predict(ip, 6),
        explainApi.getAttribution(ip),
        explainApi.getNarrative(ip),
        explainApi.getMitre()
      ]);
      setForecastData(predict);
      setAttributionData(attr);
      setNarrativeData(narr);
      setMitreData(mitre);
    } catch (err) {
      console.error('Error fetching host details:', err);
    }
  };

  const handleDatasetChange = async (e) => {
    const newDs = e.target.value;
    try {
      await datasetApi.selectDataset(newDs);
      setActiveDataset(newDs);
      fetchInitialData();
    } catch (err) {
      console.error('Dataset switch error:', err);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploadStatus({ state: 'uploading', message: `Uploading & extracting flow records from ${file.name}...` });
    try {
      const res = await analysisApi.uploadFile(file);
      setUploadStatus({ state: 'success', message: res.message, data: res });
      if (res.new_host_ip) {
        setSelectedHostIp(res.new_host_ip);
      }
      fetchInitialData();
    } catch (err) {
      setUploadStatus({ state: 'error', message: err.message });
    }
  };

  const handleGenerateReport = async () => {
    try {
      const res = await reportApi.generateReport(selectedHostIp);
      setReportResult(res);
    } catch (err) {
      console.error('Report error:', err);
    }
  };

  const handleSimulateIsolation = async () => {
    if (!selectedHostIp) return;
    setIsolationLoading(true);
    try {
      const res = await responseApi.simulateIsolation(selectedHostIp);
      setIsolationResult(res);
    } catch (err) {
      console.error('Simulate isolation error:', err);
    } finally {
      setIsolationLoading(false);
    }
  };

  return (
    <div className="gpf-dashboard-page">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />

      <div className="gpf-main-layout">
        <Header systemStatus={systemStatus} selectedHost={selectedHostIp} />

        <div className="gpf-content-area">
          {/* Top Bar Status & Dataset Context Switcher */}
          <div className="dashboard-status-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.2rem', padding: '0.8rem 1.2rem', background: '#080808', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <Database size={16} className="text-orange" />
              <span className="font-mono" style={{ fontSize: '0.8rem', color: '#a0a0a0' }}>DATA SOURCE CONTEXT:</span>
              <select
                value={activeDataset}
                onChange={handleDatasetChange}
                style={{ background: '#121212', color: '#ff6a00', border: '1px solid rgba(255,106,0,0.4)', borderRadius: '4px', padding: '0.3rem 0.8rem', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', cursor: 'pointer' }}
              >
                {datasetsData?.datasets?.map((d) => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#888888' }}>
              <span>
                STATUS: <strong className="text-good">● LIVE POLLING</strong>
              </span>
              <span>
                LAST UPDATED: <strong className="text-white">{lastUpdated || 'Initialing...'}</strong>
              </span>
              <button onClick={fetchInitialData} style={{ background: 'transparent', border: 'none', color: '#a0a0a0', cursor: 'pointer' }} title="Force Refresh Data">
                <RefreshCw size={14} className={isRefreshing ? 'spin' : ''} />
              </button>
            </div>
          </div>

          <TelemetryStrip status={systemStatus} hostCount={hosts.length} />

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="tab-content">
              {/* Monitored Hosts Table */}
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>ACTIVE MONITORED ENDPOINTS & RISK MATRIX</span>
                  <span>{hosts.length > 0 ? 'SELECT HOST TO INSPECT' : 'NO HOSTS CAPTURED'}</span>
                </div>
                {hosts.length > 0 ? (
                  <table className="hosts-table">
                    <thead>
                      <tr>
                        <th>HOST IP</th>
                        <th>FLOW COUNT</th>
                        <th>PEAK PROB (K=6)</th>
                        <th>CURRENT STAGE</th>
                        <th>PREDICTED STAGE</th>
                        <th>SEVERITY</th>
                      </tr>
                    </thead>
                    <tbody>
                      {hosts.map((h) => (
                        <tr
                          key={h.host_ip}
                          className={selectedHostIp === h.host_ip ? 'selected' : ''}
                          onClick={() => setSelectedHostIp(h.host_ip)}
                        >
                          <td style={{ fontWeight: 600 }}>{h.host_ip}</td>
                          <td>{h.flow_count?.toLocaleString() || 0}</td>
                          <td style={{ color: (h.peak_prob || 0) > 0.7 ? '#c83b32' : '#ff6a00' }}>
                            {((h.peak_prob || 0) * 100).toFixed(1)}%
                          </td>
                          <td>{h.current_stage || 'ANALYZING'}</td>
                          <td>{h.predicted_stage || 'FORECASTING'}</td>
                          <td>
                            <span className={`sev-badge ${h.severity || 'HIGH'}`}>{h.severity || 'HIGH'}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div style={{ padding: '2.5rem 1rem', textAnchor: 'middle', textAlign: 'center', background: '#0a0a0a', border: '1px stroke rgba(255,255,255,0.05)', borderRadius: '6px' }}>
                    <Activity size={36} style={{ color: '#ff7b00', marginBottom: '0.8rem', opacity: 0.8 }} />
                    <h3 style={{ color: '#f5f5f5', fontSize: '1rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                      No active network capture loaded
                    </h3>
                    <p style={{ color: '#888888', fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>
                      Upload a PCAP, PCAPNG, or CSV capture file in <strong>INGESTION & FLOWS</strong> to populate endpoints and trigger real-time sequence forecasting.
                    </p>
                  </div>
                )}
              </div>

              {/* Selected Host Threat Evaluation */}
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>TARGET INSPECTION: {selectedHostIp || 'SELECT HOST IP'}</span>
                  <span>RISK GAUGE & EVIDENCE</span>
                </div>
                <ThreatScoreGauge
                  score={forecastData?.infiltration_probs ? Math.max(...forecastData.infiltration_probs) : 0}
                  horizon={forecastData?.horizon_k || 6}
                  attackFamily={forecastData?.predicted_stages
                    ? forecastData.predicted_stages[
                        forecastData.infiltration_probs.indexOf(Math.max(...forecastData.infiltration_probs))
                      ]
                    : '—'}
                  rationale={(attributionData?.feature_attributions || []).slice(0, 3).map(
                    (a) => `${a.feature}: ${a.contribution >= 0 ? '+' : ''}${a.contribution.toFixed(4)} contribution to the infiltration score`
                  )}
                />
              </div>

              {/* State Transition Timeline */}
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>K-STEP FORECAST HORIZON (HORIZON K = 6 / 60 SECONDS)</span>
                  <span>OBSERVED VS PREDICTED</span>
                </div>
                <ForecastTimeline
                  probabilities={forecastData?.infiltration_probs}
                  predictedStages={forecastData?.predicted_stages}
                  stageIsHeuristic={forecastData?.stage_is_heuristic}
                  horizon={forecastData?.horizon_k || 6}
                />
              </div>

              {/* Model Audit Validation & Evaluation Metrics Panel.
                  Every figure comes from /api/v1/eval/metrics, which reads the seed-summary
                  results file. Do not hardcode values here: a literal that drifts from the
                  measured result is the failure mode audit E1 was about. */}
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>MODEL AUDIT VALIDATION &amp; MEASURED PERFORMANCE</span>
                  <span>{evalMetrics ? `${evalMetrics.n_seeds} SEEDS · ${evalMetrics.split?.toUpperCase()}` : 'AWAITING API'}</span>
                </div>
                {!evalMetrics ? (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#888888', padding: '0.5rem 0' }}>
                    Measured results unavailable — the backend API is not reachable.
                  </div>
                ) : (
                  <>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', fontFamily: 'var(--font-mono)' }}>
                      {[
                        { label: 'AUROC', stat: evalMetrics.auroc, color: 'var(--color-accent-amber)', note: 'Ranking quality' },
                        { label: 'AUPRC', stat: evalMetrics.auprc, color: '#0ca30c', note: 'Precision-recall area' },
                        { label: 'PRECISION @ 0.5', stat: evalMetrics['precision_at_0.5'], color: 'var(--color-accent-orange)', note: 'Of what it flags' },
                        { label: 'RECALL @ 0.5', stat: evalMetrics['recall_at_0.5'], color: 'var(--color-accent-red)', note: 'Of attacks caught' },
                        { label: 'F1 @ 0.5', stat: evalMetrics['f1_at_0.5'], color: '#ff6a00', note: 'Harmonic mean' },
                      ].map(({ label, stat, color, note }) => (
                        <div key={label} style={{ background: '#0a0a0a', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border)' }}>
                          <span style={{ fontSize: '0.7rem', color: '#888888', display: 'block' }}>{label}</span>
                          <strong style={{ fontSize: '1.25rem', color, display: 'block', marginTop: '0.2rem' }}>
                            {stat ? `${stat.mean.toFixed(3)} ± ${stat.sd.toFixed(3)}` : '—'}
                          </strong>
                          <span style={{ fontSize: '0.65rem', color: '#888888' }}>{note}</span>
                        </div>
                      ))}
                    </div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: '#888888', marginTop: '0.9rem', lineHeight: 1.6 }}>
                      {evalMetrics.n_test_sequences?.toLocaleString()} test sequences
                      ({evalMetrics.n_test_positive?.toLocaleString()} positive),
                      mean ± SD over {evalMetrics.n_seeds} independent training runs.
                      Source: {evalMetrics.source}
                      {evalMetrics.note && (
                        <div style={{ marginTop: '0.4rem', color: '#a0a0a0' }}>{evalMetrics.note}</div>
                      )}
                    </div>
                    {evalMetrics.generalisation_lofo && (
                      <div style={{ marginTop: '1rem' }}>
                        <div className="panel-header-mono" style={{ marginBottom: '0.6rem' }}>
                          <span>GENERALISATION TO UNSEEN ATTACK FAMILIES</span>
                          <span>LEAVE-ONE-FAMILY-OUT</span>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.6rem', fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                          {Object.entries(evalMetrics.generalisation_lofo).map(([family, v]) => (
                            <div key={family} style={{ background: '#080808', padding: '0.7rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border)' }}>
                              <span style={{ color: '#888888', display: 'block' }}>{family.replace(/_/g, ' ').toUpperCase()}</span>
                              <strong style={{ color: v.distinguishable_from_chance ? '#0ca30c' : '#888888' }}>
                                AUROC {v.auroc_mean.toFixed(3)} ± {v.auroc_sd.toFixed(3)}
                              </strong>
                              <span style={{ display: 'block', color: '#888888' }}>
                                {v.distinguishable_from_chance ? 'above chance' : 'not distinguishable from chance'}
                              </span>
                            </div>
                          ))}
                        </div>
                        {evalMetrics.generalisation_note && (
                          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: '#888888', marginTop: '0.6rem', lineHeight: 1.6 }}>
                            {evalMetrics.generalisation_note}
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          )}

          {/* ANALYSIS / INGESTION TAB */}
          {activeTab === 'analysis' && (
            <div className="tab-content">
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>TRAFFIC CAPTURE INGESTION WORKSPACE</span>
                  <span>PCAP / PCAPNG / CSV</span>
                </div>
                
                <label className="upload-dropzone">
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', width: '100%', pointerEvents: 'none' }}>
                    <UploadCloud size={44} style={{ color: '#ff6a00', marginBottom: '1rem' }} />
                    <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: '#f5f5f5', marginBottom: '0.5rem', textAlign: 'center' }}>
                      Upload PCAP, PCAPNG, or Flow CSV File
                    </h3>
                    <p style={{ color: '#888888', fontSize: '0.85rem', textAlign: 'center', maxWidth: '500px' }}>
                      Drag &amp; drop network captures or click to select file. Supported: .pcap, .pcapng, .csv
                    </p>
                    <p style={{ color: '#888888', fontSize: '0.78rem', textAlign: 'center', maxWidth: '520px', marginTop: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                      Needs at least 2 minutes of traffic from the same source IP (12 consecutive
                      10s windows). CSVs must use the CICFlowMeter schema.
                    </p>
                  </div>
                  <input type="file" onChange={handleFileUpload} style={{ display: 'none' }} accept=".pcap,.pcapng,.csv" />
                </label>

                {uploadStatus && (
                  <div className={`upload-status-box ${uploadStatus.state}`} style={{ marginTop: '1.2rem', padding: '1rem', background: '#121212', borderRadius: '6px' }}>
                    {uploadStatus.state === 'success' ? <CheckCircle className="text-good" size={20} /> : <AlertTriangle className="text-orange" size={20} />}
                    <span style={{ marginLeft: '0.8rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                      {uploadStatus.message}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* K-STEP FORECAST TAB */}
          {activeTab === 'forecast' && (
            <div className="tab-content">
              <div className="gpf-panel">
                <ForecastProbabilityCurve
                  probabilities={forecastData?.infiltration_probs}
                  stepSeconds={forecastData?.step_seconds}
                  stages={forecastData?.predicted_stages}
                  heuristicFlags={forecastData?.stage_is_heuristic}
                  disclosureNotes={forecastData?.stage_disclosure_notes}
                  horizonSeconds={forecastData?.horizon_seconds}
                  title={`INFILTRATION FORECAST — ${selectedHostIp || 'SELECT HOST'}`}
                  counterfactualProbabilities={whatIfResult?.counterfactual_infiltration_probs}
                  counterfactualLabel={
                    whatIfResult
                      ? `What-if: ${whatIfResult.feature_label} × ${whatIfResult.scale}`
                      : null
                  }
                  counterfactualCaveat={whatIfResult?.caveat}
                />

                <WhatIfPanel
                  hostIp={selectedHostIp}
                  onResult={setWhatIfResult}
                  onClear={() => setWhatIfResult(null)}
                />

                {forecastData && forecastData.infiltration_probs && (
                  <div className="forecast-steps-bar" style={{ marginTop: '1.2rem' }}>
                    {forecastData.infiltration_probs.map((prob, idx) => {
                      const isHeuristicStep = Array.isArray(forecastData.stage_is_heuristic)
                        ? forecastData.stage_is_heuristic[idx]
                        : (typeof forecastData.stage_is_heuristic === 'boolean' ? forecastData.stage_is_heuristic : false);
                      const note = forecastData.stage_disclosure_note?.[idx] || (isHeuristicStep ? 'Rule-based heuristic prediction' : 'Trained model inference');

                      return (
                        <div key={idx} className="step-card" title={note}>
                          <div className="step-k">STEP K = {idx + 1} ({(idx + 1) * 10}s)</div>
                          <div className="step-prob">{(prob * 100).toFixed(1)}%</div>
                          <div className="step-stage">{forecastData.predicted_stages?.[idx] || 'STAGE'}</div>
                          {isHeuristicStep && (
                            <div style={{ fontSize: '0.65rem', color: '#ffaa00', marginTop: '0.3rem', fontFamily: 'var(--font-mono)' }}>
                              ⚠️ HEURISTIC RULE
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>STATE TRANSITION PROBABILITIES</span>
                  <span>MARKOV / NEURAL SEQUENCE</span>
                </div>
                <ForecastTimeline
                  probabilities={forecastData?.infiltration_probs}
                  predictedStages={forecastData?.predicted_stages}
                  stageIsHeuristic={forecastData?.stage_is_heuristic}
                  horizon={forecastData?.horizon_k || 6}
                />
              </div>
            </div>
          )}

          {/* EXPLAINABILITY TAB */}
          {activeTab === 'evidence' && (
            <div className="tab-content">
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>FEATURE IMPORTANCE & SHAP ATTRIBUTION</span>
                  <span>TARGET: {selectedHostIp || 'SELECT HOST'}</span>
                </div>

                {attributionData && attributionData.feature_attributions && (
                  <div className="attribution-list">
                    {attributionData.feature_attributions.map((attr, idx) => (
                      <div key={idx} className="attr-item">
                        <div className="attr-header">
                          <span>{attr.feature}</span>
                          <span style={{ color: '#ff6a00' }}>{(attr.contribution * 100).toFixed(1)}%</span>
                        </div>
                        <div className="attr-bar-bg">
                          <div className="attr-bar-fill" style={{ width: `${attr.contribution * 100}%` }}></div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {narrativeData && (
                <div className="gpf-panel">
                  <div className="panel-header-mono">
                    <span>AUTOMATED ATTACK NARRATIVE & CVE THREAT INTEL</span>
                    <span>NVD CVE & CAPEC SNAPSHOT</span>
                  </div>
                  <p style={{ color: '#a0a0a0', lineHeight: '1.6', marginBottom: '1.2rem' }}>
                    {narrativeData.narrative}
                  </p>

                  {narrativeData.cve_details && (
                    <div className="cve-snapshot-list" style={{ marginBottom: '1.2rem' }}>
                      <strong style={{ display: 'block', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#888888', marginBottom: '0.6rem' }}>
                        HISTORICAL EXPLOITED CVES (NVD SNAPSHOT):
                      </strong>
                      {narrativeData.cve_details.map((cve, i) => (
                        <div key={i} style={{ background: '#121212', border: '1px solid rgba(255,255,255,0.08)', padding: '0.8rem', borderRadius: '4px', marginBottom: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                          <span style={{ color: '#ff6a00', fontWeight: 600 }}>{cve.cve_id}</span> - {cve.description}
                        </div>
                      ))}
                    </div>
                  )}

                  <div style={{ background: 'rgba(200, 59, 50, 0.1)', border: '1px solid #c83b32', padding: '1rem', borderRadius: '6px' }}>
                    <strong style={{ color: '#c83b32', display: 'block', marginBottom: '0.4rem', fontFamily: 'var(--font-mono)' }}>
                      RECOMMENDED ACTION: {narrativeData.recommended_action?.title}
                    </strong>
                    <span style={{ fontSize: '0.85rem', color: '#f5f5f5' }}>
                      {narrativeData.recommended_action?.action}
                    </span>

                    {isolationResult ? (
                      <div style={{ marginTop: '0.8rem', padding: '0.6rem 0.8rem', border: '1px solid #33c9ff', borderRadius: '4px', background: 'rgba(51,201,255,0.08)' }}>
                        <strong style={{ color: '#33c9ff', fontFamily: 'var(--font-mono)', fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                          ISOLATED (SIMULATED)
                        </strong>
                        <div style={{ fontSize: '0.72rem', color: '#a0d8ea', marginTop: '0.3rem' }}>
                          {isolationResult.note}
                        </div>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={handleSimulateIsolation}
                        disabled={isolationLoading || !selectedHostIp}
                        style={{
                          marginTop: '0.8rem', fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
                          letterSpacing: '0.04em', padding: '0.4rem 0.8rem', borderRadius: '4px',
                          border: '1px solid #33c9ff', background: 'transparent', color: '#33c9ff',
                          cursor: isolationLoading || !selectedHostIp ? 'not-allowed' : 'pointer',
                          opacity: isolationLoading || !selectedHostIp ? 0.5 : 1,
                        }}
                      >
                        {isolationLoading ? 'SIMULATING…' : 'SIMULATE ISOLATION'}
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* AUDIT & REPORTS TAB */}
          {activeTab === 'reports' && (
            <div className="tab-content">
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>CERT-IN INCIDENT MANDATORY REPORT GENERATOR</span>
                  <span>CRYPTOGRAPHIC AUDIT LEDGER</span>
                </div>

                <button
                  className="btn-primary"
                  onClick={handleGenerateReport}
                  disabled={!selectedHostIp}
                  style={{ marginBottom: '1.5rem', opacity: selectedHostIp ? 1 : 0.6 }}
                >
                  Generate CERT-In Incident Report for {selectedHostIp || 'Target Host'}
                </button>

                {/* Report + ledger. The previous block read reportResult.category /
                    .detected_at / .hours_remaining at the top level -- the API nests those under
                    `compliance` -- so every field silently fell back to a hardcoded string
                    ("5.8 hrs remaining"). AuditLedger reads the real shape, and the download
                    link now calls the endpoint instead of alert()-ing. */}
                {reportResult && (
                  <AuditLedger
                    report={reportResult}
                    status={systemStatus}
                    onDownload={async () => {
                      try {
                        const doc = await reportApi.downloadReport(`${reportResult.host_ip}.json`);
                        const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `${reportResult.host_ip}-ledger-record.json`;
                        a.click();
                        URL.revokeObjectURL(url);
                      } catch (err) {
                        console.error('Ledger record download failed:', err);
                      }
                    }}
                  />
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
