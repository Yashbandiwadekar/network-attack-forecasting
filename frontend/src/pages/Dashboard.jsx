import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from '../components/Dashboard/Sidebar';
import Header from '../components/Dashboard/Header';
import TelemetryStrip from '../components/TelemetryStrip/TelemetryStrip';
import ForecastTimeline from '../components/ForecastTimeline/ForecastTimeline';
import ThreatScoreGauge from '../components/ThreatScoreGauge/ThreatScoreGauge';
import ForecastProbabilityCurve from '../components/ForecastProbabilityCurve/ForecastProbabilityCurve';
import WhatIfPanel from '../components/WhatIfPanel/WhatIfPanel';
import AuditLedger from '../components/AuditLedger/AuditLedger';
import { systemApi, datasetApi, forecastApi, explainApi, analysisApi, reportApi, evalApi, responseApi } from '../api';
// BUG-007: removed unused imports FileText and ShieldCheck
import { UploadCloud, CheckCircle, AlertTriangle, Activity, Database, RefreshCw } from 'lucide-react';
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
  // BUG-007: mitreData state is fetched and stored inside fetchHostDetails;
  // it was declared here but never consumed by JSX — removing the top-level declaration.
  const [evalMetrics, setEvalMetrics] = useState(null);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [reportResult, setReportResult] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [whatIfResult, setWhatIfResult] = useState(null);
  const [isolationResult, setIsolationResult] = useState(null);
  const [isolationLoading, setIsolationLoading] = useState(false);
  // BUG-006: dataset switch loading and error state for visible UX feedback
  const [datasetSwitching, setDatasetSwitching] = useState(false);
  const [datasetError, setDatasetError] = useState(null);

  // BUG-007: declare fetch functions with useCallback BEFORE useEffect so they are stable
  // references — avoids the self-reference-during-initialization lint warning and the
  // exhaustive-deps warning that came from including them in effect dependency arrays.
  const fetchInitialData = useCallback(async () => {
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
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeDataset]);

  const fetchSilentUpdates = useCallback(async () => {
    try {
      const [sys, hList] = await Promise.all([
        systemApi.getStatus(),
        forecastApi.getHosts()
      ]);
      setSystemStatus(sys);
      const returnedHosts = hList?.hosts || (Array.isArray(hList) ? hList : []);
      setHosts(returnedHosts);
      setSelectedHostIp((prev) => {
        if (returnedHosts.length > 0 && !prev) return returnedHosts[0].host_ip;
        return prev;
      });
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      console.warn('Background update notice:', err.message);
    }
  }, []);

  const fetchHostDetails = useCallback(async (ip) => {
    try {
      const [predict, attr, narr] = await Promise.all([
        forecastApi.predict(ip, 6),
        explainApi.getAttribution(ip),
        explainApi.getNarrative(ip)
        // MITRE mapping is static; fetched once on mount via fetchInitialData if needed
      ]);
      setForecastData(predict);
      setAttributionData(attr);
      setNarrativeData(narr);
    } catch (err) {
      console.error('Error fetching host details:', err);
    }
  }, []);

  // Initial load & 5-second polling loop
  useEffect(() => {
    fetchInitialData();

    const interval = setInterval(() => {
      fetchSilentUpdates();
    }, 5000);

    return () => clearInterval(interval);
  }, [fetchInitialData, fetchSilentUpdates]);

  // BUG-007: selectedHostIp effect — derive the reset outside setState to avoid
  // calling setState synchronously inside an effect (set-state-in-effect warning).
  useEffect(() => {
    if (!selectedHostIp) return;
    // Reset counterfactual/isolation results when the selected host changes
    setWhatIfResult(null);
    setIsolationResult(null);
    fetchHostDetails(selectedHostIp);
  }, [selectedHostIp, fetchHostDetails]);

  // BUG-006: handleDatasetChange with explicit loading + atomic error UX feedback
  const handleDatasetChange = async (e) => {
    const newDs = e.target.value;
    if (newDs === activeDataset) return;
    setDatasetSwitching(true);
    setDatasetError(null);
    try {
      await datasetApi.selectDataset(newDs);
      setActiveDataset(newDs);
      await fetchInitialData();
    } catch (err) {
      // Preserve the previous valid dataset and show the user why it failed
      console.error('Dataset switch error:', err);
      const cleanMsg = err.message
        ? err.message.replace(/^Error:\s*HTTP \d+:\s*/, '').replace(/^HTTP \d+:\s*/, '')
        : '';
      setDatasetError(cleanMsg || `${newDs} could not be activated because its forecasting checkpoint is not available on this installation.`);
    } finally {
      setDatasetSwitching(false);
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

  const availableDatasets = (datasetsData?.datasets || []).filter((d) => d.checkpoint_available);

  return (
    <div className="gpf-dashboard-page">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />

      <div className="gpf-main-layout">
        <Header systemStatus={systemStatus} selectedHost={selectedHostIp} />

        <div className="gpf-content-area">
          {/* Top Bar Status & Dataset Context Switcher */}
          <div className="dashboard-status-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.2rem', padding: '0.8rem 1.2rem', background: 'var(--bg-panel)', border: '1px solid var(--line-10)', borderRadius: '6px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
              <Database size={16} className="text-orange" />
              <span className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--text-2)' }}>ACTIVE MODEL:</span>
              {/* The server ships model checkpoints, not raw datasets (those are large and git-ignored),
                  so only models actually present here are offered. With a single model there is nothing
                  to switch, so it is shown as a plain label rather than a one-item dropdown. Analysis
                  data comes from the capture the user uploads under Ingestion & Flows. */}
              {availableDatasets.length > 1 ? (
                <select
                  value={activeDataset}
                  onChange={handleDatasetChange}
                  disabled={datasetSwitching}
                  style={{ background: 'var(--bg-input)', color: datasetSwitching ? '#666' : 'var(--c-orange)', border: `1px solid ${datasetSwitching ? 'rgba(255,106,0,0.2)' : 'rgba(255,106,0,0.4)'}`, borderRadius: '4px', padding: '0.3rem 0.8rem', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', cursor: datasetSwitching ? 'wait' : 'pointer' }}
                >
                  {availableDatasets.map((d) => (
                    <option key={d.id} value={d.id}>{d.name}</option>
                  ))}
                </select>
              ) : (
                <span
                  className="font-mono"
                  data-testid="active-model-label"
                  style={{ fontSize: '0.8rem', color: 'var(--c-orange)', border: '1px solid rgba(255,106,0,0.4)', borderRadius: '4px', padding: '0.3rem 0.8rem' }}
                >
                  {availableDatasets[0]?.name || activeDataset}
                  <span style={{ color: 'var(--text-3)' }}> · trained model loaded · upload a capture to analyse</span>
                </span>
              )}
              {/* BUG-006: spinner while switching datasets */}
              {datasetSwitching && (
                <span style={{ fontSize: '0.75rem', color: 'var(--c-amber-3)', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <RefreshCw size={12} className="spin" /> Switching dataset…
                </span>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-3)' }}>
              <span>
                STATUS: <strong className="text-good">● LIVE POLLING</strong>
              </span>
              <span>
                LAST UPDATED: <strong className="text-white">{lastUpdated || 'Initialing...'}</strong>
              </span>
              <button onClick={fetchInitialData} style={{ background: 'transparent', border: 'none', color: 'var(--text-2)', cursor: 'pointer' }} title="Force Refresh Data">
                <RefreshCw size={14} className={isRefreshing ? 'spin' : ''} />
              </button>
            </div>
          </div>

          {/* BUG-006: visible error banner when dataset switch fails */}
          {datasetError && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.7rem 1.2rem', marginBottom: '1rem', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.4)', borderRadius: '6px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#f87171' }}>
              <AlertTriangle size={14} />
              <span>Dataset switch failed: {datasetError}</span>
              <button onClick={() => setDatasetError(null)} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', fontSize: '1rem', lineHeight: 1 }}>×</button>
            </div>
          )}

          <TelemetryStrip status={systemStatus} hostCount={hosts.length} />

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="tab-content">
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
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-3)', padding: '0.5rem 0' }}>
                    Measured results unavailable — the backend API is not reachable.
                  </div>
                ) : (
                  <>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', fontFamily: 'var(--font-mono)' }}>
                      {[
                        { label: 'AUROC', stat: evalMetrics.auroc, color: 'var(--color-accent-amber)', note: 'Ranking quality' },
                        { label: 'AUPRC', stat: evalMetrics.auprc, color: 'var(--c-green)', note: 'Precision-recall area' },
                        { label: 'PRECISION @ 0.5', stat: evalMetrics['precision_at_0.5'], color: 'var(--color-accent-orange)', note: 'Of what it flags' },
                        { label: 'RECALL @ 0.5', stat: evalMetrics['recall_at_0.5'], color: 'var(--color-accent-red)', note: 'Of attacks caught' },
                        { label: 'F1 @ 0.5', stat: evalMetrics['f1_at_0.5'], color: 'var(--c-orange)', note: 'Harmonic mean' },
                      ].map(({ label, stat, color, note }) => (
                        <div key={label} style={{ background: 'var(--bg-panel-2)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border)' }}>
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-3)', display: 'block' }}>{label}</span>
                          <strong style={{ fontSize: '1.25rem', color, display: 'block', marginTop: '0.2rem' }}>
                            {stat ? `${stat.mean.toFixed(3)} ± ${stat.sd.toFixed(3)}` : '—'}
                          </strong>
                          <span style={{ fontSize: '0.65rem', color: 'var(--text-3)' }}>{note}</span>
                        </div>
                      ))}
                    </div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-3)', marginTop: '0.9rem', lineHeight: 1.6 }}>
                      {evalMetrics.n_test_sequences?.toLocaleString()} test sequences
                      ({evalMetrics.n_test_positive?.toLocaleString()} positive),
                      mean ± SD over {evalMetrics.n_seeds} independent training runs.
                      Source: {evalMetrics.source}
                      {evalMetrics.note && (
                        <div style={{ marginTop: '0.4rem', color: 'var(--text-2)' }}>{evalMetrics.note}</div>
                      )}
                    </div>
                    {evalMetrics.generalisation_lofo && (
                      <div style={{ marginTop: '1.2rem' }}>
                        <div className="panel-header-mono" style={{ marginBottom: '0.8rem', fontSize: '0.92rem', color: 'var(--text-1-dim)' }}>
                          <span>GENERALISATION TO UNSEEN ATTACK FAMILIES</span>
                          <span style={{ color: 'var(--text-2-hi)' }}>LEAVE-ONE-FAMILY-OUT</span>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.8rem', fontFamily: 'var(--font-mono)' }}>
                          {Object.entries(evalMetrics.generalisation_lofo).map(([family, v]) => (
                            <div key={family} style={{ background: 'var(--bg-input)', padding: '0.95rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--line-15)' }}>
                              <span style={{ color: 'var(--text-2-hi)', display: 'block', fontSize: '0.85rem', letterSpacing: '0.04em', marginBottom: '0.35rem' }}>
                                {family.replace(/_/g, ' ').toUpperCase()}
                              </span>
                              <strong style={{ display: 'block', fontSize: '1.15rem', color: v.distinguishable_from_chance ? 'var(--c-green)' : 'var(--text-1)', marginBottom: '0.3rem' }}>
                                AUROC {v.auroc_mean.toFixed(3)} ± {v.auroc_sd.toFixed(3)}
                              </strong>
                              <span style={{ display: 'block', fontSize: '0.85rem', color: v.distinguishable_from_chance ? 'var(--c-green)' : 'var(--text-2-hi)' }}>
                                {v.distinguishable_from_chance ? 'above chance' : 'not distinguishable from chance'}
                              </span>
                            </div>
                          ))}
                        </div>
                        {evalMetrics.generalisation_note && (
                          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-2-hi)', marginTop: '0.8rem', lineHeight: 1.65 }}>
                            {evalMetrics.generalisation_note}
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}
              </div>

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
                          <td style={{ color: (h.peak_prob || 0) > 0.7 ? 'var(--c-red)' : 'var(--c-orange)' }}>
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
                  <div style={{ padding: '2.5rem 1rem', textAnchor: 'middle', textAlign: 'center', background: 'var(--bg-panel-2)', border: '1px stroke var(--line-05)', borderRadius: '6px' }}>
                    <Activity size={36} style={{ color: 'var(--c-orange-2)', marginBottom: '0.8rem', opacity: 0.8 }} />
                    <h3 style={{ color: 'var(--text-1)', fontSize: '1rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                      No active network capture loaded
                    </h3>
                    <p style={{ color: 'var(--text-3)', fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>
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
                    <UploadCloud size={44} style={{ color: 'var(--c-orange)', marginBottom: '1rem' }} />
                    <h3 style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-1)', marginBottom: '0.5rem', textAlign: 'center' }}>
                      Upload PCAP, PCAPNG, or Flow CSV File
                    </h3>
                    <p style={{ color: 'var(--text-3)', fontSize: '0.85rem', textAlign: 'center', maxWidth: '500px' }}>
                      Drag &amp; drop network captures or click to select file. Supported: .pcap, .pcapng, .csv
                    </p>
                    <p style={{ color: 'var(--text-3)', fontSize: '0.78rem', textAlign: 'center', maxWidth: '520px', marginTop: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                      Needs at least 2 minutes of traffic from the same source IP (12 consecutive
                      10s windows). CSVs must use the CICFlowMeter schema.
                    </p>
                  </div>
                  <input type="file" onChange={handleFileUpload} style={{ display: 'none' }} accept=".pcap,.pcapng,.csv" />
                </label>

                {uploadStatus && (
                  <div className={`upload-status-box ${uploadStatus.state}`} style={{ marginTop: '1.2rem', padding: '1rem', background: 'var(--bg-input)', borderRadius: '6px' }}>
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
                            <div style={{ fontSize: '0.65rem', color: 'var(--c-amber-2)', marginTop: '0.3rem', fontFamily: 'var(--font-mono)' }}>
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
                  <span>FEATURE IMPORTANCE · GRADIENT × INPUT</span>
                  <span>TARGET: {selectedHostIp || 'SELECT HOST'}</span>
                </div>

                {attributionData && attributionData.feature_attributions && (() => {
                  const attrs = attributionData.feature_attributions;
                  // `share` (fraction of total attribution) comes from the API. Older responses
                  // only carry the raw signed `contribution`, so fall back to its share of the
                  // displayed features rather than printing a raw gradient value as a percentage.
                  const fallbackTotal = attrs.reduce((t, a) => t + Math.abs(a.contribution), 0);
                  const shareOf = (a) => (typeof a.share === 'number'
                    ? a.share
                    : (fallbackTotal > 0 ? Math.abs(a.contribution) / fallbackTotal : 0));
                  const dirOf = (a) => a.direction || (a.contribution > 0 ? 'raises' : a.contribution < 0 ? 'lowers' : 'neutral');
                  const maxShare = Math.max(...attrs.map(shareOf), 0);
                  const hasSignal = maxShare > 0;
                  return (
                    <div className="attribution-list">
                      {!hasSignal && (
                        <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-2)', marginBottom: '0.8rem' }}>
                          No measurable attribution for this host.
                        </div>
                      )}
                      {hasSignal && (
                        <div className="font-mono" style={{ fontSize: '0.68rem', color: 'var(--text-3)', marginBottom: '0.8rem' }}>
                          Share of the explanation per feature. <span style={{ color: 'var(--c-orange)' }}>Orange</span> pushes the
                          infiltration score up, <span style={{ color: 'var(--c-cyan)' }}>blue</span> pushes it down.
                        </div>
                      )}
                      {attrs.map((attr, idx) => {
                        const share = shareOf(attr);
                        const dir = dirOf(attr);
                        const color = dir === 'lowers' ? 'var(--c-cyan)' : 'var(--c-orange)';
                        return (
                          <div key={idx} className="attr-item">
                            <div className="attr-header">
                              <span>{attr.feature}</span>
                              <span style={{ color }}>
                                {dir === 'lowers' ? '−' : dir === 'raises' ? '+' : ''}{(share * 100).toFixed(1)}%
                              </span>
                            </div>
                            <div className="attr-bar-bg">
                              {/* Width is scaled to the largest share and can never go negative
                                  (a negative CSS width is invalid, and browsers then fill the track). */}
                              <div
                                className="attr-bar-fill"
                                style={{ width: `${maxShare > 0 ? (share / maxShare) * 100 : 0}%`, background: color }}
                              ></div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  );
                })()}

                {/* Provenance flags (has_ip_data, ...) describe where the capture came from, not what
                    the traffic did. The model does read them, so they are shown -- but apart from the
                    behavioural drivers and with an explicit warning, never as attack evidence. */}
                {attributionData?.provenance_attributions?.length > 0
                  && attributionData.provenance_share_total >= 0.01 && (
                  <div
                    data-testid="provenance-callout"
                    style={{ marginTop: '1.2rem', padding: '0.8rem 1rem', border: '1px solid rgba(250,178,25,0.5)', borderLeft: '3px solid #fab219', background: 'rgba(250,178,25,0.07)', borderRadius: '4px' }}
                  >
                    <div className="font-mono" style={{ fontSize: '0.72rem', letterSpacing: '0.04em', color: 'var(--c-amber)', marginBottom: '0.4rem' }}>
                      DATASET ARTEFACT — NOT ATTACK EVIDENCE ({(attributionData.provenance_share_total * 100).toFixed(1)}% OF THIS EXPLANATION)
                    </div>
                    {attributionData.provenance_attributions.filter((a) => a.share >= 0.005).map((a) => (
                      <div key={a.feature} className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-1-dim)', marginBottom: '0.3rem' }}>
                        {a.feature}: {a.direction === 'lowers' ? '−' : '+'}{(a.share * 100).toFixed(1)}%
                      </div>
                    ))}
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-2)', lineHeight: 1.5, marginTop: '0.3rem' }}>
                      {attributionData.provenance_attributions[0].note}
                    </div>
                  </div>
                )}
              </div>

              {narrativeData && (
                <div className="gpf-panel">
                  <div className="panel-header-mono">
                    <span>AUTOMATED ATTACK NARRATIVE & CVE THREAT INTEL</span>
                    <span>NVD CVE & CAPEC SNAPSHOT</span>
                  </div>
                  <p style={{ color: 'var(--text-2)', lineHeight: '1.6', marginBottom: '1.2rem' }}>
                    {narrativeData.narrative}
                  </p>

                  {narrativeData.cve_details && (
                    <div className="cve-snapshot-list" style={{ marginBottom: '1.2rem' }}>
                      <strong style={{ display: 'block', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-3)', marginBottom: '0.6rem' }}>
                        HISTORICAL EXPLOITED CVES (NVD SNAPSHOT):
                      </strong>
                      {narrativeData.cve_details.map((cve, i) => (
                        <div key={i} style={{ background: 'var(--bg-input)', border: '1px solid var(--line-08)', padding: '0.8rem', borderRadius: '4px', marginBottom: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                          <span style={{ color: 'var(--c-orange)', fontWeight: 600 }}>{cve.cve_id}</span> - {cve.description}
                        </div>
                      ))}
                    </div>
                  )}

                  <div style={{ background: 'rgba(200, 59, 50, 0.1)', border: '1px solid #c83b32', padding: '1rem', borderRadius: '6px' }}>
                    <strong style={{ color: 'var(--c-red)', display: 'block', marginBottom: '0.4rem', fontFamily: 'var(--font-mono)' }}>
                      RECOMMENDED ACTION: {narrativeData.recommended_action?.title}
                    </strong>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-1)' }}>
                      {narrativeData.recommended_action?.action}
                    </span>

                    {isolationResult ? (
                      <div style={{ marginTop: '0.8rem', padding: '0.6rem 0.8rem', border: '1px solid #33c9ff', borderRadius: '4px', background: 'rgba(51,201,255,0.08)' }}>
                        <strong style={{ color: 'var(--c-cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.72rem', letterSpacing: '0.04em' }}>
                          ISOLATED (SIMULATED)
                        </strong>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-2)', marginTop: '0.3rem' }}>
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
                          border: '1px solid #33c9ff', background: 'transparent', color: 'var(--c-cyan)',
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
                    onDownloadPdf={async () => {
                      try {
                        const { blob, filename } = await reportApi.downloadReportPdf(reportResult.host_ip);
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = filename || `incident-report-${reportResult.host_ip}.pdf`;
                        a.click();
                        URL.revokeObjectURL(url);
                      } catch (err) {
                        console.error('PDF report download failed:', err);
                      }
                    }}
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
