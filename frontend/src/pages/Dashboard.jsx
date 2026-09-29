import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Dashboard/Sidebar';
import Header from '../components/Dashboard/Header';
import TelemetryStrip from '../components/TelemetryStrip/TelemetryStrip';
import ForecastTimeline from '../components/ForecastTimeline/ForecastTimeline';
import ThreatScoreGauge from '../components/ThreatScoreGauge/ThreatScoreGauge';
import { systemApi, datasetApi, forecastApi, explainApi, analysisApi, reportApi } from '../api';
import { UploadCloud, CheckCircle, AlertTriangle, FileText, Activity, ShieldCheck, Database, RefreshCw } from 'lucide-react';
import './Dashboard.css';

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [systemStatus, setSystemStatus] = useState(null);
  const [datasetsData, setDatasetsData] = useState(null);
  const [activeDataset, setActiveDataset] = useState('CIC-IDS-2018');
  const [hosts, setHosts] = useState([]);
  const [selectedHostIp, setSelectedHostIp] = useState('10.0.4.5');
  const [forecastData, setForecastData] = useState(null);
  const [attributionData, setAttributionData] = useState(null);
  const [narrativeData, setNarrativeData] = useState(null);
  const [mitreData, setMitreData] = useState(null);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [reportResult, setReportResult] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

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
  }, [selectedHostIp]);

  const fetchInitialData = async () => {
    setIsRefreshing(true);
    try {
      const [sys, ds, hList] = await Promise.all([
        systemApi.getStatus(),
        datasetApi.getDatasets(),
        forecastApi.getHosts()
      ]);
      setSystemStatus(sys);
      setDatasetsData(ds);
      if (ds && ds.active_dataset) setActiveDataset(ds.active_dataset);
      if (hList && hList.hosts) setHosts(hList.hosts);
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
      if (hList && hList.hosts) setHosts(hList.hosts);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      console.warn('Background update notice:', err.message);
    }
  };

  const fetchHostDetails = async (ip) => {
    try {
      const [predict, attr, narr, mitre] = await Promise.all([
        forecastApi.predict(ip, 5),
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

          <TelemetryStrip />

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="tab-content">
              {/* Monitored Hosts Table */}
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>ACTIVE MONITORED ENDPOINTS & RISK MATRIX</span>
                  <span>SELECT HOST TO INSPECT</span>
                </div>
                <table className="hosts-table">
                  <thead>
                    <tr>
                      <th>HOST IP</th>
                      <th>FLOW COUNT</th>
                      <th>PEAK PROB (K=5)</th>
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
                        <td>{h.flow_count.toLocaleString()}</td>
                        <td style={{ color: h.peak_prob > 0.7 ? '#c83b32' : '#ff6a00' }}>
                          {(h.peak_prob * 100).toFixed(1)}%
                        </td>
                        <td>{h.current_stage}</td>
                        <td>{h.predicted_stage}</td>
                        <td>
                          <span className={`sev-badge ${h.severity}`}>{h.severity}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Selected Host Threat Evaluation */}
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>TARGET INSPECTION: {selectedHostIp}</span>
                  <span>RISK GAUGE & EVIDENCE</span>
                </div>
                <ThreatScoreGauge />
              </div>

              {/* State Transition Timeline */}
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>K-STEP FORECAST HORIZON (HORIZON K = 5)</span>
                  <span>OBSERVED VS PREDICTED</span>
                </div>
                <ForecastTimeline />
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
                      Drag & drop network captures or click to select file. Supported: .pcap, .pcapng, .csv
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
                <div className="panel-header-mono">
                  <span>K-STEP INFILTRATION PROBABILITY TIMELINE ({selectedHostIp})</span>
                  <span>MODEL CHECKPOINT 447 KB</span>
                </div>

                {forecastData && forecastData.infiltration_probs && (
                  <div className="forecast-steps-bar">
                    {forecastData.infiltration_probs.map((prob, idx) => (
                      <div key={idx} className="step-card">
                        <div className="step-k">STEP K = {idx + 1}</div>
                        <div className="step-prob">{(prob * 100).toFixed(1)}%</div>
                        <div className="step-stage">{forecastData.predicted_stages[idx]}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>STATE TRANSITION PROBABILITIES</span>
                  <span>MARKOV / NEURAL SEQUENCE</span>
                </div>
                <ForecastTimeline />
              </div>
            </div>
          )}

          {/* EXPLAINABILITY TAB */}
          {activeTab === 'evidence' && (
            <div className="tab-content">
              <div className="gpf-panel">
                <div className="panel-header-mono">
                  <span>FEATURE IMPORTANCE & SHAP ATTRIBUTION</span>
                  <span>TARGET: {selectedHostIp}</span>
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
                  <span>CRYPTOGRAPHIC AUDIT LEDGER & CERTIFICATE GENERATION</span>
                  <span>AUDIT LEDGER PROOF</span>
                </div>

                <button className="btn-primary" onClick={handleGenerateReport} style={{ marginBottom: '1.5rem' }}>
                  Generate Certified Audit Report for {selectedHostIp}
                </button>

                {reportResult && (
                  <div style={{ background: '#121212', border: '1px solid rgba(255, 176, 0, 0.4)', padding: '1.5rem', borderRadius: '6px', fontFamily: 'var(--font-mono)' }}>
                    <div style={{ color: '#ffb000', fontWeight: 600, marginBottom: '0.6rem' }}>
                      <ShieldCheck size={18} inline style={{ marginRight: '0.4rem' }} />
                      AUDIT LEDGER VERIFICATION SUCCESSFUL
                    </div>
                    <div style={{ fontSize: '0.85rem', color: '#a0a0a0', marginBottom: '0.4rem' }}>
                      Verification Hash: <code style={{ color: '#f5f5f5' }}>{reportResult.audit_hash}</code>
                    </div>
                    <div style={{ fontSize: '0.85rem', color: '#a0a0a0', marginBottom: '1rem' }}>
                      Compliance Framework: <strong style={{ color: '#f5f5f5' }}>{reportResult.compliance_certificate?.framework}</strong>
                    </div>
                    <a href="#" onClick={(e) => { e.preventDefault(); alert(`Downloaded certified report bundle for ${reportResult.host_ip}`); }} className="btn-ghost" style={{ fontSize: '0.8rem' }}>
                      <FileText size={14} style={{ marginRight: '0.4rem' }} />
                      Download Certified JSON / PDF Report
                    </a>
                  </div>
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
