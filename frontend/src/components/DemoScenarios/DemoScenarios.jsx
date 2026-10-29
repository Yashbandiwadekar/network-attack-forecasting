import React, { useEffect, useState } from 'react';
import { Loader2, PlayCircle } from 'lucide-react';
import { demoApi } from '../../api';
import './DemoScenarios.css';

// Cards for the server's demo scenarios (GET /api/v1/demo/scenarios). Everything shown comes from
// the manifest: the expected-behaviour note and the measured peak are what the served model actually
// produced when the manifest was built, including the scenarios it misses. Loading goes through the
// same ingest path as an upload; the parent owns the success / error status box.

const VERDICT_LABEL = {
  flagged: 'MODEL FLAGS THIS',
  missed: 'MODEL MISSES THIS',
  out_of_view: 'ATTACK NOT IN SCORED WINDOWS',
  alert_on_benign_windows: 'ALERT, BUT NO ATTACK IN SCORED WINDOWS',
  false_alarm: 'FALSE ALARM',
  correct_quiet: 'MODEL STAYS QUIET',
  not_scored: 'NOT SCORED',
};

const DemoScenarios = ({ onLoad, loadingId = null, disabled = false }) => {
  const [scenarios, setScenarios] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    demoApi.listScenarios()
      .then((res) => { if (!cancelled) setScenarios(res?.scenarios || []); })
      .catch((err) => { if (!cancelled) { setScenarios([]); setError(err.message); } });
    return () => { cancelled = true; };
  }, []);

  if (scenarios === null) return null;

  return (
    <div className="demo-scenarios" data-testid="demo-scenarios">
      <div className="demo-scenarios-title">OR LOAD A DEMO SCENARIO</div>
      {scenarios.length === 0 && (
        <p className="demo-empty">
          {error ? `Demo scenarios could not be listed: ${error}` : 'No demo scenarios are installed on this server.'}
        </p>
      )}
      <div className="demo-grid">
        {scenarios.map((s) => {
          const verdict = s.expected_behaviour?.verdict;
          const busy = loadingId === s.id;
          return (
            <div key={s.id} className="demo-card" data-testid="demo-card">
              <div className="demo-card-top">
                <span className="demo-card-title">{s.title}</span>
                {s.split_tag && <span className="demo-tag">{s.split_tag}</span>}
              </div>
              <p className="demo-desc">{s.description}</p>
              <p className="demo-source">
                {s.source?.dataset}{s.source?.day ? ` · ${s.source.day}` : ''}
                {s.size_mb != null ? ` · ${s.size_mb} MB` : ''}
              </p>
              {s.expected_behaviour?.text && (
                <p className={`demo-expect ${verdict || ''}`}>
                  {VERDICT_LABEL[verdict] && <strong>{VERDICT_LABEL[verdict]}. </strong>}
                  {s.expected_behaviour.text}
                </p>
              )}
              <button
                type="button"
                className="demo-load-btn"
                disabled={disabled || !s.available || loadingId !== null}
                onClick={() => onLoad(s.id, s.title)}
              >
                {busy
                  ? <><Loader2 size={14} className="demo-spin" /> Loading...</>
                  : <><PlayCircle size={14} /> {s.available ? 'Load' : 'Not installed'}</>}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default DemoScenarios;
