import React from 'react';
import './AuditLedger.css';

/**
 * Tamper-evident audit ledger + CERT-In compliance panel.
 *
 * Both features are fully implemented in the backend (models/audit_ledger.py,
 * models/compliance.py) and had no UI at all. The ledger is a SHA-256 hash chain: every alert
 * shown to an analyst is appended with the previous record's hash folded in, so a record cannot
 * be altered or removed after the fact without breaking the chain. `verify_integrity()` walks it
 * and reports the first bad index.
 *
 * `report` is a /api/v1/reports/generate payload; `status` is /api/v1/system/status.
 */
const AuditLedger = ({ report = null, status = null, onDownload = null, onDownloadPdf = null }) => {
  const compliance = report?.compliance;
  const intact = status?.ledger_intact;
  const entries = status?.ledger_entries;

  const hoursRemaining = compliance?.hours_remaining;
  const deadline = compliance?.reporting_deadline
    ? new Date(compliance.reporting_deadline).toLocaleString()
    : null;

  return (
    <div className="ledger-panel">
      <div className="ledger-header">
        <span className="ledger-title">TAMPER-EVIDENT AUDIT LEDGER</span>
        {typeof intact === 'boolean' && (
          <span className={`ledger-badge ${intact ? 'ok' : 'broken'}`}>
            {intact ? '✓ CHAIN VERIFIED' : '✗ CHAIN BROKEN'}
          </span>
        )}
      </div>

      <div className="ledger-grid">
        <div className="ledger-stat">
          <span className="ledger-stat-label">RECORDS</span>
          <strong className="ledger-stat-val">{typeof entries === 'number' ? entries : '—'}</strong>
          <span className="ledger-stat-note">append-only, SHA-256 chained</span>
        </div>
        <div className="ledger-stat">
          <span className="ledger-stat-label">INTEGRITY</span>
          <strong className={`ledger-stat-val ${intact ? 'text-ok' : 'text-bad'}`}>
            {intact === true ? 'VERIFIED' : intact === false ? 'BROKEN' : '—'}
          </strong>
          <span className="ledger-stat-note">
            {status?.ledger_first_bad_index != null
              ? `first bad record: #${status.ledger_first_bad_index}`
              : 'every record re-hashed on read'}
          </span>
        </div>
      </div>

      {report && (
        <div className="ledger-chain">
          <div className="chain-row">
            <span className="chain-label">PREV</span>
            <code className="chain-hash prev">{report.prev_hash}</code>
          </div>
          <div className="chain-arrow">↓ sha256(record ‖ prev)</div>
          <div className="chain-row">
            <span className="chain-label">RECORD #{report.ledger_index}</span>
            <code className="chain-hash current">{report.audit_hash}</code>
          </div>
        </div>
      )}

      {compliance && (
        <div className="compliance-block">
          <div className="compliance-header">
            <span className="compliance-title">CERT-In INCIDENT REPORT</span>
            <span className={`compliance-tag ${compliance.is_reportable ? 'reportable' : 'not-reportable'}`}>
              {compliance.is_reportable ? 'REPORTABLE' : 'NOT REPORTABLE'}
            </span>
          </div>

          {compliance.category && <div className="compliance-category">{compliance.category}</div>}

          {compliance.is_reportable && (
            <div className="compliance-deadline">
              <div className="deadline-clock">
                <span className="deadline-label">REPORTING WINDOW</span>
                <strong className={hoursRemaining != null && hoursRemaining < 2 ? 'text-bad' : 'text-amber'}>
                  {hoursRemaining != null ? `${hoursRemaining.toFixed(1)} h remaining` : 'historical capture'}
                </strong>
              </div>
              {deadline && <span className="deadline-abs">deadline {deadline}</span>}
              <span className="deadline-note">
                CERT-In directions require reporting inside 6 hours of detection.
                {hoursRemaining == null &&
                  ' This capture is historical, so no live countdown is shown rather than a misleading one.'}
              </span>
            </div>
          )}

          {onDownloadPdf && (
            <button type="button" className="ledger-download" onClick={onDownloadPdf}>
              Download incident report (PDF)
            </button>
          )}

          {onDownload && (
            <button type="button" className="ledger-download" onClick={onDownload}>
              Download signed ledger record (JSON)
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default AuditLedger;
