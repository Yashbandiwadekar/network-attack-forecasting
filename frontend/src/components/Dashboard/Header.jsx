import React from 'react';
import { ShieldCheck, LogOut, Radio } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const Header = ({ systemStatus, selectedHost }) => {
  const navigate = useNavigate();
  
  const handleLogout = () => {
    localStorage.removeItem('auth');
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  return (
    <header className="gpf-header">
      <div className="header-left">
        <span className="header-title font-mono">PHOENIX IDPS — THREAT FORECASTING CONSOLE</span>
        {selectedHost && (
          <span className="selected-host-tag font-mono">
            TARGET: <strong className="text-orange">{selectedHost}</strong>
          </span>
        )}
      </div>

      <div className="header-right">
        <div className="status-indicator">
          <Radio size={14} className="pulse-green" />
          <span className="status-text font-mono">
            Backend: <strong className="text-white">{systemStatus?.api_connected ? 'CONNECTED' : 'OFFLINE'}</strong>
          </span>
        </div>

        <div className="status-indicator">
          <ShieldCheck size={14} className="text-orange" />
          <span className="status-text font-mono">
            Model: <strong className="text-white">{systemStatus?.model_loaded ? 'CHECKPOINT LOADED' : 'READY (447 KB)'}</strong>
          </span>
        </div>

        <button className="logout-btn font-mono" onClick={handleLogout} title="Logout Session">
          <LogOut size={16} />
          <span>EXIT</span>
        </button>
      </div>
    </header>
  );
};

export default Header;
