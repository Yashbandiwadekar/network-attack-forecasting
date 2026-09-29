import React from 'react';
import { ShieldAlert, Activity, FileText, Cpu, LayoutDashboard, Terminal, CheckCircle2 } from 'lucide-react';
import '../../pages/Dashboard.css';

const Sidebar = ({ activeTab, onTabChange }) => {
  const navItems = [
    { id: 'overview', label: 'OVERVIEW', icon: LayoutDashboard },
    { id: 'analysis', label: 'INGESTION & FLOWS', icon: Terminal },
    { id: 'forecast', label: 'K-STEP FORECAST', icon: Activity },
    { id: 'evidence', label: 'EXPLAINABILITY & ATTACK', icon: Cpu },
    { id: 'reports', label: 'AUDIT & REPORTS', icon: FileText },
  ];

  return (
    <aside className="gpf-sidebar">
      <div className="sidebar-brand">
        <ShieldAlert className="brand-icon" size={22} />
        <div className="brand-text-wrap">
          <span className="brand-main">PHOENIX IDPS</span>
          <span className="brand-sub font-mono">CONSOLE v1.1</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => onTabChange(item.id)}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="footer-status-pill">
          <CheckCircle2 size={14} className="text-good" />
          <span>OFFLINE ENGINE LOCAL</span>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
