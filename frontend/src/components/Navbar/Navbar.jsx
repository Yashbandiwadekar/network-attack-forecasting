import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { ShieldAlert } from 'lucide-react';
import './Navbar.css';

const Navbar = () => {
  const [scrolled, setScrolled] = useState(false);
  const [activeSection, setActiveSection] = useState('hero');
  const navigate = useNavigate();
  const location = useLocation();
  const isAuthenticated = localStorage.getItem('auth') === 'true';

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);

      const sections = ['platform', 'how-it-works', 'datasets', 'research'];
      for (const sec of sections) {
        const el = document.getElementById(sec);
        if (el) {
          const rect = el.getBoundingClientRect();
          if (rect.top <= 140 && rect.bottom >= 140) {
            setActiveSection(sec);
            break;
          }
        }
      }
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleNavClick = (e, sectionId) => {
    e.preventDefault();
    if (location.pathname !== '/') {
      navigate('/#' + sectionId);
      setTimeout(() => {
        const el = document.getElementById(sectionId);
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    } else {
      const el = document.getElementById(sectionId);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        setActiveSection(sectionId);
      }
    }
  };

  return (
    <nav className={`navbar ${scrolled ? 'scrolled' : ''}`}>
      <div className="nav-container">
        <Link to="/" className="nav-brand">
          <ShieldAlert className="brand-icon" size={24} />
          <span className="brand-text">PHOENIX IDPS</span>
        </Link>
        
        <div className="nav-links desktop-only">
          <a
            href="#platform"
            className={`nav-link ${activeSection === 'platform' ? 'active' : ''}`}
            onClick={(e) => handleNavClick(e, 'platform')}
          >
            Platform
          </a>
          <a
            href="#how-it-works"
            className={`nav-link ${activeSection === 'how-it-works' ? 'active' : ''}`}
            onClick={(e) => handleNavClick(e, 'how-it-works')}
          >
            How It Works
          </a>
          <a
            href="#datasets"
            className={`nav-link ${activeSection === 'datasets' ? 'active' : ''}`}
            onClick={(e) => handleNavClick(e, 'datasets')}
          >
            Datasets
          </a>
          <a
            href="#research"
            className={`nav-link ${activeSection === 'research' ? 'active' : ''}`}
            onClick={(e) => handleNavClick(e, 'research')}
          >
            Research & Deployment
          </a>
        </div>

        <div className="nav-actions">
          {!isAuthenticated ? (
            <button className="btn-ghost" onClick={() => navigate('/login')}>
              Login
            </button>
          ) : (
            <button className="btn-ghost" onClick={() => {
              localStorage.removeItem('auth');
              localStorage.removeItem('token');
              localStorage.removeItem('access_token');
              navigate('/');
            }}>
              Logout
            </button>
          )}
          <button className="btn-primary" onClick={() => navigate('/login')}>
            Open Dashboard
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
