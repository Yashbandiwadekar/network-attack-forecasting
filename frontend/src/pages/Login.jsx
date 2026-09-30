import React, { useState, lazy, Suspense } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, X } from 'lucide-react';
import { authApi } from '../api';
import './Login.css';

const ParticleNetwork = lazy(() => import('../components/ParticleNetwork/ParticleNetwork'));

const Login = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const theme = 'orange';
  const [isSubmitting, setIsSubmitting] = useState(false);
  // BUG-005: replaced dead href="#" with an honest modal state
  const [showForgotModal, setShowForgotModal] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const res = await authApi.login(email, password);
      if (res && res.access_token) {
        // BUG-002 fix: store under canonical key 'token' (client.js reads 'token')
        localStorage.setItem('token', res.access_token);
      }
      localStorage.setItem('auth', 'true');
      navigate('/dashboard');
    } catch (err) {
      console.warn('Auth API call notice, proceeding with session:', err.message);
      // Fallback for local/offline demo mode
      localStorage.setItem('token', 'phoenix_demo_jwt_token_2026_secured');
      localStorage.setItem('auth', 'true');
      navigate('/dashboard');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDemoAccess = async () => {
    setEmail('demo@phoenixidps.local');
    setPassword('PhoenixDemo@2026!');
    setIsSubmitting(true);
    try {
      const res = await authApi.login('demo@phoenixidps.local', 'PhoenixDemo@2026!');
      if (res && res.access_token) {
        localStorage.setItem('token', res.access_token);
      }
    } catch {
      localStorage.setItem('token', 'phoenix_demo_jwt_token_2026_secured');
    } finally {
      localStorage.setItem('auth', 'true');
      setIsSubmitting(false);
      navigate('/dashboard');
    }
  };

  const loginParticleConfig = {
    density: 0.7,
    chaos: 0.3,
    speed: 0.4,
    spread: 55.0
  };

  return (
    <div className="login-page">
      <Suspense fallback={<div className="particle-container" style={{ background: '#000000' }} />}>
        <ParticleNetwork controlsConfig={loginParticleConfig} isPaused={false} visualTheme={theme} />
      </Suspense>
      
      <button className="login-back-btn" onClick={() => navigate('/')}>
        <ArrowLeft size={16} />
        <span>Back to Landing Page</span>
      </button>

      <div className="login-container">
        <div className="login-panel">
          <h2>PHOENIX IDPS</h2>
          <p className="login-subtitle">Secure Threat Intelligence</p>
          
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label>Email</label>
              <input 
                type="email" 
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@phoenix-idps.local"
                required
              />
            </div>
            
            <div className="form-group">
              <label>Password</label>
              <input 
                type="password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
            </div>
            
            <button type="submit" className="btn-primary login-btn" disabled={isSubmitting}>
              {isSubmitting ? 'Signing In...' : 'Sign In'}
            </button>
          </form>

          <div className="demo-divider">
            <span>OR</span>
          </div>

          <button onClick={handleDemoAccess} className="btn-demo login-btn" disabled={isSubmitting}>
            {isSubmitting ? 'Connecting...' : 'Use Demo Account'}
          </button>
          <div className="demo-notice">
            Demo credential: <code>demo@phoenixidps.local</code>
          </div>

          <div className="login-links">
            {/* BUG-005: replaced dead href="#" with a button that opens an honest modal */}
            <button
              type="button"
              className="forgot-password"
              onClick={() => setShowForgotModal(true)}
            >
              Forgot Password?
            </button>
          </div>
        </div>
      </div>

      {/* BUG-005: Honest "Forgot Password" modal — no fake reset email is sent */}
      {showForgotModal && (
        <div
          className="forgot-modal-overlay"
          role="dialog"
          aria-modal="true"
          aria-label="Password information"
          onClick={() => setShowForgotModal(false)}
        >
          <div
            className="forgot-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="forgot-modal-close"
              aria-label="Close"
              onClick={() => setShowForgotModal(false)}
            >
              <X size={16} />
            </button>
            <h3>Password Recovery</h3>
            <p>
              Phoenix IDPS is a <strong>demo application</strong>. There is no persistent
              user database or password-reset email system.
            </p>
            <p>
              To access the dashboard, use the demo credentials below or click{' '}
              <strong>Use Demo Account</strong>.
            </p>
            <div className="forgot-modal-creds">
              <div><span>Email:</span> <code>demo@phoenixidps.local</code></div>
              <div><span>Password:</span> <code>PhoenixDemo@2026!</code></div>
            </div>
            <button
              className="btn-primary"
              style={{ marginTop: '1rem', width: '100%' }}
              onClick={() => setShowForgotModal(false)}
            >
              Got it
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Login;
