import React, { useState, lazy, Suspense } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import './Login.css';

const ParticleNetwork = lazy(() => import('../components/ParticleNetwork/ParticleNetwork'));

const Login = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [theme, setTheme] = useState('orange');

  const handleLogin = (e) => {
    e.preventDefault();
    localStorage.setItem('auth', 'true');
    navigate('/dashboard');
  };

  const handleDemoAccess = () => {
    setEmail('demo@phoenixidps.local');
    setPassword('PhoenixDemo@2026!');
    localStorage.setItem('auth', 'true');
    setTimeout(() => {
      navigate('/dashboard');
    }, 400);
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
            
            <button type="submit" className="btn-primary login-btn">Sign In</button>
          </form>

          <div className="demo-divider">
            <span>OR</span>
          </div>

          <button onClick={handleDemoAccess} className="btn-demo login-btn">
            Use Demo Account
          </button>
          <div className="demo-notice">
            Demo credential: <code>demo@phoenixidps.local</code>
          </div>

          <div className="login-links">
            <a href="#" className="forgot-password">Forgot Password?</a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
