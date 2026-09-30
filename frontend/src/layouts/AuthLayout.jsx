import React from 'react';
import { Outlet } from 'react-router-dom';

const AuthLayout = () => {
  return (
    <div style={{ width: '100%', minHeight: '100vh', backgroundColor: 'var(--bg-void)', position: 'relative', overflow: 'hidden' }}>
      <Outlet />
    </div>
  );
};

export default AuthLayout;
