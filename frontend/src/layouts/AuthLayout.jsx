import React from 'react';
import { Outlet } from 'react-router-dom';

const AuthLayout = () => {
  return (
    <div style={{ width: '100%', minHeight: '100vh', backgroundColor: '#000000', position: 'relative', overflow: 'hidden' }}>
      <Outlet />
    </div>
  );
};

export default AuthLayout;
