import React from 'react';
import { Outlet } from 'react-router-dom';

const AppLayout = () => {
  return (
    <div style={{ minHeight: '100vh', backgroundColor: 'var(--bg-void)', color: 'var(--text-1)' }}>
      <Outlet />
    </div>
  );
};

export default AppLayout;
