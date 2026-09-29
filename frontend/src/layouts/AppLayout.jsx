import React from 'react';
import { Outlet } from 'react-router-dom';

const AppLayout = () => {
  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#000000', color: '#f5f5f5' }}>
      <Outlet />
    </div>
  );
};

export default AppLayout;
