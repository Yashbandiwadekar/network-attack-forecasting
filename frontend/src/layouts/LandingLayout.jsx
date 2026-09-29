import React from 'react';
import { Outlet } from 'react-router-dom';
import Navbar from '../components/Navbar/Navbar';

const LandingLayout = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', backgroundColor: '#000000' }}>
      <Navbar />
      <main style={{ flex: 1, position: 'relative' }}>
        <Outlet />
      </main>
    </div>
  );
};

export default LandingLayout;
