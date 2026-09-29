import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, beforeEach } from 'vitest';
import AppRoutes from '../routes/AppRoutes';

describe('AppRoutes Route Isolation & Navigation', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('renders landing page on root route /', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <AppRoutes />
      </MemoryRouter>
    );

    expect(screen.getByText(/SEE THE ATTACK/i)).toBeInTheDocument();
    expect(screen.getByRole('navigation')).toBeInTheDocument();
  });

  it('redirects to /login when accessing protected /dashboard unauthenticated', () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <AppRoutes />
      </MemoryRouter>
    );

    expect(screen.getByText(/Secure Threat Intelligence/i)).toBeInTheDocument();
  });

  it('allows access to /dashboard when authenticated', () => {
    localStorage.setItem('auth', 'true');
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <AppRoutes />
      </MemoryRouter>
    );

    expect(screen.getByText(/CONSOLE v1.1/i)).toBeInTheDocument();
    // Verify Landing Navbar is NOT rendered inside Dashboard
    expect(screen.queryByText(/HOW IT WORKS/i)).not.toBeInTheDocument();
  });
});
