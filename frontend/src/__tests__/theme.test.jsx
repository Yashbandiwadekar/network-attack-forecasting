import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { ThemeProvider, useTheme, readStoredTheme, STORAGE_KEY } from '../theme/ThemeContext';
import ThemeToggle from '../components/ThemeToggle/ThemeToggle';

const html = () => document.documentElement;

beforeEach(() => {
  localStorage.clear();
  html().removeAttribute('data-theme');
});
afterEach(() => vi.restoreAllMocks());

describe('theme', () => {
  it('defaults to dark when nothing is stored', () => {
    render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
    expect(html().getAttribute('data-theme')).toBe('dark');
    expect(screen.getByTestId('theme-toggle')).toHaveAccessibleName('Switch to light mode');
  });

  it('toggles to light, updates <html>, and persists the choice', () => {
    render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
    fireEvent.click(screen.getByTestId('theme-toggle'));
    expect(html().getAttribute('data-theme')).toBe('light');
    expect(localStorage.getItem(STORAGE_KEY)).toBe('light');
    expect(screen.getByTestId('theme-toggle')).toHaveAccessibleName('Switch to dark mode');
    fireEvent.click(screen.getByTestId('theme-toggle'));
    expect(html().getAttribute('data-theme')).toBe('dark');
    expect(localStorage.getItem(STORAGE_KEY)).toBe('dark');
  });

  it('restores a saved light choice on load', () => {
    localStorage.setItem(STORAGE_KEY, 'light');
    render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
    expect(html().getAttribute('data-theme')).toBe('light');
  });

  it('ignores a corrupted stored value instead of applying it', () => {
    localStorage.setItem(STORAGE_KEY, 'sepia; drop table');
    expect(readStoredTheme()).toBe('dark');
    render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
    expect(html().getAttribute('data-theme')).toBe('dark');
  });

  it('still works when localStorage throws (private window / blocked site data)', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked'); });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked'); });
    render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
    expect(html().getAttribute('data-theme')).toBe('dark');
    fireEvent.click(screen.getByTestId('theme-toggle')); // must not throw
    expect(html().getAttribute('data-theme')).toBe('light');
  });

  it('setTheme rejects values that are not a known theme', () => {
    let api;
    const Probe = () => { api = useTheme(); return null; };
    render(<ThemeProvider><Probe /></ThemeProvider>);
    api.setTheme('neon');
    expect(html().getAttribute('data-theme')).toBe('dark');
  });

  it('the toggle renders harmlessly without a provider (component tests, storybook)', () => {
    render(<ThemeToggle />);
    expect(screen.getByTestId('theme-toggle')).toBeInTheDocument();
  });
});
