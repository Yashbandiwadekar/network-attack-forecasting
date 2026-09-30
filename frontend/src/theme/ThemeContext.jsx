import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

/* Light / dark theme.

   The choice lives on <html data-theme="..."> so plain CSS (styles/variables.css) does the
   restyling; React only tracks the current value for the toggle and for the two things CSS can't
   reach (the WebGL canvas background). Persisted in localStorage under STORAGE_KEY.

   Default is DARK -- that is the product's design, and an explicit user choice (or none) beats
   guessing from the OS. Every localStorage access is wrapped: private windows and blocked site data
   make it throw, and the app must still render. */
export const STORAGE_KEY = 'phoenix-theme';
export const THEMES = ['dark', 'light'];

export function readStoredTheme() {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return THEMES.includes(v) ? v : 'dark';
  } catch {
    return 'dark';
  }
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  // Keep the browser chrome (mobile address bar) in step with the page.
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', theme === 'light' ? '#f3f4f6' : '#0a0a0a');
}

const ThemeContext = createContext({ theme: 'dark', setTheme: () => {}, toggleTheme: () => {} });

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(readStoredTheme);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((next) => {
    if (!THEMES.includes(next)) return;
    setThemeState(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* storage unavailable: the choice still applies for this session */
    }
  }, []);

  const toggleTheme = useCallback(() => setTheme(theme === 'dark' ? 'light' : 'dark'), [theme, setTheme]);

  const value = useMemo(() => ({ theme, setTheme, toggleTheme }), [theme, setTheme, toggleTheme]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export const useTheme = () => useContext(ThemeContext);
