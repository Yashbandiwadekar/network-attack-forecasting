import React from 'react';
import { Moon, Sun } from 'lucide-react';
import { useTheme } from '../../theme/ThemeContext';
import './ThemeToggle.css';

/* Icon button that flips light/dark. The icon shows the mode you would switch TO. */
const ThemeToggle = ({ className = '' }) => {
  const { theme, toggleTheme } = useTheme();
  const next = theme === 'dark' ? 'light' : 'dark';
  return (
    <button
      type="button"
      className={`theme-toggle ${className}`.trim()}
      onClick={toggleTheme}
      aria-label={`Switch to ${next} mode`}
      title={`Switch to ${next} mode`}
      data-testid="theme-toggle"
    >
      {theme === 'dark' ? <Sun size={16} aria-hidden="true" /> : <Moon size={16} aria-hidden="true" />}
    </button>
  );
};

export default ThemeToggle;
