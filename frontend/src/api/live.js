import { apiFetch } from './client';

// Kept out of api/index.js so the existing component tests that mock '../api' are unaffected.
export const liveApi = {
  getStatus: () => apiFetch('/api/v1/live/status'),
};
