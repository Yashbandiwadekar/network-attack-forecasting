/* Relative by default. When the API serves the built dashboard (the deployed, single-port
   setup) the browser and API share an origin, so a relative URL is correct everywhere -- on
   localhost, on a LAN IP, or behind a reverse proxy -- with no build-time configuration and no
   CORS involved. The previous absolute default hardcoded 127.0.0.1, which meant a phone or
   laptop loading the dashboard over the LAN would call back to *itself* and silently fail.

   Set VITE_API_BASE_URL only for split development, where Vite serves on :5173 and the API on
   :8000 (see .env.development). */
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';

export async function apiFetch(endpoint, options = {}) {
  // Canonical key: 'token' — matches what Login.jsx stores via setItem('token', ...).
  // Using 'access_token' here caused a silent fallback to the hardcoded demo JWT on every
  // authenticated request even after a successful login (BUG-002).
  const token = localStorage.getItem('token') || 'phoenix_demo_jwt_token_2026_secured';
  
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...options.headers,
  };

  // If uploading FormData, delete Content-Type so browser sets boundary automatically
  if (options.body instanceof FormData) {
    delete headers['Content-Type'];
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = 'API request failed';
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      errorDetail = await response.text();
    }
    throw new Error(`HTTP ${response.status}: ${errorDetail}`);
  }

  return response.json();
}

/* Binary download (e.g. a PDF). apiFetch always parses JSON, so files need their own path; the auth
   header and error shape are the same. Returns { blob, filename }. */
export async function apiFetchBlob(endpoint, options = {}) {
  const token = localStorage.getItem('token') || 'phoenix_demo_jwt_token_2026_secured';
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers },
  });
  if (!response.ok) {
    let detail = 'Download failed';
    try {
      const j = await response.json();
      detail = j.detail || JSON.stringify(j);
    } catch {
      detail = await response.text();
    }
    throw new Error(`HTTP ${response.status}: ${detail}`);
  }
  const disposition = response.headers.get('Content-Disposition') || '';
  const match = /filename="?([^";]+)"?/.exec(disposition);
  return { blob: await response.blob(), filename: match ? match[1] : null };
}
