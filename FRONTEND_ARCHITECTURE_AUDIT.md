# PHOENIX IDPS — FRONTEND ARCHITECTURE, DESIGN SYSTEM & INTEGRATION AUDIT

> **Date:** September 29, 2026  
> **Target System:** Phoenix IDPS (Intelligent Intrusion Detection & Threat Forecasting Platform)  
> **Status:** Production-Ready Frontend Build Verified (`npm run build` cleanly compiled in < 1.5s)  
> **Dev Environment:** Vite React Frontend (`http://localhost:5174`) ↔ Python FastAPI Engine (`http://127.0.0.1:8000`)  

---

## 1. Executive Summary & System Overview

Today’s frontend architecture pass transformed Phoenix IDPS into a cohesive, high-performance cybersecurity threat forecasting application. The application strictly enforces the core design philosophy: **The Python FastAPI backend is the authoritative source of truth for all security analytics, infiltration probabilities, attack-stage classifications, SHAP attributions, NVD CVE threat intelligence snapshots, and audit ledger cryptographic hashes.** The frontend is strictly responsible for zero-latency 3D volumetric field rendering, interactive data presentation, route isolation, state handling, and analyst workflows.

```
                    ┌────────────────────────────────────────┐
                    │    DATA SOURCES / PCAP / CSV / BENCH   │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │   FASTAPI INGESTION & FLOW PARSING     │
                    │   (app/server.py -> 5-Tuple Extraction)│
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │    MODEL INFERENCE & K-STEP FORECAST   │
                    │  (ForecastEngine / Analytical Fallback)│
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │   EXPLAINABILITY & INTEL ENRICHMENT    │
                    │ (SHAP Attributions + NVD CVE Snapshot) │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │    REST API LAYER (app/server.py)      │
                    │ http://127.0.0.1:8000/api/v1/...       │
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │    FRONTEND STORE & API CLIENT         │
                    │ (frontend/src/api/index.js & client.js)│
                    └───────────────────┬────────────────────┘
                                        │
                                        ▼
                    ┌────────────────────────────────────────┐
                    │      REACT GPF DASHBOARD PAGE          │
                    │ (http://localhost:5174/dashboard)      │
                    └────────────────────────────────────────┘
```

---

## 2. Design System & Typography Engine

### A. Font Families
- **Primary Display & Body Font:** `Space Grotesk` (Google Fonts). Geometric, sharp, modern engineered sans-serif designed for technical platforms, replacing generic browser defaults (`Inter` / `system-ui`).
- **Monospaced Technical Font:** `JetBrains Mono` / `IBM Plex Mono`. Applied across all telemetry strips, flow tables, timestamps, pipeline tags, hash proofs, and code snippets.

### B. Color Tokens (Strict Phoenix Cyber Palette — 0 Gray Particles, 0 Generic SaaS Blue/Purple)
- **Background Base:** `#000000` (Near-black environment)
- **Panel Containers:** `rgba(15, 15, 15, 0.65)` with `backdrop-filter: blur(16px)`
- **Base Reddish-Orange (Standard Flow):** `#FF4500` / `#FF5500`
- **Bright Orange Accent (Hubs):** `#FF6A00`
- **Deep Crimson Red (Threats / Critical Nodes):** `#D32F2F` / `#C82828`
- **Dark Maroon (Anomalies):** `#7A1A24`
- **Borders & Dividers:** `rgba(255, 255, 255, 0.1)`

---

## 3. Strict Route & Layout Isolation Architecture

To guarantee zero navbar/footer leakage between marketing, authentication, and application screens, the application routes are divided into 3 distinct layout boundaries inside [`src/routes/AppRoutes.jsx`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/network-attack-forecasting/frontend/src/routes/AppRoutes.jsx):

```
                        Routes Hierarchy
                        ────────────────
┌──────────────────────────┐  ┌──────────────────────────┐  ┌──────────────────────────┐
│     LandingLayout        │  │        AuthLayout        │  │        AppLayout         │
├──────────────────────────┤  ├──────────────────────────┤  ├──────────────────────────┤
│ - Landing Fixed Navbar   │  │ - Back to Landing Button │  │ - GPF Dashboard Sidebar  │
│ - Hero 3D Particle Field │  │ - Auth Container Panel   │  │ - System Header Bar      │
│ - Telemetry Strip        │  │ - 3D Background Canvas   │  │ - Status Context Selector│
│ - Section Anchor ID Targets││ - Protected Route Guard  │  │ - Active Operational Tabs│
└────────────┬─────────────┘  └────────────┬─────────────┘  └────────────┬─────────────┘
             │                             │                             │
             ▼                             ▼                             ▼
       Route: `/`                   Route: `/login`              Route: `/dashboard`
```

1. **Landing Layout (`/`)**:
   - Includes fixed sticky navbar with smooth section scrolling (`#platform`, `#how-it-works`, `#datasets`, `#research`).
   - `scroll-margin-top: 80px` prevents fixed navbar overlaying section headers.
2. **Auth Layout (`/login`)**:
   - Contains a glassmorphism `"← Back to Landing Page"` button floating at top-left (`top: 2rem`, `left: 2rem`, `z-index: 20`) that routes directly to `/`.
   - Includes centered authentication panel over 3D WebGL background.
3. **App Layout (`/dashboard`)**:
   - Encapsulated operational GPF Dashboard shell.
   - Protected route requiring valid authentication state in `localStorage`.
   - Zero marketing navbar or landing elements leak into `/dashboard`.

---

## 4. Landing Hero & 3D WebGL Particle System Specification

### A. 3D WebGL Particle System (`ParticleNetwork.jsx` & `particleBehavior.js`)
- **Particle Count:** ~2,200 desktop target (Adaptive scaling: Desktop: 2200, Tablet: 1800, Mobile: 1200).
- **Spatial Distribution:** Open 3D Network Field floating cleanly across thin air (`-57.5` to `+57.5` X, `-32.5` to `+32.5` Y, `-27.5` to `+27.5` Z). Zero dense cores, zero centroid nucleus, zero starburst cluster balls.
- **Node Scaling:** Uniform 0.20 base size rendering as crisp, delicate network points.
- **3D Spatial Line Edges:** Spatial grid index (`cellSize: 10.0`, `MAX_CONNECT_DIST: 9.8`, max 3 edges per node) rendering thin, delicate 3D connection lines (`lineBasicMaterial opacity = 0.4`).
- **Performance:** In-place position and color buffer updates inside pre-allocated `Float32Array` objects (`nodeCurrentPositions`, `linePositions`, `lineColors`). Zero per-frame memory garbage collection.

### B. High-End Command Hero Copy & Typography Hierarchy
- **Eyebrow Tag:** `PHOENIX IDPS · THREAT FORECASTING ENGINE` (uppercase, monospaced amber tag with border glow).
- **Primary Headline:**
  ```
  SEE THE ATTACK.
  FORECAST WHAT COMES NEXT.
  ```
- **Supporting Description:**  
  *"Phoenix IDPS transforms network traffic into an evolving threat state — detecting hostile behavior, classifying attack stages, and forecasting how an intrusion may propagate next."*
- **System Pipeline Micro-Strip:** `PCAP / FLOW / DETECT / CLASSIFY / FORECAST` (Monospaced HUD pipeline component).
- **Primary Action Buttons:** `OPEN DASHBOARD` (routes to `/dashboard` or `/login`) and `EXPLORE PLATFORM` (smooth scrolls to `#how-it-works`).
- **Interactive Controls:** `Pause` / `Resume` and `Reset View` floating bottom controls retained.

---

## 5. Full Page Breakdown & Interactive Component Directory

### 1. Landing Page (`/`)
- **Hero Section (`Hero.jsx`):** 3D WebGL Open Field Network, Command Headline, Pipeline Micro-strip, Action Buttons, and Bottom Canvas Controls (`Pause`, `Reset View`).
- **Telemetry Readout Strip (`TelemetryStrip.jsx`):** Live stream ticker displaying real-time metrics (Active Monitored Hosts, Flow Count, Peak Infiltration Probability, Reconstruct Error, Horizon K = 5).
- **Workflow Pipeline (`WorkflowPipeline.jsx`):** 5-stage architectural pipeline step cards (PCAP Ingestion → Flow Feature Extraction → Neural Model Evaluation → Attack Stage Classification → K-Step Horizon Forecast).
- **Forecast Timeline (`ForecastTimeline.jsx`):** Interactive comparison chart of observed past flow evidence against predicted future attack stage transitions.
- **Threat Score Gauge (`ThreatScoreGauge.jsx`):** Threat score risk gauge with observable feature evidence chain.
- **Dataset Benchmarks (`DatasetTable.jsx`):** Cross-dataset evaluation metrics across `CIC-IDS-2018`, `UNSW-NB15`, and `CTU-13`.
- **Deployment Architecture Grid:** Enterprise SOC, MSSP Multi-tenant, and Air-Gapped Critical Infrastructure panels.
- **Technical Footer:** System brand info, quick anchor links (`#platform`, `#how-it-works`, `#datasets`), copyright notice.

### 2. Login / Authentication Page (`/login`)
- **Top-Left Back Button:** `<button className="login-back-btn">` with `<ArrowLeft />` icon routing back to `/`.
- **Auth Card Container:** Centered authentication panel with Email/Password fields, "Sign In" button, "Use Demo Account" quick trigger (`demo@phoenixidps.local`), and "Forgot Password?" link.
- **3D Background Canvas:** WebGL particle network background.

### 3. GPF Dashboard (`/dashboard`)
- **Sidebar (`Sidebar.jsx`):** Brand logo, navigation tabs (`overview`, `analysis`, `forecast`, `evidence`, `reports`), and system status pill.
- **Header Bar (`Header.jsx`):** Operational title, active target host IP badge (`Target Host: 10.0.4.5`), API status indicator, and Logout button.
- **Top Status & Dataset Selector Bar:**
  - Active Dataset Context Switcher (`CIC-IDS-2018`, `UNSW-NB15`, `CTU-13`).
  - Live 5-second background polling ticker with "LAST UPDATED" timestamp.
  - Manual forced refresh button (`<RefreshCw />`).
- **Active Operational Tabs:**
  - **Overview Tab:** Monitored Endpoints & Risk Matrix table, Target Risk Gauge, Forecast Horizon Timeline.
  - **Analysis Tab:** PCAP/PCAPNG/CSV Drag & Drop Workspace with centered `<UploadCloud />` dropzone and ingestion status feedback box.
  - **K-Step Forecast Tab:** Horizon K=1..5 Infiltration Probability step cards, model checkpoint specs, state transition probability matrix.
  - **Explainability Tab:** Feature importance SHAP attributions, automated attack narrative text, historical NVD CVE threat intel snapshot details, recommended response action box.
  - **Audit & Reports Tab:** Cryptographic Audit Ledger verification hash proof generator, ISO 27001 / NIST SP 800-53 compliance certificate, downloadable JSON/PDF report generator.

---

## 6. Backend ↔ Frontend REST API Integration Mapping

All frontend API calls map directly to routes implemented in [`app/server.py`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/network-attack-forecasting/app/server.py):

| Backend Endpoint | Method | Frontend Client Function (`src/api`) | Dashboard Usage / UI Component |
| :--- | :---: | :---: | :--- |
| `/api/v1/auth/login` | `POST` | `authApi.login` | Login page & demo account authentication |
| `/api/v1/system/status` | `GET` | `systemApi.getStatus` | Dashboard header, status bar, and 5s polling loop |
| `/api/v1/datasets` | `GET` | `datasetApi.getDatasets` | Top Status Bar dataset context selector |
| `/api/v1/datasets/select` | `POST` | `datasetApi.selectDataset` | Dataset dropdown switcher (switches benchmark context) |
| `/api/v1/forecast/hosts` | `GET` | `forecastApi.getHosts` | Overview Monitored Endpoints & Risk Matrix table |
| `/api/v1/forecast/predict` | `POST` | `forecastApi.predict` | Forecast Tab K=1..5 Infiltration Probability cards |
| `/api/v1/explainability/attribution` | `POST` | `explainApi.getAttribution` | Explainability Tab SHAP feature attribution bars |
| `/api/v1/attacks/narrative` | `GET` | `explainApi.getNarrative` | Automated Attack Narrative & NVD CVE snapshot card |
| `/api/v1/mitre/mapping` | `GET` | `explainApi.getMitre` | MITRE ATT&CK technique mapping matrix |
| `/api/v1/analysis/upload` | `POST` | `analysisApi.uploadFile` | Analysis Tab PCAP/CSV dropzone ingestion pipeline |
| `/api/v1/reports/generate` | `POST` | `reportApi.generateReport` | Reports Tab Cryptographic audit hash proof generator |
| `/api/v1/reports/download/{filename}` | `GET` | `reportApi.downloadReport` | Reports Tab certified report download trigger |

---

## 7. Major Bugs Identified & Resolved Today

1. **Half-Black / Blank Screen Layout Bug**:
   - **Cause:** Legacy `index.css` contained `#root { width: 1126px; margin: 0 auto; }` restricting container width.
   - **Fix:** Removed `#root` max-width restrictions and enforced `width: 100%`, `min-height: 100vh`, `margin: 0`, `padding: 0` in `globals.css` and `index.css`.
2. **Dense Exploding Starburst Core in WebGL Canvas**:
   - **Cause:** Clusters centered at origin `(0, 0, 0)` with heavy `centerBias` math and large node scale boosting.
   - **Fix:** Distributed particles across a continuous 3D open volume (`-57.5` to `+57.5` X), eliminated origin clustering, and standardized node scaling.
3. **Dropzone Layout Distortion**:
   - **Cause:** `.upload-dropzone` label lacked flex centering, causing `<UploadCloud>` icon to collapse to top-left.
   - **Fix:** Added `display: flex; flex-direction: column; align-items: center; justify-content: center; width: 100%;` in `Dashboard.css` and `Dashboard.jsx`.
4. **Yellow/Gray Particles Removal**:
   - **Fix:** Replaced yellow/gray particle colors with a strict Reddish & Orangish palette (`#FF4500` Reddish-Orange, `#FF6A00` Bright Orange, `#D32F2F` Crimson Red, `#7A1A24` Deep Maroon).

---

## 8. Architectural Review & Page-by-Page Checklist for Lead Architect

Please review the following checklist to specify any additional content or features for each page:

```
[ ] 1. LANDING HERO PAGE (/)
    [x] High-end command headline & pipeline micro-strip
    [x] Open 3D WebGL particle field (2,200 particles, Reddish/Orangish palette)
    [x] Navbar smooth scrolling to sections (#platform, #how-it-works, #datasets, #research)
    [ ] Architect Review: Are any additional marketing/research sections needed?

[ ] 2. LOGIN PAGE (/login)
    [x] Glassmorphism "Back to Landing Page" button
    [x] Quick Demo Account trigger & form handling
    [ ] Architect Review: Should SSO / SAML 2.0 / OAuth2 login options be added?

[ ] 3. GPF DASHBOARD PAGE (/dashboard)
    [x] Active Dataset Context Selector (CIC-IDS-2018, UNSW-NB15, CTU-13)
    [x] 5-second live polling loop with "Last Updated" timestamp
    [x] Endpoints Risk Matrix Table & Target Host Inspection
    [x] PCAP / PCAPNG / Flow CSV Drag & Drop Ingestion dropzone
    [x] K-Step Horizon Prediction cards (K=1..5)
    [x] SHAP Feature Attribution bars & automated attack narrative text
    [x] NVD CVE Threat Intel Snapshot & recommended response actions
    [x] Cryptographic Audit Ledger Hash proof & ISO 27001 report generator
    [ ] Architect Review: Are any additional SOC widgets or chart visualizations required?
```
