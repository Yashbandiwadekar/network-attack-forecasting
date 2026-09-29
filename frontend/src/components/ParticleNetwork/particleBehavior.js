// Phoenix IDPS 3D Cybersecurity Network Topology Engine
// Open 3D Network Field - Reddish & Orangish Color Palette (0 Yellow, 0 Gray)

let controls = {};

export const setControls = (newControls) => {
  controls = { ...controls, ...newControls };
};

const getControl = (id, defaultValue) => {
  return controls[id] !== undefined ? controls[id] : defaultValue;
};

// Target Desktop Particle Count = 2,200
export const DEFAULT_DESKTOP_PARTICLE_COUNT = 2200;
export const MAX_DESKTOP_PARTICLE_COUNT = 2500;

// Device Adaptive Particle Count helper
export const getAdaptiveParticleCount = () => {
  if (typeof window === 'undefined') return DEFAULT_DESKTOP_PARTICLE_COUNT;
  const width = window.innerWidth;
  if (width < 768) return 1200;          // Mobile target
  if (width < 1024) return 1800;         // Tablet target
  return DEFAULT_DESKTOP_PARTICLE_COUNT; // Desktop target (2,200)
};

/* Topology cache, keyed by (particleCount, formationIndex).
   This used to be a single set of module-level globals that every caller overwrote in place.
   Two ParticleNetwork instances mount in this app (Hero on the landing page, and Login), so the
   second one to build a topology would mutate `edgesList` underneath the first. The first
   instance's line buffers had been allocated from the OLD edge count while its bufferAttribute
   `count` was read from the NEW shared array's length -- a size mismatch that made three.js
   throw "Resizing buffer attributes is not supported" on every rendered frame, thousands of
   times per page view, from inside the render loop.
   Caching per key keeps the original "don't rebuild identical topology" optimisation while
   giving each distinct configuration its own immutable arrays. */
const topologyCache = new Map();

let basePositions = null;
let nodeTypes = null; // 0=red_orange_base, 1=bright_orange_hub, 2=deep_maroon_anomaly, 3=crimson_red_threat
let edgesList = []; // [[i, j, dist, edgeType], ...]

function seededRandom(seed) {
  const x = Math.sin(seed++) * 10000;
  return x - Math.floor(x);
}

/**
 * Initializes an Open 3D Network Field floating in thin air across the screen.
 */
export const buildNetworkTopology = (particleCount, formationIndex = 0) => {
  const cacheKey = `${particleCount}:${formationIndex}`;
  const cached = topologyCache.get(cacheKey);
  if (cached) return cached;

  basePositions = new Float32Array(particleCount * 3);
  nodeTypes = new Uint8Array(particleCount);

  let seed = 42 + formationIndex * 137;

  // Generate continuous open 3D volume (-55 to +55 X, -32 to +32 Y, -28 to +28 Z)
  for (let i = 0; i < particleCount; i++) {
    const u1 = seededRandom(seed++);
    const u2 = seededRandom(seed++);
    const u3 = seededRandom(seed++);

    let px = (u1 - 0.5) * 115.0;
    let py = (u2 - 0.5) * 65.0;
    let pz = (u3 - 0.5) * 55.0;

    py += Math.sin(px * 0.04 + pz * 0.03) * 6.0;
    pz += Math.cos(px * 0.05 + py * 0.04) * 5.0;

    const idx3 = i * 3;
    basePositions[idx3] = px;
    basePositions[idx3 + 1] = py;
    basePositions[idx3 + 2] = pz;

    // Semantic Reddish & Orangish Group Assignments:
    // 0: Reddish-Orange Base (#FF4500) ~60%
    // 1: Bright Orange Hub (#FF6A00) ~15%
    // 2: Deep Maroon Anomaly (#7A1A24) ~12%
    // 3: Crimson Red Threat (#D32F2F) ~13%
    const randType = seededRandom(seed++);
    if (randType < 0.15) nodeTypes[i] = 1;
    else if (randType < 0.27) nodeTypes[i] = 2;
    else if (randType < 0.40) nodeTypes[i] = 3;
    else nodeTypes[i] = 0;
  }

  // --------------------------------------------------------------------------
  // Build Spatial 3D Network Edges
  // --------------------------------------------------------------------------
  edgesList = [];
  const MAX_CONNECT_DIST = 9.8;
  const MAX_CONNECT_DIST_SQ = MAX_CONNECT_DIST * MAX_CONNECT_DIST;

  const cellSize = 10.0;
  const grid = new Map();

  for (let i = 0; i < particleCount; i++) {
    const px = basePositions[i * 3];
    const py = basePositions[i * 3 + 1];
    const pz = basePositions[i * 3 + 2];

    const cx = Math.floor(px / cellSize);
    const cy = Math.floor(py / cellSize);
    const cz = Math.floor(pz / cellSize);
    const key = `${cx},${cy},${cz}`;

    if (!grid.has(key)) grid.set(key, []);
    grid.get(key).push(i);
  }

  const maxEdges = Math.min(6000, particleCount * 3);
  const maxEdgesPerNode = 3;
  const nodeEdgeCounts = new Uint8Array(particleCount);

  for (let i = 0; i < particleCount; i++) {
    if (edgesList.length >= maxEdges) break;

    const px = basePositions[i * 3];
    const py = basePositions[i * 3 + 1];
    const pz = basePositions[i * 3 + 2];

    const cx = Math.floor(px / cellSize);
    const cy = Math.floor(py / cellSize);
    const cz = Math.floor(pz / cellSize);

    for (let dx = -1; dx <= 1; dx++) {
      for (let dy = -1; dy <= 1; dy++) {
        for (let dz = -1; dz <= 1; dz++) {
          const neighborKey = `${cx + dx},${cy + dy},${cz + dz}`;
          const cellNodes = grid.get(neighborKey);
          if (!cellNodes) continue;

          for (let k = 0; k < cellNodes.length; k++) {
            const j = cellNodes[k];
            if (j <= i) continue;

            if (nodeEdgeCounts[i] >= maxEdgesPerNode || nodeEdgeCounts[j] >= maxEdgesPerNode) {
              continue;
            }

            const nx = basePositions[j * 3];
            const ny = basePositions[j * 3 + 1];
            const nz = basePositions[j * 3 + 2];

            const distSq = (px - nx) ** 2 + (py - ny) ** 2 + (pz - nz) ** 2;

            if (distSq <= MAX_CONNECT_DIST_SQ) {
              const dist = Math.sqrt(distSq);
              let edgeType = 0;

              const typeI = nodeTypes[i];
              const typeJ = nodeTypes[j];

              if (typeI === 3 || typeJ === 3) edgeType = 1; // Crimson threat edge
              else if (typeI === 2 || typeJ === 2) edgeType = 2; // Deep maroon anomaly edge
              else if (typeI === 1 || typeJ === 1) edgeType = 3; // Bright orange link

              edgesList.push([i, j, dist, edgeType]);
              nodeEdgeCounts[i]++;
              nodeEdgeCounts[j]++;

              if (edgesList.length >= maxEdges) break;
            }
          }
        }
      }
    }
  }

  const topology = { basePositions, nodeTypes, edgesList };
  topologyCache.set(cacheKey, topology);
  return topology;
};

/**
 * Calculates particle positions & colors in thin air during animation frames.
 * Strict Reddish & Orangish Palette (Zero Yellow, Zero Gray).
 */
export const updateParticlePosAndColor = (
  i,
  particleCount,
  time,
  mode,
  clickPulse,
  isPaused,
  targetPos,
  outColor
) => {
  if (!basePositions || basePositions.length < particleCount * 3) {
    buildNetworkTopology(particleCount);
  }

  const idx3 = i * 3;
  const bx = basePositions[idx3];
  const by = basePositions[idx3 + 1];
  const bz = basePositions[idx3 + 2];
  const type = nodeTypes[i];

  const speed = getControl("speed", 0.65);
  const chaos = getControl("chaos", 0.42);

  const t = isPaused ? 0 : time * speed;
  const wave = Math.sin(t * 0.9 + i * 0.015) * (0.5 + chaos * 0.5);
  const waveZ = Math.cos(t * 0.7 + i * 0.011) * 0.4;

  let clickDistFactor = 0;
  if (clickPulse > 0) {
    const distFromOrigin = Math.sqrt(bx * bx + by * by + bz * bz);
    const pulseRadius = (t * 8.0) % 50.0;
    const diff = Math.abs(distFromOrigin - pulseRadius);
    if (diff < 6.0) {
      clickDistFactor = (1.0 - diff / 6.0) * 1.5;
    }
  }

  const px = bx + wave * 0.7;
  const py = by + wave * 0.8 + clickDistFactor * 0.8;
  const pz = bz + waveZ * 0.7;

  targetPos.set(px, py, pz);

  // --------------------------------------------------------------------------
  // STRICT REDDISH & ORANGISH COLOR PALETTE (ZERO YELLOW, ZERO GRAY):
  // 0. Base Reddish-Orange: #FF4500 -> RGB(1.000, 0.270, 0.000)
  // 1. Bright Orange:       #FF6A00 -> RGB(1.000, 0.415, 0.000)
  // 2. Deep Maroon:         #7A1A24 -> RGB(0.480, 0.100, 0.140)
  // 3. Crimson Red:         #D32F2F -> RGB(0.850, 0.160, 0.160)
  // --------------------------------------------------------------------------
  let r = 1.000, g = 0.270, b = 0.000; // Base Reddish-Orange (#FF4500)

  if (type === 1) {
    r = 1.000; g = 0.415; b = 0.000; // Bright Orange (#FF6A00)
  } else if (type === 2) {
    r = 0.480; g = 0.100; b = 0.140; // Deep Maroon (#7A1A24)
  } else if (type === 3) {
    r = 0.850; g = 0.160; b = 0.160; // Crimson Red (#D32F2F)
  }

  if (mode === 'threat' && type === 3) {
    r = 0.95; g = 0.12; b = 0.15; // Intense Threat Red
  } else if (mode === 'forecast' && type === 1) {
    r = 1.00; g = 0.50; b = 0.00; // Bright Forecast Orange
  }

  outColor.setRGB(r, g, b);
};
