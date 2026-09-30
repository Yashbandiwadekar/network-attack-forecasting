import { useTheme } from '../../theme/ThemeContext';
import React, { useRef, useMemo, useEffect, useState } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { OrbitControls } from '@react-three/drei';
import * as THREE from 'three';
import {
  buildNetworkTopology,
  updateParticlePosAndColor,
  setControls,
  getAdaptiveParticleCount
} from './particleBehavior';
import './particleStyles.css';

function CameraController({ resetTrigger }) {
  const { camera } = useThree();
  const controlsRef = useRef();

  useEffect(() => {
    if (controlsRef.current) {
      camera.position.set(0, 10, 52);
      camera.lookAt(0, 0, 0);
      controlsRef.current.reset();
    }
  }, [resetTrigger, camera]);

  return (
    <OrbitControls
      ref={controlsRef}
      enableZoom={true}
      enablePan={true}
      enableRotate={true}
      autoRotate={true}
      autoRotateSpeed={0.35}
      maxDistance={120}
      minDistance={10}
    />
  );
}

const NetworkField = ({ particleCount, controlsConfig, isPaused, mode, clickPulse, formationIndex, isLight = false }) => {
  const meshRef = useRef();
  const linesRef = useRef();

  const dummy = useMemo(() => new THREE.Object3D(), []);
  const tempColor = useMemo(() => new THREE.Color(), []);
  const tempPos = useMemo(() => new THREE.Vector3(), []);

  const nodeCurrentPositions = useMemo(() => {
    return new Float32Array(particleCount * 3);
  }, [particleCount]);

  const topology = useMemo(() => {
    return buildNetworkTopology(particleCount, formationIndex);
  }, [particleCount, formationIndex]);

  const edgesCount = topology.edgesList.length;

  const linePositions = useMemo(() => new Float32Array(edgesCount * 6), [edgesCount]);
  const lineColors = useMemo(() => new Float32Array(edgesCount * 6), [edgesCount]);

  useEffect(() => {
    setControls(controlsConfig);
  }, [controlsConfig]);

  // BUG-008: manual elapsed-time accumulator using useFrame's delta parameter.
  // THREE.Clock is deprecated in Three.js >=0.169 — state.clock.getElapsedTime() would
  // trigger the "THREE.Clock: This module has been deprecated" warning on every frame.
  // Accumulating delta ourselves produces identical timing without touching THREE.Clock.
  const elapsedRef = useRef(0);

  // BUG-007 (react/immutability): linePositions, lineColors, and nodeCurrentPositions are
  // Float32Array buffers that MUST be mutated in-place per frame — this is the required
  // Three.js/R3F pattern for updating BufferGeometry attributes. Using useState or
  // useReducer would allocate a new array every frame and thrash the GC. The mutation
  // happens inside useFrame (outside React's render cycle), so it cannot cause tearing.
  // eslint-disable-next-line react/immutability -- intentional Three.js buffer mutation
  useFrame((_state, delta) => {
    if (!meshRef.current || !linesRef.current) return;

    if (!isPaused) elapsedRef.current += delta;
    const time = isPaused ? 0 : elapsedRef.current;
    const activeCount = Math.floor(particleCount * (controlsConfig.density || 0.85));

    for (let i = 0; i < particleCount; i++) {
      const idx3 = i * 3;

      if (i >= activeCount) {
        dummy.position.set(9999, 9999, 9999);
        dummy.scale.set(0, 0, 0);
        dummy.updateMatrix();
        meshRef.current.setMatrixAt(i, dummy.matrix);
        nodeCurrentPositions[idx3] = 9999;
        nodeCurrentPositions[idx3 + 1] = 9999;
        nodeCurrentPositions[idx3 + 2] = 9999;
        continue;
      }

      updateParticlePosAndColor(
        i,
        particleCount,
        time,
        mode,
        clickPulse,
        isPaused,
        tempPos,
        tempColor
      );

      nodeCurrentPositions[idx3] = tempPos.x;
      nodeCurrentPositions[idx3 + 1] = tempPos.y;
      nodeCurrentPositions[idx3 + 2] = tempPos.z;

      let scale = 0.20;
      if (topology.nodeTypes[i] === 1) scale = 0.28;
      else if (topology.nodeTypes[i] === 2 || topology.nodeTypes[i] === 3) scale = 0.26;

      dummy.position.copy(tempPos);
      dummy.scale.set(scale, scale, scale);
      dummy.updateMatrix();

      meshRef.current.setMatrixAt(i, dummy.matrix);
      meshRef.current.setColorAt(i, tempColor);
    }

    meshRef.current.instanceMatrix.needsUpdate = true;
    if (meshRef.current.instanceColor) {
      meshRef.current.instanceColor.needsUpdate = true;
    }

    let validLineCount = 0;
    const edgesList = topology.edgesList;

    for (let e = 0; e < edgesCount; e++) {
      const edge = edgesList[e];
      const i = edge[0];
      const j = edge[1];
      const edgeType = edge[3];

      if (i >= activeCount || j >= activeCount) continue;

      const i3 = i * 3;
      const j3 = j * 3;

      const p1x = nodeCurrentPositions[i3];
      const p1y = nodeCurrentPositions[i3 + 1];
      const p1z = nodeCurrentPositions[i3 + 2];

      const p2x = nodeCurrentPositions[j3];
      const p2y = nodeCurrentPositions[j3 + 1];
      const p2z = nodeCurrentPositions[j3 + 2];

      const dx = p1x - p2x;
      const dy = p1y - p2y;
      const dz = p1z - p2z;
      const curDist = Math.sqrt(dx * dx + dy * dy + dz * dz);

      if (curDist > 16.0) continue;

      const lineIdx = validLineCount * 6;

      linePositions[lineIdx] = p1x;
      linePositions[lineIdx + 1] = p1y;
      linePositions[lineIdx + 2] = p1z;
      linePositions[lineIdx + 3] = p2x;
      linePositions[lineIdx + 4] = p2y;
      linePositions[lineIdx + 5] = p2z;

      const pulseSignal = Math.sin(time * 3.5 - (p1x + p2x) * 0.15);
      const isPulsing = pulseSignal > 0.6;

      let alpha = (1.0 - curDist / 16.0) * 0.75;
      let lr = 1.0, lg = 0.28, lb = 0.02;

      if (edgeType === 1 || mode === 'threat') {
        if (isPulsing || edgeType === 1) {
          lr = 0.90; lg = 0.14; lb = 0.16;
          alpha = Math.min(0.9, alpha * 1.4);
        }
      } else if (edgeType === 2 || mode === 'forecast') {
        lr = 1.0; lg = 0.45; lb = 0.0;
        if (isPulsing) alpha = Math.min(0.95, alpha * 1.3);
      } else if (edgeType === 3) {
        lr = 1.0; lg = 0.35; lb = 0.0;
        alpha = Math.min(0.85, alpha * 1.2);
      }

      lineColors[lineIdx] = lr * alpha;
      lineColors[lineIdx + 1] = lg * alpha;
      lineColors[lineIdx + 2] = lb * alpha;
      lineColors[lineIdx + 3] = lr * alpha;
      lineColors[lineIdx + 4] = lg * alpha;
      lineColors[lineIdx + 5] = lb * alpha;

      validLineCount++;
    }

    for (let k = validLineCount * 6; k < linePositions.length; k++) {
      linePositions[k] = 0;
      lineColors[k] = 0;
    }

    linesRef.current.geometry.attributes.position.needsUpdate = true;
    linesRef.current.geometry.attributes.color.needsUpdate = true;
    linesRef.current.geometry.setDrawRange(0, validLineCount * 2);
  });

  /* `key={particleCount}` on both meshes is load-bearing, not cosmetic.
     When the viewport crosses a breakpoint, getAdaptiveParticleCount() changes particleCount,
     which changes edgesCount, which produces new Float32Arrays for the line buffers. Without a
     key, React attaches those differently-sized arrays to the SAME bufferGeometry, and three.js
     refuses to resize an allocated buffer attribute -- it threw
     "THREE.WebGLAttributes: Resizing buffer attributes is not supported" on every frame
     thereafter (thousands of errors per page view, from inside the render loop).
     Keying the elements makes React mount fresh geometry instead of mutating the old one.
     Visual output is unchanged. */
  return (
    <group>
      <instancedMesh key={`mesh-${particleCount}`} ref={meshRef} args={[null, null, particleCount]}>
        <sphereGeometry args={[1, 8, 8]} />
        <meshBasicMaterial toneMapped={false} transparent={true} opacity={0.95} />
      </instancedMesh>

      <lineSegments key={`lines-${particleCount}-${formationIndex}`} ref={linesRef}>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            count={edgesCount * 2}
            array={linePositions}
            itemSize={3}
          />
          <bufferAttribute
            attach="attributes-color"
            count={edgesCount * 2}
            array={lineColors}
            itemSize={3}
          />
        </bufferGeometry>
        <lineBasicMaterial
          vertexColors={true}
          transparent={true}
          opacity={isLight ? 0.38 : 0.75}
          blending={isLight ? THREE.NormalBlending : THREE.AdditiveBlending}
          depthWrite={false}
        />
      </lineSegments>
    </group>
  );
};

const ParticleNetwork = ({ controlsConfig, isPaused, mode, resetTrigger, onCanvasClick, clickPulse, formationIndex = 0 }) => {
  // Read the theme here, not inside <Canvas>: R3F renders in its own reconciler, so React context does
  // not cross the Canvas boundary and the scene has to be handed the value as a prop.
  const { theme } = useTheme();
  const isLight = theme === 'light';
  const canvasBg = isLight ? '#f3f4f6' : '#000000';
  const [particleCount, setParticleCount] = useState(() => getAdaptiveParticleCount());

  useEffect(() => {
    const handleResize = () => {
      const count = getAdaptiveParticleCount();
      if (count !== particleCount) {
        setParticleCount(count);
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [particleCount]);

  return (
    <div className="particle-container" onClick={onCanvasClick}>
      <Canvas
        camera={{ position: [0, 10, 52], fov: 45 }}
        gl={{ alpha: false, antialias: true, powerPreference: "high-performance" }}
        dpr={[1, 2]}
      >
        <color attach="background" args={[canvasBg]} />
        <fog attach="fog" args={[canvasBg, 30, 95]} />

        <NetworkField
          particleCount={particleCount}
          controlsConfig={controlsConfig}
          isPaused={isPaused}
          mode={mode}
          clickPulse={clickPulse}
          formationIndex={formationIndex}
          isLight={isLight}
        />

        <CameraController resetTrigger={resetTrigger} />
      </Canvas>
    </div>
  );
};

export default ParticleNetwork;
