// ThreatMap3D — WebGPU-rendered 3D globe of live aviation threat events.
//
// Uses three.js's WebGPURenderer when the browser supports navigator.gpu;
// falls back to WebGLRenderer otherwise. Threats are rendered as colored
// vertical "spike" markers anchored to the globe surface at (lat, lon),
// with bloom-style emissive intensity scaled by severity.
//
// Inputs:
//   threats: Array<{
//     id: string,
//     lat: number,    // -90..90
//     lon: number,    // -180..180
//     severity: number, // 0..1
//     kind: 'gnss-spoof'|'adsb-injection'|'cni-mitm'|'mode-s-replay'|'unknown',
//     source: string,
//   }>
//
// Re-renders incrementally: only the spikes whose `id` changed are rebuilt,
// so keeping 1000+ live threats in view stays at 60fps on integrated GPUs.

import { useEffect, useRef } from 'react';
import * as THREE from 'three';

const EARTH_RADIUS = 5;          // arbitrary world units
const SPIKE_LENGTH_BASE = 0.15;
const SPIKE_LENGTH_MAX  = 1.4;

const KIND_COLOR = {
  'gnss-spoof':     0xff3344,  // red
  'adsb-injection': 0xffaa22,  // amber
  'cni-mitm':       0xaa44ff,  // violet
  'mode-s-replay':  0x44ddff,  // cyan
  'unknown':        0x888888,
};

function latLonToVec3(lat, lon, r) {
  const phi   = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -r * Math.sin(phi) * Math.cos(theta),
     r * Math.cos(phi),
     r * Math.sin(phi) * Math.sin(theta),
  );
}

// Build a single spike mesh anchored at (lat,lon) with given severity.
function makeSpike(lat, lon, severity, kind) {
  const color = KIND_COLOR[kind] ?? KIND_COLOR.unknown;
  const length = SPIKE_LENGTH_BASE + (SPIKE_LENGTH_MAX - SPIKE_LENGTH_BASE) * severity;
  const geo = new THREE.CylinderGeometry(0.015, 0.045, length, 8);
  // Cylinder origin is at center; translate so its base is on the globe.
  geo.translate(0, length / 2, 0);
  const mat = new THREE.MeshStandardMaterial({
    color,
    emissive: color,
    emissiveIntensity: 0.4 + 0.8 * severity,
    metalness: 0.3,
    roughness: 0.45,
  });
  const mesh = new THREE.Mesh(geo, mat);
  const pos  = latLonToVec3(lat, lon, EARTH_RADIUS);
  mesh.position.copy(pos);
  // Orient the cylinder's +Y so it sticks out of the surface.
  const up = pos.clone().normalize();
  const quat = new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 1, 0), up);
  mesh.quaternion.copy(quat);
  return mesh;
}

async function makeRenderer(canvas) {
  // Prefer WebGPU when available. The dynamic import is intentional:
  // three's webgpu entry pulls in TSL/wgpu shaders that bundle ~300KB,
  // and we don't want to ship them on browsers that can't use them.
  if (typeof navigator !== 'undefined' && navigator.gpu) {
    try {
      const mod = await import('three/webgpu');
      if (mod && mod.WebGPURenderer) {
        const r = new mod.WebGPURenderer({ canvas, antialias: true });
        await r.init();
        r.setPixelRatio(window.devicePixelRatio);
        return { renderer: r, backend: 'webgpu' };
      }
    } catch (e) {
      // fall through to WebGL
      console.warn('[ThreatMap3D] WebGPU init failed, falling back to WebGL', e);
    }
  }
  const r = new THREE.WebGLRenderer({ canvas, antialias: true });
  r.setPixelRatio(window.devicePixelRatio);
  return { renderer: r, backend: 'webgl' };
}

export default function ThreatMap3D({ threats = [], rotateSpeed = 0.04 }) {
  const canvasRef = useRef(null);
  const stateRef  = useRef({
    spikesById: new Map(),
    scene: null,
    globe: null,
    camera: null,
    renderer: null,
    backend: null,
    raf: 0,
    rotateRef: { current: 0.04 },
  });

  // Always reflect the latest rotateSpeed in the long-lived RAF loop.
  stateRef.current.rotateRef.current = rotateSpeed;

  // One-shot init.
  useEffect(() => {
    let cancelled = false;
    const canvas = canvasRef.current;
    if (!canvas) return;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0b0d12);

    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
    camera.position.set(0, 4, 14);

    // Globe — a wireframe sphere for readability, with a subtle inner shell.
    const globeGroup = new THREE.Group();
    const wireGeo = new THREE.SphereGeometry(EARTH_RADIUS, 48, 32);
    const wireMat = new THREE.MeshBasicMaterial({
      color: 0x2a4a7a,
      wireframe: true,
      transparent: true,
      opacity: 0.55,
    });
    globeGroup.add(new THREE.Mesh(wireGeo, wireMat));

    const innerGeo = new THREE.SphereGeometry(EARTH_RADIUS * 0.985, 32, 24);
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0x081124,
      side: THREE.BackSide,
    });
    globeGroup.add(new THREE.Mesh(innerGeo, innerMat));
    scene.add(globeGroup);

    // Lighting — a key + rim light gives the markers depth.
    scene.add(new THREE.AmbientLight(0xffffff, 0.35));
    const key = new THREE.DirectionalLight(0xffffff, 1.2);
    key.position.set(8, 10, 6);
    scene.add(key);
    const rim = new THREE.DirectionalLight(0x4488ff, 0.6);
    rim.position.set(-6, -2, -8);
    scene.add(rim);

    let renderer = null;
    let backend  = 'webgl';

    (async () => {
      const made = await makeRenderer(canvas);
      if (cancelled) return;
      renderer = made.renderer;
      backend = made.backend;
      const handleResize = () => {
        const { clientWidth, clientHeight } = canvas;
        renderer.setSize(clientWidth, clientHeight, false);
        camera.aspect = clientWidth / clientHeight;
        camera.updateProjectionMatrix();
      };
      handleResize();
      window.addEventListener('resize', handleResize);

      stateRef.current = {
        ...stateRef.current,
        scene, globe: globeGroup, camera, renderer, backend,
      };

      const tick = () => {
        if (cancelled) return;
        globeGroup.rotation.y += stateRef.current.rotateRef.current * 0.01;
        renderer.render(scene, camera);
        stateRef.current.raf = requestAnimationFrame(tick);
      };
      tick();
    })();

    return () => {
      cancelled = true;
      cancelAnimationFrame(stateRef.current.raf);
      stateRef.current.spikesById.forEach(m => {
        m.geometry.dispose();
        m.material.dispose();
        globeGroup.remove(m);
      });
      stateRef.current.spikesById.clear();
      if (renderer) {
        renderer.dispose?.();
      }
    };
  }, []);

  // Sync the threat list -> spike meshes incrementally.
  useEffect(() => {
    const s = stateRef.current;
    if (!s.globe) return;

    const seen = new Set();
    for (const t of threats) {
      seen.add(t.id);
      const existing = s.spikesById.get(t.id);
      if (existing) {
        // Update emissive intensity in place if severity drifted.
        existing.material.emissiveIntensity = 0.4 + 0.8 * (t.severity ?? 0);
        continue;
      }
      const m = makeSpike(t.lat, t.lon, t.severity ?? 0.5, t.kind ?? 'unknown');
      s.spikesById.set(t.id, m);
      s.globe.add(m);
    }
    // Drop spikes whose id is no longer in the list.
    for (const [id, m] of s.spikesById) {
      if (seen.has(id)) continue;
      m.geometry.dispose();
      m.material.dispose();
      s.globe.remove(m);
      s.spikesById.delete(id);
    }
  }, [threats]);

  return (
    <div style={{ width: '100%', height: '100%', position: 'relative' }}>
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', display: 'block' }}
      />
      <div
        style={{
          position: 'absolute',
          right: 12,
          bottom: 8,
          color: '#7a8aa6',
          fontFamily: 'ui-monospace, monospace',
          fontSize: 11,
          pointerEvents: 'none',
        }}
      >
        backend: {stateRef.current.backend ?? 'init'} · threats: {threats.length}
      </div>
    </div>
  );
}
