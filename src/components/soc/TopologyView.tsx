import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Server, ShieldAlert, Cpu, Network, RefreshCw, ZoomIn, ZoomOut, AlertCircle } from 'lucide-react';

interface NetworkNode {
  id: string;
  label: string;
  zone: 'Internet / Edge' | 'DMZ' | 'Internal Core' | 'Database LAN' | 'Deception Honeypot';
  ip: string;
  status: 'healthy' | 'compromised' | 'warning';
  pos: [number, number, number];
  services: string[];
}

const networkNodes: NetworkNode[] = [
  { id: 'gw-01', label: 'Perimeter FW & IPS', zone: 'Internet / Edge', ip: '198.51.100.1', status: 'healthy', pos: [-4, 0, 0], services: ['Palo Alto OS', 'BGP', 'Snort 3.0'] },
  { id: 'dmz-web', label: 'WAF & Web Proxy', zone: 'DMZ', ip: '172.16.10.80', status: 'warning', pos: [-2, 1.5, 0], services: ['NGINX Reverse Proxy', 'ModSecurity'] },
  { id: 'dmz-mail', label: 'Mail Gateway & SPF', zone: 'DMZ', ip: '172.16.10.25', status: 'healthy', pos: [-2, -1.5, 0], services: ['Postfix', 'SpamAssassin', 'DKIM'] },
  { id: 'core-dc', label: 'Primary Domain Controller', zone: 'Internal Core', ip: '10.0.4.12', status: 'compromised', pos: [1, 2, 0], services: ['Active Directory', 'Kerberos (KDC)', 'DNS'] },
  { id: 'core-file', label: 'Corporate File Storage', zone: 'Internal Core', ip: '10.0.7.19', status: 'healthy', pos: [1, 0, 0], services: ['SMB 3.1.1', 'NFS', 'VSS Agent'] },
  { id: 'db-cluster', label: 'Financial DB Cluster', zone: 'Database LAN', ip: '10.0.9.100', status: 'healthy', pos: [3.5, 1, 0], services: ['PostgreSQL 16', 'TLS Mutual Auth'] },
  { id: 'honey-01', label: 'Canary Honeypot Node', zone: 'Deception Honeypot', ip: '10.0.12.99', status: 'warning', pos: [2.5, -2, 0], services: ['Cowrie SSH Trap', 'Dionaea'] },
];

export const TopologyView: React.FC = () => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<NetworkNode>(networkNodes[3]); // Default to compromised DC
  const [isRotating, setIsRotating] = useState(true);

  useEffect(() => {
    if (!mountRef.current) return;

    const width = mountRef.current.clientWidth;
    const height = mountRef.current.clientHeight || 450;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x030712, 0.05);

    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
    camera.position.set(0, 0, 9);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mountRef.current.appendChild(renderer.domElement);

    // Ambient & Point Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0x06b6d4, 2, 50);
    pointLight.position.set(0, 5, 5);
    scene.add(pointLight);

    const threatLight = new THREE.PointLight(0xf43f5e, 2, 50);
    threatLight.position.set(2, 2, 4);
    scene.add(threatLight);

    // Grid Floor
    const gridHelper = new THREE.GridHelper(20, 20, 0x164e63, 0x0f172a);
    gridHelper.position.y = -3;
    scene.add(gridHelper);

    // Topology Group
    const graphGroup = new THREE.Group();
    scene.add(graphGroup);

    // Node Meshes
    const nodeObjects: { mesh: THREE.Mesh; node: NetworkNode }[] = [];

    networkNodes.forEach(node => {
      const color = node.status === 'compromised' ? 0xf43f5e : node.status === 'warning' ? 0xf59e0b : 0x06b6d4;
      const geometry = node.status === 'compromised' ? new THREE.OctahedronGeometry(0.35) : new THREE.SphereGeometry(0.3, 16, 16);
      const material = new THREE.MeshStandardMaterial({
        color,
        emissive: color,
        emissiveIntensity: node.status === 'compromised' ? 0.7 : 0.3,
        roughness: 0.2,
        metalness: 0.8,
      });

      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.set(node.pos[0], node.pos[1], node.pos[2]);
      graphGroup.add(mesh);
      nodeObjects.push({ mesh, node });

      // Outer wireframe ring
      const ringGeo = new THREE.RingGeometry(0.42, 0.46, 24);
      const ringMat = new THREE.MeshBasicMaterial({ color, side: THREE.DoubleSide, transparent: true, opacity: 0.4 });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.position.set(node.pos[0], node.pos[1], node.pos[2]);
      graphGroup.add(ring);
    });

    // Connecting Lines (Edges)
    const edges: [string, string][] = [
      ['gw-01', 'dmz-web'],
      ['gw-01', 'dmz-mail'],
      ['dmz-web', 'core-dc'],
      ['dmz-web', 'core-file'],
      ['core-dc', 'db-cluster'],
      ['core-dc', 'honey-01'],
      ['core-file', 'db-cluster'],
    ];

    const lineMat = new THREE.LineBasicMaterial({ color: 0x0e7490, transparent: true, opacity: 0.5 });
    const lineCompromisedMat = new THREE.LineBasicMaterial({ color: 0xf43f5e, transparent: true, opacity: 0.8 });

    edges.forEach(([srcId, dstId]) => {
      const src = networkNodes.find(n => n.id === srcId);
      const dst = networkNodes.find(n => n.id === dstId);
      if (src && dst) {
        const points = [
          new THREE.Vector3(src.pos[0], src.pos[1], src.pos[2]),
          new THREE.Vector3(dst.pos[0], dst.pos[1], dst.pos[2])
        ];
        const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
        const isCompromisedEdge = src.status === 'compromised' || dst.status === 'compromised';
        const line = new THREE.Line(lineGeo, isCompromisedEdge ? lineCompromisedMat : lineMat);
        graphGroup.add(line);
      }
    });

    // Particle Pulses traversing edges
    const particleCount = 40;
    const particleGeo = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount * 3; i++) {
      particlePositions[i] = (Math.random() - 0.5) * 6;
    }
    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const particleMat = new THREE.PointsMaterial({ color: 0x38bdf8, size: 0.08, transparent: true, opacity: 0.8 });
    const particleSystem = new THREE.Points(particleGeo, particleMat);
    graphGroup.add(particleSystem);

    // Animation Loop
    let animationFrameId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      if (isRotating) {
        graphGroup.rotation.y = Math.sin(elapsedTime * 0.2) * 0.3;
        graphGroup.rotation.x = Math.cos(elapsedTime * 0.15) * 0.15;
      }

      // Pulse compromised node
      nodeObjects.forEach(({ mesh, node }) => {
        if (node.status === 'compromised') {
          const s = 1 + Math.sin(elapsedTime * 6) * 0.2;
          mesh.scale.set(s, s, s);
          mesh.rotation.y += 0.02;
        }
      });

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      if (!mountRef.current) return;
      const w = mountRef.current.clientWidth;
      const h = mountRef.current.clientHeight || 450;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
      renderer.dispose();
      if (mountRef.current && renderer.domElement) {
        mountRef.current.removeChild(renderer.domElement);
      }
    };
  }, [isRotating]);

  return (
    <div className="space-y-4">
      {/* 3D Canvas Container */}
      <div className="relative h-[480px] w-full rounded-2xl border border-cyan-950/80 bg-gray-950 overflow-hidden shadow-[inset_0_0_50px_rgba(0,0,0,0.8)]">
        <div ref={mountRef} className="h-full w-full" />

        {/* Floating Top Controls */}
        <div className="absolute left-4 top-4 z-10 flex items-center gap-2">
          <div className="rounded-lg bg-gray-950/80 border border-gray-800 px-3 py-1.5 backdrop-blur-md">
            <span className="font-mono text-xs font-bold text-cyan-400">3D NETWORK TOPOLOGY GRAPH</span>
            <span className="ml-2 text-[10px] font-mono text-gray-400">LIVE ZONES</span>
          </div>
          <button
            onClick={() => setIsRotating(!isRotating)}
            className={`rounded-lg border px-3 py-1.5 text-xs font-mono transition-all cursor-pointer ${
              isRotating ? 'border-cyan-500/50 bg-cyan-950/80 text-cyan-300' : 'border-gray-800 bg-gray-900 text-gray-400'
            }`}
          >
            Auto Orbit: {isRotating ? 'ON' : 'OFF'}
          </button>
        </div>

        {/* Legend */}
        <div className="absolute right-4 top-4 z-10 hidden sm:flex flex-col gap-1.5 rounded-lg border border-gray-800 bg-gray-950/80 p-3 backdrop-blur-md font-mono text-[11px]">
          <div className="flex items-center gap-2 text-cyan-400">
            <span className="h-2.5 w-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
            <span>Normal Node</span>
          </div>
          <div className="flex items-center gap-2 text-amber-400">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-400 shadow-[0_0_8px_rgba(245,158,11,0.8)]" />
            <span>Suspicious Activity</span>
          </div>
          <div className="flex items-center gap-2 text-rose-400">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-400 animate-ping" />
            <span>Active Intrusion</span>
          </div>
        </div>

        {/* Quick Node Selector bar */}
        <div className="absolute bottom-4 left-4 right-4 z-10 flex items-center gap-2 overflow-x-auto p-1.5 rounded-xl border border-gray-800/80 bg-gray-950/85 backdrop-blur-md">
          {networkNodes.map(node => (
            <button
              key={node.id}
              onClick={() => setSelectedNode(node)}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-mono transition-all shrink-0 cursor-pointer ${
                selectedNode.id === node.id
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/80'
                  : 'bg-gray-900 text-gray-400 border border-gray-800 hover:text-gray-200'
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${
                node.status === 'compromised' ? 'bg-rose-500 animate-pulse' : node.status === 'warning' ? 'bg-amber-500' : 'bg-cyan-400'
              }`} />
              <span>{node.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Selected Node Deep Inspector */}
      {selectedNode && (
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-5 shadow-lg">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 pb-3">
            <div className="flex items-center gap-3">
              <div className={`flex h-10 w-10 items-center justify-center rounded-lg border ${
                selectedNode.status === 'compromised'
                  ? 'bg-rose-950 text-rose-400 border-rose-800'
                  : selectedNode.status === 'warning'
                  ? 'bg-amber-950 text-amber-400 border-amber-800'
                  : 'bg-cyan-950 text-cyan-400 border-cyan-800'
              }`}>
                <Server className="h-5 w-5" />
              </div>
              <div>
                <h3 className="font-mono text-base font-bold text-gray-100">{selectedNode.label}</h3>
                <p className="text-xs font-mono text-cyan-400">
                  Zone: {selectedNode.zone} &bull; IP: {selectedNode.ip}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className={`rounded px-2.5 py-1 text-xs font-mono font-bold uppercase border ${
                selectedNode.status === 'compromised'
                  ? 'bg-rose-950 text-rose-300 border-rose-800 animate-pulse'
                  : selectedNode.status === 'warning'
                  ? 'bg-amber-950 text-amber-300 border-amber-800'
                  : 'bg-emerald-950 text-emerald-300 border-emerald-800'
              }`}>
                {selectedNode.status}
              </span>
            </div>
          </div>

          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <span className="text-xs font-mono uppercase text-gray-400 block mb-2">Running Services &amp; Daemons</span>
              <div className="flex flex-wrap gap-2">
                {selectedNode.services.map((svc, i) => (
                  <span key={i} className="rounded-lg border border-gray-800 bg-gray-900 px-2.5 py-1 text-xs font-mono text-gray-300">
                    {svc}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span className="text-xs font-mono uppercase text-gray-400 block mb-2">Security Telemetry Correlation</span>
              {selectedNode.status === 'compromised' ? (
                <div className="rounded-lg border border-rose-900/60 bg-rose-950/20 p-3 text-xs font-mono text-rose-300">
                  <div className="flex items-center gap-1.5 font-bold mb-1">
                    <AlertCircle className="h-4 w-4 text-rose-400" />
                    COMPROMISED HOST — ACTIVE INTRUSION
                  </div>
                  <p className="text-[11px] text-gray-300">
                    Correlate live alerts against this asset in the SOC dashboard — isolate at the switch/EDR layer and preserve volatile memory.
                  </p>
                </div>
              ) : selectedNode.status === 'warning' ? (
                <div className="rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-xs font-mono text-amber-300">
                  <p className="text-[11px] text-gray-300">
                    Elevated probe frequency on public HTTP ports. WAF rules currently blocking SQL injection attempts.
                  </p>
                </div>
              ) : (
                <div className="rounded-lg border border-emerald-900/60 bg-emerald-950/20 p-3 text-xs font-mono text-emerald-300">
                  <p className="text-[11px] text-gray-300">
                    All endpoint health telemetry verified. EDR agent reporting zero anomalous process injections.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
