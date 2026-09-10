import React, { useState, useEffect } from 'react';
import { Globe, Radio, ShieldAlert, Crosshair, MapPin, Zap } from 'lucide-react';

interface ThreatArc {
  id: string;
  sourceCity: string;
  sourceCountry: string;
  sourcePos: [number, number]; // [x%, y%]
  targetCity: string;
  targetCountry: string;
  targetPos: [number, number];
  type: string;
  severity: 'critical' | 'high' | 'medium';
  timestamp: string;
}

const initialThreatArcs: ThreatArc[] = [
  { id: 'ARC-1', sourceCity: 'St. Petersburg', sourceCountry: 'RU', sourcePos: [63, 26], targetCity: 'New York HQ', targetCountry: 'US', targetPos: [28, 38], type: 'Cobalt Strike C2 Beacon', severity: 'critical', timestamp: '12s ago' },
  { id: 'ARC-2', sourceCity: 'Amsterdam', sourceCountry: 'NL', sourcePos: [51, 31], targetCity: 'Frankfurt Datacenter', targetCountry: 'DE', targetPos: [53, 33], type: 'DNS Tunnel Exfiltration', severity: 'high', timestamp: '24s ago' },
  { id: 'ARC-3', sourceCity: 'Shanghai', sourceCountry: 'CN', sourcePos: [82, 45], targetCity: 'Tokyo Edge', targetCountry: 'JP', targetPos: [87, 42], type: 'Zero-Day SSRF Probe', severity: 'medium', timestamp: '48s ago' },
  { id: 'ARC-4', sourceCity: 'São Paulo', sourceCountry: 'BR', sourcePos: [36, 75], targetCity: 'New York HQ', targetCountry: 'US', targetPos: [28, 38], type: 'Distributed DDoS SYN Flood', severity: 'high', timestamp: '1m ago' },
  { id: 'ARC-5', sourceCity: 'Singapore', sourceCountry: 'SG', sourcePos: [78, 62], targetCity: 'Dhaka Regional Hub', targetCountry: 'BD', targetPos: [74, 48], type: 'Credential Stuffing Botnet', severity: 'medium', timestamp: '1m ago' },
];

export const ThreatMapView: React.FC = () => {
  const [arcs, setArcs] = useState<ThreatArc[]>(initialThreatArcs);
  const [activeArc, setActiveArc] = useState<ThreatArc>(initialThreatArcs[0]);

  // Periodic random attack generation for live feel
  useEffect(() => {
    const interval = setInterval(() => {
      const sources: { city: string; country: string; pos: [number, number] }[] = [
        { city: 'Bucharest', country: 'RO', pos: [57, 34] },
        { city: 'Seoul', country: 'KR', pos: [84, 41] },
        { city: 'Warsaw', country: 'PL', pos: [55, 30] },
        { city: 'Toronto', country: 'CA', pos: [26, 33] },
        { city: 'Mumbai', country: 'IN', pos: [71, 52] },
      ];
      const types = ['AS-REP Roasting', 'Log4j / Spring4Shell probe', 'WAF SQLi Bypass', 'Malicious PDF Drop', 'Kerberoasting'];
      const severities: ('critical' | 'high' | 'medium')[] = ['critical', 'high', 'medium'];

      const randomSrc = sources[Math.floor(Math.random() * sources.length)];
      const randomType = types[Math.floor(Math.random() * types.length)];
      const randomSev = severities[Math.floor(Math.random() * severities.length)];

      const newArc: ThreatArc = {
        id: `ARC-${Date.now().toString().slice(-4)}`,
        sourceCity: randomSrc.city,
        sourceCountry: randomSrc.country,
        sourcePos: randomSrc.pos,
        targetCity: 'Global Core Cloud',
        targetCountry: 'US-EAST',
        targetPos: [28, 38],
        type: randomType,
        severity: randomSev,
        timestamp: 'Just now',
      };

      setArcs(prev => [newArc, ...prev.slice(0, 7)]);
      setActiveArc(newArc);
    }, 6000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div>
          <h2 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wide flex items-center gap-2">
            <Globe className="h-4 w-4 text-cyan-400" />
            Global Cyber Threat &amp; Incursion Map
          </h2>
          <p className="text-xs text-gray-400">
            Real-time geospatial telemetry tracking adversary origin IPs, botnet nodes, and border ingress strikes.
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-md bg-rose-950/60 border border-rose-800 px-3 py-1.5 text-xs font-mono text-rose-300">
          <Radio className="h-3.5 w-3.5 text-rose-400 animate-pulse" />
          <span>INCOMING ATTACK VECTOR DETECTED</span>
        </div>
      </div>

      {/* World Map SVG Canvas */}
      <div className="relative h-[440px] w-full rounded-2xl border border-cyan-950/80 bg-gray-950 p-4 overflow-hidden shadow-2xl">
        {/* World Map Graphic (Stylized Cyber Continents via SVG) */}
        <svg
          className="h-full w-full opacity-60"
          viewBox="0 0 1000 500"
          preserveAspectRatio="xMidYMid slice"
        >
          <defs>
            <radialGradient id="mapGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#0891b2" stopOpacity="0.15" />
              <stop offset="100%" stopColor="#0891b2" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="attackGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.2" />
            </linearGradient>
          </defs>

          {/* Background cyber grid */}
          <rect width="1000" height="500" fill="#030712" />
          <circle cx="500" cy="250" r="400" fill="url(#mapGlow)" />

          {/* Vectorized continents (stylized low-poly paths) */}
          {/* North America */}
          <path
            d="M 120 80 Q 200 60 280 90 Q 320 140 260 210 Q 220 230 180 200 Q 150 160 120 80 Z"
            fill="#0f172a"
            stroke="#1e293b"
            strokeWidth="1.5"
          />
          {/* South America */}
          <path
            d="M 280 260 Q 360 270 380 340 Q 350 440 300 480 Q 260 410 270 320 Z"
            fill="#0f172a"
            stroke="#1e293b"
            strokeWidth="1.5"
          />
          {/* Europe */}
          <path
            d="M 460 80 Q 560 70 580 140 Q 530 190 470 180 Q 430 140 460 80 Z"
            fill="#0f172a"
            stroke="#1e293b"
            strokeWidth="1.5"
          />
          {/* Africa */}
          <path
            d="M 460 210 Q 560 200 580 280 Q 540 390 490 430 Q 430 330 450 240 Z"
            fill="#0f172a"
            stroke="#1e293b"
            strokeWidth="1.5"
          />
          {/* Asia */}
          <path
            d="M 580 80 Q 820 60 880 160 Q 840 260 720 250 Q 640 180 580 80 Z"
            fill="#0f172a"
            stroke="#1e293b"
            strokeWidth="1.5"
          />
          {/* Australia */}
          <path
            d="M 760 330 Q 860 320 880 390 Q 820 440 760 400 Z"
            fill="#0f172a"
            stroke="#1e293b"
            strokeWidth="1.5"
          />

          {/* Render Attack Arcs */}
          {arcs.map((arc, i) => {
            const x1 = (arc.sourcePos[0] / 100) * 1000;
            const y1 = (arc.sourcePos[1] / 100) * 500;
            const x2 = (arc.targetPos[0] / 100) * 1000;
            const y2 = (arc.targetPos[1] / 100) * 500;
            const cx = (x1 + x2) / 2;
            const cy = Math.min(y1, y2) - 80;

            const isSelected = activeArc.id === arc.id;

            return (
              <g key={arc.id}>
                {/* Curved Path */}
                <path
                  d={`M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`}
                  fill="none"
                  stroke={arc.severity === 'critical' ? '#f43f5e' : arc.severity === 'high' ? '#f59e0b' : '#06b6d4'}
                  strokeWidth={isSelected ? '2.5' : '1.5'}
                  strokeDasharray={isSelected ? '6,3' : '4,4'}
                  opacity={isSelected ? 1 : 0.6}
                  className="transition-all"
                />

                {/* Source Node Pulse */}
                <circle cx={x1} cy={y1} r="4" fill="#f43f5e" />
                <circle cx={x1} cy={y1} r="10" fill="#f43f5e" opacity="0.3" className="animate-ping" />

                {/* Target Node */}
                <circle cx={x2} cy={y2} r="5" fill="#06b6d4" />
                <circle cx={x2} cy={y2} r="12" fill="#06b6d4" opacity="0.25" />
              </g>
            );
          })}
        </svg>

        {/* Floating Active Attack Card */}
        <div className="absolute bottom-4 left-4 z-10 w-80 rounded-xl border border-gray-800 bg-gray-950/90 p-3.5 backdrop-blur-md font-mono text-xs">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-gray-400 text-[10px] uppercase">Live Threat Vector</span>
            <span className={`px-2 py-0.2 rounded text-[10px] font-bold uppercase ${
              activeArc.severity === 'critical' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
            }`}>
              {activeArc.severity}
            </span>
          </div>
          <p className="font-bold text-gray-100 text-sm">{activeArc.type}</p>
          <div className="mt-2 text-[11px] text-gray-300 space-y-0.5">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Origin:</span>
              <span className="text-rose-400 font-semibold">{activeArc.sourceCity} ({activeArc.sourceCountry})</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Target:</span>
              <span className="text-cyan-400 font-semibold">{activeArc.targetCity}</span>
            </div>
          </div>
        </div>

        {/* Feed List */}
        <div className="absolute top-4 right-4 z-10 hidden md:block w-72 max-h-[360px] overflow-y-auto rounded-xl border border-gray-800 bg-gray-950/90 p-3 backdrop-blur-md font-mono text-xs">
          <div className="flex items-center justify-between border-b border-gray-800 pb-2 mb-2">
            <span className="text-[11px] text-gray-400 font-bold uppercase">Attack Stream</span>
            <span className="text-[10px] text-emerald-400 flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" /> Real-time
            </span>
          </div>

          <div className="space-y-2">
            {arcs.map(arc => (
              <div
                key={arc.id}
                onClick={() => setActiveArc(arc)}
                className={`p-2 rounded-lg border transition-all cursor-pointer ${
                  activeArc.id === arc.id ? 'bg-gray-900 border-cyan-500/70 text-cyan-300' : 'bg-gray-950/60 border-gray-800/80 text-gray-300 hover:bg-gray-900/40'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] mb-0.5">
                  <span className="text-rose-400 font-bold">{arc.sourceCountry} &rarr; {arc.targetCountry}</span>
                  <span className="text-gray-500">{arc.timestamp}</span>
                </div>
                <p className="text-[11px] font-medium text-gray-200 truncate">{arc.type}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
