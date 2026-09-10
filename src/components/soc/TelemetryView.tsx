import React, { useState, useEffect } from 'react';
import { Activity, Cpu, HardDrive, Radio, Shield, Zap, Server, CheckCircle2, AlertTriangle } from 'lucide-react';
import { TelemetryPoint, SensorStatus } from '../../types';
import { api } from '../../services/api';

export const TelemetryView: React.FC = () => {
  const [history, setHistory] = useState<TelemetryPoint[]>([]);
  const [current, setCurrent] = useState<TelemetryPoint | null>(null);
  const [sensors, setSensors] = useState<SensorStatus[]>([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await api.getTelemetry();
        setHistory(data.history || []);
        setCurrent(data.current || null);
        setSensors(data.sensors || []);
      } catch (err) {
        console.error(err);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  // Compute SVG polyline points for EPS
  const maxEps = 900;
  const chartHeight = 120;
  const chartWidth = 550;

  const points = history.map((item, idx) => {
    const x = (idx / Math.max(1, history.length - 1)) * chartWidth;
    const y = chartHeight - (item.eps / maxEps) * chartHeight;
    return `${x},${y}`;
  }).join(' ');

  const networkPoints = history.map((item, idx) => {
    const x = (idx / Math.max(1, history.length - 1)) * chartWidth;
    const y = chartHeight - (item.networkMbps / 300) * chartHeight;
    return `${x},${y}`;
  }).join(' ');

  return (
    <div className="space-y-4">
      {/* Metric summary top grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-gray-400 uppercase">Live Pipeline EPS</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <p className="mt-2 text-2xl font-mono font-bold text-cyan-400">
            {current?.eps || 512} <span className="text-xs text-gray-500 font-normal">events/sec</span>
          </p>
          <div className="mt-1 flex items-center gap-1.5 text-[10px] font-mono text-emerald-400">
            <Radio className="h-3 w-3 animate-pulse" /> Ingestion Steady
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-gray-400 uppercase">Network Throughput</span>
            <Zap className="h-4 w-4 text-purple-400" />
          </div>
          <p className="mt-2 text-2xl font-mono font-bold text-purple-400">
            {current?.networkMbps || 145} <span className="text-xs text-gray-500 font-normal">Mbps</span>
          </p>
          <span className="text-[10px] font-mono text-gray-400">10Gbps Uplink Active</span>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-gray-400 uppercase">SIEM Core CPU Load</span>
            <Cpu className="h-4 w-4 text-amber-400" />
          </div>
          <p className="mt-2 text-2xl font-mono font-bold text-amber-400">
            {current?.cpuUsage || 48}%
          </p>
          <div className="mt-1 h-1.5 w-full rounded-full bg-gray-800 overflow-hidden">
            <div className="h-full bg-amber-400" style={{ width: `${current?.cpuUsage || 48}%` }} />
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-950 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-gray-400 uppercase">Threats Neutralized</span>
            <Shield className="h-4 w-4 text-emerald-400" />
          </div>
          <p className="mt-2 text-2xl font-mono font-bold text-emerald-400">
            {current?.threatsBlocked || 9} <span className="text-xs text-gray-500 font-normal">in past 5m</span>
          </p>
          <span className="text-[10px] font-mono text-emerald-400/80">Automated EDR Drop</span>
        </div>
      </div>

      {/* Main Charts Area */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* EPS Line Chart */}
        <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-mono text-sm font-bold text-gray-100 uppercase">
                Events Per Second (EPS) Time-Series
              </h3>
              <p className="text-xs text-gray-400 font-mono">Real-time log ingestion flow rate</p>
            </div>
            <span className="rounded bg-cyan-950/80 border border-cyan-800 px-2 py-0.5 text-xs font-mono text-cyan-300">
              Peak: 840 EPS
            </span>
          </div>

          <div className="h-36 w-full relative">
            <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} className="h-full w-full overflow-visible">
              <defs>
                <linearGradient id="epsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
                  <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Grid Lines */}
              <line x1="0" y1="30" x2={chartWidth} y2="30" stroke="#1f293d" strokeDasharray="3,3" />
              <line x1="0" y1="60" x2={chartWidth} y2="60" stroke="#1f293d" strokeDasharray="3,3" />
              <line x1="0" y1="90" x2={chartWidth} y2="90" stroke="#1f293d" strokeDasharray="3,3" />

              {/* Area Fill */}
              {points && (
                <polygon
                  points={`0,${chartHeight} ${points} ${chartWidth},${chartHeight}`}
                  fill="url(#epsGrad)"
                />
              )}

              {/* Line */}
              {points && (
                <polyline
                  points={points}
                  fill="none"
                  stroke="#06b6d4"
                  strokeWidth="2.5"
                />
              )}
            </svg>
          </div>

          <div className="mt-2 flex justify-between text-[10px] font-mono text-gray-500">
            <span>-2m 30s</span>
            <span>-1m 15s</span>
            <span>Now</span>
          </div>
        </div>

        {/* Network Ingress / Egress Chart */}
        <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-mono text-sm font-bold text-gray-100 uppercase">
                Perimeter Bandwidth &amp; Sensor Load
              </h3>
              <p className="text-xs text-gray-400 font-mono">Core ingress &amp; egress Mbps</p>
            </div>
            <span className="rounded bg-purple-950/80 border border-purple-800 px-2 py-0.5 text-xs font-mono text-purple-300">
              Avg: 140 Mbps
            </span>
          </div>

          <div className="h-36 w-full relative">
            <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} className="h-full w-full overflow-visible">
              <defs>
                <linearGradient id="netGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#a855f7" stopOpacity="0.35" />
                  <stop offset="100%" stopColor="#a855f7" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Grid Lines */}
              <line x1="0" y1="30" x2={chartWidth} y2="30" stroke="#1f293d" strokeDasharray="3,3" />
              <line x1="0" y1="60" x2={chartWidth} y2="60" stroke="#1f293d" strokeDasharray="3,3" />
              <line x1="0" y1="90" x2={chartWidth} y2="90" stroke="#1f293d" strokeDasharray="3,3" />

              {/* Area Fill */}
              {networkPoints && (
                <polygon
                  points={`0,${chartHeight} ${networkPoints} ${chartWidth},${chartHeight}`}
                  fill="url(#netGrad)"
                />
              )}

              {/* Line */}
              {networkPoints && (
                <polyline
                  points={networkPoints}
                  fill="none"
                  stroke="#a855f7"
                  strokeWidth="2.5"
                />
              )}
            </svg>
          </div>

          <div className="mt-2 flex justify-between text-[10px] font-mono text-gray-500">
            <span>-2m 30s</span>
            <span>-1m 15s</span>
            <span>Now</span>
          </div>
        </div>
      </div>

      {/* Sensor Health Table */}
      <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5 shadow-lg">
        <h3 className="font-mono text-sm font-bold text-gray-100 uppercase mb-3 flex items-center gap-2">
          <Server className="h-4 w-4 text-cyan-400" />
          Fleet Sensor Operational Status
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-gray-800 bg-gray-900/60 text-gray-400">
              <tr>
                <th className="p-3">Sensor Agent &amp; Engine</th>
                <th className="p-3">Status</th>
                <th className="p-3">Live EPS</th>
                <th className="p-3">Availability SLA</th>
                <th className="p-3 text-right">Heartbeat</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {sensors.map((s, idx) => (
                <tr key={idx} className="hover:bg-gray-900/30 transition-colors">
                  <td className="p-3 font-semibold text-gray-200">{s.name}</td>
                  <td className="p-3">
                    <span className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[10px] font-bold uppercase border ${
                      s.status === 'online'
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                        : 'bg-amber-950 text-amber-300 border-amber-800'
                    }`}>
                      {s.status === 'online' ? <CheckCircle2 className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
                      {s.status}
                    </span>
                  </td>
                  <td className="p-3 text-cyan-300">{s.eps} events/sec</td>
                  <td className="p-3 text-gray-300">{s.uptime}</td>
                  <td className="p-3 text-right text-gray-400">0.8s ago</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
