import React, { useState } from 'react';
import { Flame, ShieldAlert, Cpu, Database, Skull, X, CheckCircle } from 'lucide-react';
import { api } from '../../services/api';
import { Alert } from '../../types';

interface IncidentSimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onIncidentInjected: (newAlert: Alert) => void;
}

export const IncidentSimulatorModal: React.FC<IncidentSimulatorModalProps> = ({
  isOpen,
  onClose,
  onIncidentInjected,
}) => {
  const [loading, setLoading] = useState(false);
  const [lastResult, setLastResult] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleInject = async (scenario: 'ransomware' | 'beacon' | 'sqli') => {
    setLoading(true);
    setLastResult(null);
    try {
      const res = await api.injectSimulation(scenario);
      if (res.success && res.alert) {
        onIncidentInjected(res.alert);
        setLastResult(`Injected: ${res.alert.title}`);
        setTimeout(() => {
          onClose();
        }, 1200);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-lg rounded-2xl border border-amber-500/30 bg-gray-950 p-6 shadow-[0_0_40px_rgba(245,158,11,0.15)]">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 rounded-lg p-1.5 text-gray-400 hover:bg-gray-900 hover:text-gray-200 cursor-pointer"
        >
          <X className="h-5 w-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
            <Flame className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wide">
              Adversary Attack Simulator
            </h3>
            <p className="text-xs text-gray-400">
              Inject synthetic attack telemetry to test SOC alerts, AI triage, and CTF conversion workflows.
            </p>
          </div>
        </div>

        {lastResult && (
          <div className="mb-4 flex items-center gap-2 rounded-lg bg-emerald-950/60 border border-emerald-800/80 p-3 text-xs text-emerald-300">
            <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0" />
            <span className="font-mono">{lastResult}</span>
          </div>
        )}

        <div className="space-y-3">
          <div
            onClick={() => !loading && handleInject('ransomware')}
            className="group flex items-start gap-4 rounded-xl border border-gray-800 bg-gray-900/50 p-4 transition-all hover:border-rose-500/50 hover:bg-rose-950/20 cursor-pointer"
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/30 group-hover:scale-105 transition-transform">
              <Skull className="h-5 w-5" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold text-rose-300">Ransomware Detonation Drill</span>
                <span className="rounded bg-rose-950 px-2 py-0.5 text-[10px] font-mono font-bold text-rose-300 border border-rose-800">CRITICAL</span>
              </div>
              <p className="mt-1 text-xs text-gray-400">
                Simulates volume shadow copy wipe (`vssadmin delete shadows`) and rapid file extension renaming across corporate file share.
              </p>
            </div>
          </div>

          <div
            onClick={() => !loading && handleInject('beacon')}
            className="group flex items-start gap-4 rounded-xl border border-gray-800 bg-gray-900/50 p-4 transition-all hover:border-amber-500/50 hover:bg-amber-950/20 cursor-pointer"
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/30 group-hover:scale-105 transition-transform">
              <Cpu className="h-5 w-5" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold text-amber-300">Cobalt Strike / Mythic C2 Beacon</span>
                <span className="rounded bg-amber-950 px-2 py-0.5 text-[10px] font-mono font-bold text-amber-300 border border-amber-800">HIGH</span>
              </div>
              <p className="mt-1 text-xs text-gray-400">
                Periodic HTTPS egress beaconing with jitter, invoking unusual parent-child process memory injection.
              </p>
            </div>
          </div>

          <div
            onClick={() => !loading && handleInject('sqli')}
            className="group flex items-start gap-4 rounded-xl border border-gray-800 bg-gray-900/50 p-4 transition-all hover:border-cyan-500/50 hover:bg-cyan-950/20 cursor-pointer"
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 group-hover:scale-105 transition-transform">
              <Database className="h-5 w-5" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold text-cyan-300">Web AppSec Blind SQLi Probe</span>
                <span className="rounded bg-cyan-950 px-2 py-0.5 text-[10px] font-mono font-bold text-cyan-300 border border-cyan-800">MEDIUM</span>
              </div>
              <p className="mt-1 text-xs text-gray-400">
                WAF detects UNION SELECT SQL injection vectors and SSRF metadata exploitation attempts.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-5 flex justify-end">
          <button
            onClick={onClose}
            className="rounded-lg border border-gray-800 bg-gray-900 px-4 py-2 text-xs font-mono text-gray-300 hover:bg-gray-800 transition-all cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};
