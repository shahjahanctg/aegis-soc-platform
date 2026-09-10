import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  Bot, 
  CheckCircle, 
  AlertTriangle, 
  ArrowRight, 
  Terminal, 
  Flag, 
  Sparkles,
  Server,
  Network,
  Clock,
  UserCheck
} from 'lucide-react';
import { Alert, UserSession } from '../../types';
import { api } from '../../services/api';

interface AlertDetailModalProps {
  alert: Alert | null;
  onClose: () => void;
  onUpdateAlert: (updated: Alert) => void;
  onNavigateToCTF: () => void;
  user: UserSession;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({
  alert,
  onClose,
  onUpdateAlert,
  onNavigateToCTF,
  user,
}) => {
  if (!alert) return null;

  const [triageNotes, setTriageNotes] = useState(alert.triage_notes || '');
  const [status, setStatus] = useState(alert.status);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiVerdict, setAiVerdict] = useState(alert.aiVerdict || null);
  const [convertingToCTF, setConvertingToCTF] = useState(false);
  const [ctfSuccessMsg, setCtfSuccessMsg] = useState<string | null>(null);

  const handleSaveTriage = async () => {
    try {
      const updated = await api.triageAlert(alert.id, {
        status,
        triage_notes: triageNotes,
        analyst: user.name,
      });
      onUpdateAlert(updated);
    } catch (err) {
      console.error(err);
    }
  };

  const handleRunAiTriage = async () => {
    setAiLoading(true);
    try {
      const verdict = await api.getAITriage(alert.id);
      setAiVerdict(verdict);
      onUpdateAlert({ ...alert, aiVerdict: verdict });
    } catch (err) {
      console.error(err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleConvertToCTF = async () => {
    setConvertingToCTF(true);
    try {
      const res = await api.convertAlertToCTF(alert.id);
      if (res.success) {
        setCtfSuccessMsg(`Successfully generated CTF Challenge: "${res.challenge.title}" (+${res.challenge.points} pts)!`);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setConvertingToCTF(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'critical':
        return 'bg-rose-950 text-rose-300 border-rose-800';
      case 'high':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'medium':
        return 'bg-cyan-950 text-cyan-300 border-cyan-800';
      default:
        return 'bg-gray-900 text-gray-400 border-gray-800';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-2xl">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute right-5 top-5 rounded-lg p-1.5 text-gray-400 hover:bg-gray-900 hover:text-gray-100 cursor-pointer"
        >
          <X className="h-5 w-5" />
        </button>

        {/* Header section */}
        <div className="flex flex-wrap items-center gap-3 pr-10">
          <span className="font-mono text-xs text-gray-500">{alert.id}</span>
          <span className={`rounded px-2.5 py-0.5 text-xs font-mono font-bold uppercase border ${getSeverityBadge(alert.severity)}`}>
            {alert.severity}
          </span>
          <span className="rounded bg-gray-900 px-2.5 py-0.5 text-xs font-mono text-gray-300 border border-gray-800">
            {alert.source}
          </span>
        </div>

        <h2 className="mt-2 text-xl font-bold text-gray-100">{alert.title}</h2>
        <p className="mt-1 text-sm text-gray-400 leading-relaxed">{alert.description}</p>

        {/* Alert Key Attributes Grid */}
        <div className="mt-5 grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="rounded-xl border border-gray-800/80 bg-gray-900/50 p-3">
            <div className="flex items-center gap-2 text-gray-400 text-xs font-mono mb-1">
              <Server className="h-3.5 w-3.5 text-cyan-400" />
              <span>Target Asset</span>
            </div>
            <p className="text-sm font-mono text-gray-200 truncate">{alert.asset}</p>
          </div>

          <div className="rounded-xl border border-gray-800/80 bg-gray-900/50 p-3">
            <div className="flex items-center gap-2 text-gray-400 text-xs font-mono mb-1">
              <Network className="h-3.5 w-3.5 text-cyan-400" />
              <span>Source &rarr; Destination IP</span>
            </div>
            <p className="text-xs font-mono text-cyan-300 truncate">
              {alert.sourceIp} &rarr; {alert.destIp}
            </p>
          </div>

          <div className="rounded-xl border border-gray-800/80 bg-gray-900/50 p-3">
            <div className="flex items-center gap-2 text-gray-400 text-xs font-mono mb-1">
              <Clock className="h-3.5 w-3.5 text-cyan-400" />
              <span>Detected At</span>
            </div>
            <p className="text-xs font-mono text-gray-300">
              {new Date(alert.created_at).toLocaleString()}
            </p>
          </div>
        </div>

        {/* MITRE ATT&CK Mapping */}
        <div className="mt-4 rounded-xl border border-cyan-900/40 bg-cyan-950/20 p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="rounded bg-cyan-900/80 px-2 py-0.5 text-[11px] font-mono font-bold text-cyan-300 border border-cyan-700">
                MITRE ATT&CK
              </span>
              <span className="text-xs font-mono text-gray-400">Tactic: {alert.mitreTactic}</span>
            </div>
            <span className="text-xs font-mono text-cyan-400">{alert.mitreTechnique}</span>
          </div>
        </div>

        {/* AI Triage Section */}
        <div className="mt-5 rounded-xl border border-purple-900/50 bg-gradient-to-br from-purple-950/30 to-gray-950 p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Bot className="h-5 w-5 text-purple-400" />
              <h4 className="font-mono text-sm font-bold text-purple-300 uppercase">
                AI Automated Triage Assistant
              </h4>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                Gemini 3.8 Flash
              </span>
            </div>
            <button
              onClick={handleRunAiTriage}
              disabled={aiLoading}
              className="flex items-center gap-1.5 rounded-lg bg-purple-600/30 hover:bg-purple-600/50 border border-purple-500/50 px-3 py-1.5 text-xs font-semibold text-purple-200 transition-all cursor-pointer disabled:opacity-50"
            >
              <Sparkles className="h-3.5 w-3.5 text-purple-400 animate-spin" style={{ animationDuration: aiLoading ? '1s' : '0s' }} />
              {aiLoading ? 'Analyzing Telemetry...' : (aiVerdict ? 'Re-run AI Triage' : 'Analyze with AI')}
            </button>
          </div>

          {aiVerdict ? (
            <div className="space-y-2.5 rounded-lg border border-purple-800/40 bg-gray-900/60 p-3.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase border ${
                    aiVerdict.classification === 'TRUE_POSITIVE'
                      ? 'bg-rose-950 text-rose-300 border-rose-800'
                      : aiVerdict.classification === 'FALSE_POSITIVE'
                      ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                      : 'bg-amber-950 text-amber-300 border-amber-800'
                  }`}>
                    {aiVerdict.classification.replace('_', ' ')}
                  </span>
                  <span className="text-xs font-mono text-gray-400">
                    Confidence: <span className="text-cyan-400 font-bold">{aiVerdict.confidence}%</span>
                  </span>
                </div>
              </div>
              <p className="text-xs text-gray-300 leading-relaxed font-sans">
                {aiVerdict.reasoning}
              </p>
              <div className="rounded border border-gray-800 bg-gray-950/80 p-2 text-xs font-mono text-emerald-400">
                <span className="text-gray-400 font-bold block mb-0.5">CONTAINMENT ACTION:</span>
                {aiVerdict.recommendedAction}
              </div>
            </div>
          ) : (
            <p className="text-xs text-gray-400 italic">
              Click &quot;Analyze with AI&quot; to obtain instant True/False Positive classification, MITRE reasoning, and containment recommendations.
            </p>
          )}
        </div>

        {/* Cross-module conversion banner */}
        <div className="mt-5 rounded-xl border border-indigo-900/40 bg-indigo-950/20 p-4">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div>
              <h4 className="flex items-center gap-2 text-xs font-mono font-bold text-indigo-300 uppercase">
                <Flag className="h-4 w-4 text-indigo-400" />
                Cross-Module Workflow: Incident &rarr; Training / CTF
              </h4>
              <p className="text-xs text-gray-400 mt-0.5">
                Convert this live SOC incident into a playable CTF challenge for analyst skill drills.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleConvertToCTF}
                disabled={convertingToCTF}
                className="flex items-center gap-1.5 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/50 border border-indigo-500/50 px-3 py-1.5 text-xs font-semibold text-indigo-200 transition-all cursor-pointer"
              >
                <Flag className="h-3.5 w-3.5 text-indigo-400" />
                {convertingToCTF ? 'Creating Challenge...' : 'Convert to CTF Challenge'}
              </button>
            </div>
          </div>

          {ctfSuccessMsg && (
            <div className="mt-3 flex items-center justify-between rounded-lg bg-indigo-950 border border-indigo-800 p-2.5 text-xs text-indigo-300 font-mono">
              <span>{ctfSuccessMsg}</span>
              <button
                onClick={() => {
                  onClose();
                  onNavigateToCTF();
                }}
                className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 underline font-semibold cursor-pointer"
              >
                Go to CTF Arena &rarr;
              </button>
            </div>
          )}
        </div>

        {/* Analyst Triage Form */}
        <div className="mt-6 border-t border-gray-800 pt-4">
          <h4 className="text-xs font-mono uppercase text-gray-400 mb-3 flex items-center gap-2">
            <UserCheck className="h-4 w-4 text-cyan-400" />
            Analyst Triage &amp; Investigation Notes
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1">Investigation Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as any)}
                className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-xs font-mono text-gray-200 focus:border-cyan-500 focus:outline-none"
              >
                <option value="new">NEW (Unassigned)</option>
                <option value="triaged">TRIAGED (Initial Assessment Done)</option>
                <option value="investigating">INVESTIGATING (Active Containment)</option>
                <option value="resolved">RESOLVED (Threat Remediated)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1">Attributed Analyst</label>
              <input
                type="text"
                disabled
                value={alert.analyst || user.name}
                className="w-full rounded-lg border border-gray-800 bg-gray-900/50 px-3 py-2 text-xs font-mono text-gray-400 cursor-not-allowed"
              />
            </div>
          </div>

          <div className="mt-3">
            <label className="block text-xs font-mono text-gray-400 mb-1">Triage Notes &amp; Remediation Log</label>
            <textarea
              rows={3}
              value={triageNotes}
              onChange={(e) => setTriageNotes(e.target.value)}
              placeholder="Record forensic findings, host isolation status, hash lookups, or escalation steps..."
              className="w-full rounded-lg border border-gray-800 bg-gray-900 p-3 text-xs text-gray-200 placeholder-gray-600 focus:border-cyan-500 focus:outline-none font-mono"
            />
          </div>

          <div className="mt-4 flex items-center justify-end gap-3">
            <button
              onClick={onClose}
              className="rounded-lg border border-gray-800 bg-gray-900 px-4 py-2 text-xs font-mono text-gray-400 hover:bg-gray-800 transition-all cursor-pointer"
            >
              Cancel
            </button>
            <button
              onClick={handleSaveTriage}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-4 py-2 text-xs font-semibold text-gray-950 transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] cursor-pointer"
            >
              <CheckCircle className="h-4 w-4" />
              Save Triage Record
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
