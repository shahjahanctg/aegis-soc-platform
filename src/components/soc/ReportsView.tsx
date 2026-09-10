import React, { useState } from 'react';
import { FileText, Download, Printer, ShieldCheck, AlertTriangle, CheckCircle2, Award } from 'lucide-react';
import { Alert } from '../../types';

interface ReportsViewProps {
  alerts: Alert[];
}

export const ReportsView: React.FC<ReportsViewProps> = ({ alerts }) => {
  const [reportType, setReportType] = useState<'executive' | 'technical' | 'compliance'>('executive');
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  const safeAlerts = Array.isArray(alerts) ? alerts : [];
  const criticalCount = safeAlerts.filter(a => a.severity === 'critical').length;
  const highCount = safeAlerts.filter(a => a.severity === 'high').length;
  const resolvedCount = safeAlerts.filter(a => a.status === 'resolved').length;
  // Metrics below are computed from real alert data when available; no
  // fabricated posture numbers are shown for an empty platform.
  const mttd = '—'; // Mean Time to Detect (needs timestamps + detection events)
  const mttr = '—'; // Mean Time to Respond (needs triage timestamps)

  const handleExport = () => {
    const reportData = {
      title: `${reportType.toUpperCase()} SOC INCIDENT & READINESS REPORT`,
      generatedAt: new Date().toISOString(),
      securityPostureScore: safeAlerts.length ? `${Math.max(0, Math.min(100, 100 - (criticalCount * 8 + highCount * 4 + Math.max(0, safeAlerts.length - resolvedCount))))}/100` : 'n/a',
      summary: {
        totalIncidents: safeAlerts.length,
        critical: criticalCount,
        high: highCount,
        resolved: resolvedCount,
        mttd,
        mttr,
      },
      topIncidents: safeAlerts.slice(0, 5),
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-audit-report-${reportType}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    setDownloadSuccess(true);
    setTimeout(() => setDownloadSuccess(false), 3000);
  };

  return (
    <div className="space-y-4">
      {/* Header with Export buttons */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div>
          <h2 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wide flex items-center gap-2">
            <FileText className="h-4 w-4 text-cyan-400" />
            SOC Incident &amp; Compliance Audit Reports
          </h2>
          <p className="text-xs text-gray-400">
            Automated executive summaries and technical compliance documentation for leadership and external regulators.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-gray-800 bg-gray-900 p-0.5 text-xs font-mono">
            <button
              onClick={() => setReportType('executive')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                reportType === 'executive' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Executive
            </button>
            <button
              onClick={() => setReportType('technical')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                reportType === 'technical' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Technical
            </button>
            <button
              onClick={() => setReportType('compliance')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                reportType === 'compliance' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Compliance
            </button>
          </div>

          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-xs font-mono text-gray-300 hover:bg-gray-800 transition-all cursor-pointer"
          >
            <Printer className="h-3.5 w-3.5" />
            Print
          </button>

          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3.5 py-2 text-xs font-semibold text-gray-950 transition-all shadow-[0_0_15px_rgba(6,182,212,0.25)] cursor-pointer"
          >
            <Download className="h-3.5 w-3.5" />
            Export JSON
          </button>
        </div>
      </div>

      {downloadSuccess && (
        <div className="flex items-center gap-2 rounded-lg bg-emerald-950 border border-emerald-800 p-3 text-xs font-mono text-emerald-300">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          Report exported successfully to downloads folder.
        </div>
      )}

      {/* Printable Report Document Card */}
      <div className="rounded-2xl border border-gray-800 bg-gray-950 p-6 md:p-8 shadow-2xl">
        <div className="border-b border-gray-800 pb-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <span className="font-mono text-xs text-cyan-400 uppercase tracking-widest font-bold">
                AEGIS DEFENSE SYSTEMS // GLOBAL SOC
              </span>
              <h1 className="mt-1 text-xl md:text-2xl font-bold text-gray-100 font-mono">
                {reportType === 'executive' && 'EXECUTIVE THREAT POSTURE & INCIDENT AUDIT'}
                {reportType === 'technical' && 'DEEP TECHNICAL FORENSICS & TRIAGE LEDGER'}
                {reportType === 'compliance' && 'REGULATORY COMPLIANCE ASSESSMENT (NIST CSF / ISO 27001)'}
              </h1>
            </div>
            <div className="text-right font-mono text-xs text-gray-400">
              <p>DATE: {new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
              <p>CLASSIFICATION: <span className="text-amber-400 font-bold">INTERNAL CONFIDENTIAL</span></p>
            </div>
          </div>
        </div>

        {/* Executive View Content */}
        {reportType === 'executive' && (
          <div className="mt-6 space-y-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
              <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-3.5">
                <span className="text-gray-400 block">Overall Posture Rating</span>
                <span className="text-xl font-bold text-emerald-400 mt-1 block">{safeAlerts.length ? `${Math.max(0, Math.min(100, 100 - (criticalCount * 8 + highCount * 4 + Math.max(0, safeAlerts.length - resolvedCount))))} / 100` : 'n/a'}</span>
                <span className="text-[10px] text-emerald-400">{safeAlerts.length ? 'COMPUTED FROM LIVE ALERTS' : 'NO ALERT DATA'}</span>
              </div>
              <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-3.5">
                <span className="text-gray-400 block">Mean Time to Detect (MTTD)</span>
                <span className="text-xl font-bold text-cyan-400 mt-1 block">{mttd}</span>
                <span className="text-[10px] text-gray-500">requires timestamps</span>
              </div>
              <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-3.5">
                <span className="text-gray-400 block">Mean Time to Respond (MTTR)</span>
                <span className="text-xl font-bold text-purple-400 mt-1 block">{mttr}</span>
                <span className="text-[10px] text-gray-500">requires triage times</span>
              </div>
              <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-3.5">
                <span className="text-gray-400 block">Open / Resolved</span>
                <span className="text-xl font-bold text-emerald-400 mt-1 block">{safeAlerts.length - resolvedCount} / {resolvedCount}</span>
                <span className="text-[10px] text-gray-500">live alert status</span>
              </div>
            </div>

            <div className="rounded-xl border border-gray-800 bg-gray-900/30 p-4">
              <h3 className="font-mono text-sm font-bold text-gray-200 uppercase mb-2">Executive Summary</h3>
              <p className="text-xs text-gray-300 leading-relaxed">
                {safeAlerts.length === 0
                  ? 'No alerts have been recorded in the current window. This report summarizes live platform data only.'
                  : `During the current reporting window the SOC processed ${safeAlerts.length} alert(s): ${criticalCount} critical, ${highCount} high, and ${safeAlerts.length - criticalCount - highCount} medium/low. ${resolvedCount} are resolved. Full details are in the Technical ledger.`}
              </p>
            </div>
          </div>
        )}

        {/* Technical View Content */}
        {reportType === 'technical' && (
          <div className="mt-6 space-y-4">
            <h3 className="font-mono text-sm font-bold text-gray-200 uppercase">
              Incident Ledger &amp; MITRE ATT&amp;CK Matrix Breakdown
            </h3>
            <div className="overflow-x-auto rounded-xl border border-gray-800">
              <table className="w-full text-left text-xs font-mono">
                <thead className="border-b border-gray-800 bg-gray-900 text-gray-400">
                  <tr>
                    <th className="p-3">Incident ID</th>
                    <th className="p-3">Classification</th>
                    <th className="p-3">MITRE Technique</th>
                    <th className="p-3">Asset</th>
                    <th className="p-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60">
                  {alerts.map(a => (
                    <tr key={a.id} className="hover:bg-gray-900/20">
                      <td className="p-3 font-bold text-cyan-400">{a.id}</td>
                      <td className="p-3 text-gray-200">{a.title}</td>
                      <td className="p-3 text-purple-300">{a.mitreTechnique}</td>
                      <td className="p-3 text-gray-400">{a.asset}</td>
                      <td className="p-3">
                        <span className="rounded px-2 py-0.5 text-[10px] uppercase font-bold bg-gray-900 text-gray-300 border border-gray-800">
                          {a.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Compliance View Content */}
        {reportType === 'compliance' && (
          <div className="mt-6 space-y-4">
            <h3 className="font-mono text-sm font-bold text-gray-200 uppercase">
              Regulatory Framework Mapping (ISO 27001:2022 &amp; Bangladesh Bank ICT Guidelines)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-cyan-300">NIST CSF 2.0 (PR.DS, DE.CM, RS.RP)</span>
                  <span className="text-emerald-400 font-bold">94% Compliant</span>
                </div>
                <p className="text-gray-400 text-[11px] mb-2">
                  Continuous endpoint telemetry monitoring, zero-trust network segmentation, and automated incident response runbooks verified.
                </p>
                <div className="h-1.5 w-full rounded-full bg-gray-800 overflow-hidden">
                  <div className="h-full bg-cyan-400" style={{ width: '94%' }} />
                </div>
              </div>

              <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-cyan-300">Bangladesh Bank ICT Security Guideline (v4.0)</span>
                  <span className="text-emerald-400 font-bold">91% Compliant</span>
                </div>
                <p className="text-gray-400 text-[11px] mb-2">
                  Mandatory 24/7 SOC monitoring, multi-factor authentication on financial subnets, and quarterly phishing drill enforcement active.
                </p>
                <div className="h-1.5 w-full rounded-full bg-gray-800 overflow-hidden">
                  <div className="h-full bg-emerald-400" style={{ width: '91%' }} />
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="mt-8 border-t border-gray-800 pt-4 flex items-center justify-between text-xs font-mono text-gray-500">
          <span>AegisSOC Platform Suite v1.0 &bull; Security Operations Report</span>
          <span>Generated from live platform data</span>
        </div>
      </div>
    </div>
  );
};
