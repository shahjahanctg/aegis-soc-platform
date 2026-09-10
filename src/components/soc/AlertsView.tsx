import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  ArrowUpRight, 
  CheckCircle2, 
  AlertCircle, 
  Radio, 
  Clock,
  Sparkles,
  ChevronRight
} from 'lucide-react';
import { Alert } from '../../types';

interface AlertsViewProps {
  alerts: Alert[];
  onSelectAlert: (alert: Alert) => void;
  onQuickTriage: (alertId: string, newStatus: 'investigating' | 'resolved') => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  onSelectAlert,
  onQuickTriage,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const safeAlerts = Array.isArray(alerts) ? alerts : [];

  const filteredAlerts = safeAlerts.filter(a => {
    if (severityFilter !== 'all' && a.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && a.status !== statusFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        a.title.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        a.sourceIp.includes(q) ||
        a.destIp.includes(q) ||
        a.mitreTechnique.toLowerCase().includes(q) ||
        a.asset.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const stats = {
    total: safeAlerts.length,
    critical: safeAlerts.filter(a => a.severity === 'critical').length,
    high: safeAlerts.filter(a => a.severity === 'high').length,
    medium: safeAlerts.filter(a => a.severity === 'medium').length,
    resolved: safeAlerts.filter(a => a.status === 'resolved').length,
  };

  const getSeverityPill = (sev: string) => {
    switch (sev) {
      case 'critical':
        return 'bg-rose-950 text-rose-300 border-rose-800 animate-pulse';
      case 'high':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'medium':
        return 'bg-cyan-950 text-cyan-300 border-cyan-800';
      default:
        return 'bg-gray-900 text-gray-400 border-gray-800';
    }
  };

  const getStatusPill = (st: string) => {
    switch (st) {
      case 'new':
        return 'bg-blue-950 text-blue-300 border-blue-800';
      case 'investigating':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'triaged':
        return 'bg-purple-950 text-purple-300 border-purple-800';
      case 'resolved':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      default:
        return 'bg-gray-900 text-gray-400 border-gray-800';
    }
  };

  return (
    <div className="space-y-4">
      {/* Metric Stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-3.5">
          <span className="text-[11px] font-mono text-gray-400 uppercase">Total Ingestion</span>
          <p className="mt-1 text-2xl font-mono font-bold text-gray-100">{stats.total}</p>
          <div className="mt-1 text-[10px] font-mono text-cyan-400 flex items-center gap-1">
            <Radio className="h-3 w-3 animate-pulse text-emerald-400" /> Active Feed
          </div>
        </div>

        <div className="rounded-xl border border-rose-900/40 bg-rose-950/20 p-3.5">
          <span className="text-[11px] font-mono text-rose-400 uppercase">Critical Severity</span>
          <p className="mt-1 text-2xl font-mono font-bold text-rose-300">{stats.critical}</p>
          <span className="text-[10px] font-mono text-rose-400/80">Immediate Action Required</span>
        </div>

        <div className="rounded-xl border border-amber-900/40 bg-amber-950/20 p-3.5">
          <span className="text-[11px] font-mono text-amber-400 uppercase">High Severity</span>
          <p className="mt-1 text-2xl font-mono font-bold text-amber-300">{stats.high}</p>
          <span className="text-[10px] font-mono text-amber-400/80">Active Containment</span>
        </div>

        <div className="rounded-xl border border-cyan-900/40 bg-cyan-950/20 p-3.5">
          <span className="text-[11px] font-mono text-cyan-400 uppercase">Medium Severity</span>
          <p className="mt-1 text-2xl font-mono font-bold text-cyan-300">{stats.medium}</p>
          <span className="text-[10px] font-mono text-cyan-400/80">Under Monitoring</span>
        </div>

        <div className="rounded-xl border border-emerald-900/40 bg-emerald-950/20 p-3.5 col-span-2 sm:col-span-1">
          <span className="text-[11px] font-mono text-emerald-400 uppercase">Remediated / Closed</span>
          <p className="mt-1 text-2xl font-mono font-bold text-emerald-300">{stats.resolved}</p>
          <span className="text-[10px] font-mono text-emerald-400/80">Threat Neutralized</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-gray-800 bg-gray-950 p-3">
        <div className="flex flex-1 items-center gap-2 min-w-[240px] rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5">
          <Search className="h-4 w-4 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search alerts by title, IP, asset, or MITRE technique..."
            className="w-full bg-transparent text-xs text-gray-200 placeholder-gray-500 focus:outline-none font-mono"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 text-xs font-mono text-gray-400">
            <Filter className="h-3.5 w-3.5" />
            <span>Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-md border border-gray-800 bg-gray-900 px-2.5 py-1 text-xs font-mono text-gray-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 text-xs font-mono text-gray-400">
            <span>Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-md border border-gray-800 bg-gray-900 px-2.5 py-1 text-xs font-mono text-gray-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="triaged">Triaged</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alert Cards List */}
      <div className="space-y-2.5">
        {filteredAlerts.length === 0 ? (
          <div className="rounded-xl border border-gray-800 bg-gray-950 p-8 text-center">
            <ShieldAlert className="mx-auto h-8 w-8 text-gray-600 mb-2" />
            <p className="text-sm font-mono text-gray-400">No alerts match current search filter criteria.</p>
          </div>
        ) : (
          filteredAlerts.map(alert => (
            <div
              key={alert.id}
              onClick={() => onSelectAlert(alert)}
              className="group relative flex flex-col md:flex-row md:items-center justify-between gap-4 rounded-xl border border-gray-800/80 bg-gray-950/80 p-4 transition-all hover:border-cyan-500/50 hover:bg-gray-900/60 shadow-sm cursor-pointer"
            >
              <div className="flex-1 space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-gray-500 font-bold">{alert.id}</span>
                  <span className={`rounded px-2 py-0.2 text-[10px] font-mono font-bold uppercase border ${getSeverityPill(alert.severity)}`}>
                    {alert.severity}
                  </span>
                  <span className={`rounded px-2 py-0.2 text-[10px] font-mono font-semibold uppercase border ${getStatusPill(alert.status)}`}>
                    {alert.status}
                  </span>
                  <span className="text-xs font-mono text-gray-400 truncate max-w-xs">
                    &bull; {alert.source}
                  </span>
                </div>

                <h3 className="text-sm font-semibold text-gray-100 group-hover:text-cyan-300 transition-colors">
                  {alert.title}
                </h3>

                <p className="text-xs text-gray-400 line-clamp-1">
                  {alert.description}
                </p>

                <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] font-mono text-gray-400">
                  <span className="text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-900/50">
                    {alert.mitreTechnique}
                  </span>
                  <span>Asset: <strong className="text-gray-300">{alert.asset}</strong></span>
                  <span>Flow: <code className="text-gray-300">{alert.sourceIp} &rarr; {alert.destIp}</code></span>
                  <span className="flex items-center gap-1 text-gray-500">
                    <Clock className="h-3 w-3" />
                    {new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              </div>

              {/* Action buttons */}
              <div className="flex items-center gap-2 self-end md:self-center shrink-0">
                {alert.aiVerdict && (
                  <span className="flex items-center gap-1 rounded bg-purple-950/80 px-2 py-1 text-[10px] font-mono font-bold text-purple-300 border border-purple-800">
                    <Sparkles className="h-3 w-3 text-purple-400" />
                    AI: {alert.aiVerdict.classification.replace('_', ' ')}
                  </span>
                )}

                {alert.status !== 'resolved' ? (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onQuickTriage(alert.id, 'resolved');
                    }}
                    className="flex items-center gap-1 rounded-lg border border-emerald-800/80 bg-emerald-950/40 px-2.5 py-1.5 text-xs font-mono text-emerald-300 hover:bg-emerald-900/60 transition-all cursor-pointer"
                    title="Quick Resolve"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    <span className="hidden sm:inline">Resolve</span>
                  </button>
                ) : (
                  <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="h-4 w-4" /> Remediated
                  </span>
                )}

                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gray-900 text-gray-400 group-hover:bg-cyan-500 group-hover:text-gray-950 transition-all">
                  <ChevronRight className="h-4 w-4" />
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
