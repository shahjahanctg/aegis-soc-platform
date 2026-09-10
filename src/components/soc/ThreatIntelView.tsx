import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Ban, 
  Plus, 
  Search, 
  Globe, 
  Hash, 
  Link, 
  Server,
  AlertTriangle,
  CheckCircle2,
  X
} from 'lucide-react';
import { IOC } from '../../types';

interface ThreatIntelViewProps {
  iocs: IOC[];
  onToggleBlock: (id: string) => void;
  onAddIOC: (newIoc: Partial<IOC>) => void;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({
  iocs,
  onToggleBlock,
  onAddIOC,
}) => {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  // Add IOC form state
  const [newType, setNewType] = useState<'ip' | 'domain' | 'sha256' | 'url'>('ip');
  const [newValue, setNewValue] = useState('');
  const [newGroup, setNewGroup] = useState('');
  const [newCategory, setNewCategory] = useState('Command & Control');
  const [newDesc, setNewDesc] = useState('');

  const safeIocs = Array.isArray(iocs) ? iocs : [];

  const filtered = safeIocs.filter(ioc => {
    if (typeFilter !== 'all' && ioc.type !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        ioc.value.toLowerCase().includes(q) ||
        ioc.threatGroup.toLowerCase().includes(q) ||
        ioc.category.toLowerCase().includes(q) ||
        ioc.description.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newValue) return;
    onAddIOC({
      type: newType,
      value: newValue,
      threatGroup: newGroup || 'Unknown APT',
      category: newCategory,
      description: newDesc || 'Analyst identified indicator',
    });
    setNewValue('');
    setNewGroup('');
    setNewDesc('');
    setIsAddModalOpen(false);
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ip':
        return <Server className="h-4 w-4 text-cyan-400" />;
      case 'domain':
        return <Globe className="h-4 w-4 text-purple-400" />;
      case 'sha256':
        return <Hash className="h-4 w-4 text-amber-400" />;
      default:
        return <Link className="h-4 w-4 text-emerald-400" />;
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Banner & Action */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div>
          <h2 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wide">
            Threat Intelligence &amp; IOC Feed
          </h2>
          <p className="text-xs text-gray-400">
            Real-time Indicators of Compromise correlated against global C2 telemetry, ransomware signatures, and threat actors.
          </p>
        </div>

        <button
          onClick={() => setIsAddModalOpen(true)}
          className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3.5 py-2 text-xs font-semibold text-gray-950 transition-all shadow-[0_0_15px_rgba(6,182,212,0.25)] cursor-pointer"
        >
          <Plus className="h-4 w-4" />
          Add Indicator
        </button>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-gray-800 bg-gray-950 p-3">
        <div className="flex flex-1 items-center gap-2 min-w-[240px] rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5">
          <Search className="h-4 w-4 text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search indicator by value, APT group, or category..."
            className="w-full bg-transparent text-xs text-gray-200 placeholder-gray-500 focus:outline-none font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-gray-400">Filter Type:</span>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="rounded-md border border-gray-800 bg-gray-900 px-2.5 py-1 text-xs font-mono text-gray-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="all">All Types</option>
            <option value="ip">IP Address</option>
            <option value="domain">Domain Name</option>
            <option value="sha256">File Hash (SHA-256)</option>
            <option value="url">Malicious URL</option>
          </select>
        </div>
      </div>

      {/* IOC Table */}
      <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-950">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-gray-800 bg-gray-900/60 text-gray-400 font-mono">
            <tr>
              <th className="p-3">Type &amp; Value</th>
              <th className="p-3">Attributed Threat Group</th>
              <th className="p-3">Category</th>
              <th className="p-3">Confidence</th>
              <th className="p-3">First Seen</th>
              <th className="p-3 text-right">Perimeter Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60 font-mono">
            {filtered.map(ioc => (
              <tr key={ioc.id} className="hover:bg-gray-900/40 transition-colors">
                <td className="p-3">
                  <div className="flex items-center gap-2">
                    <div className="flex h-7 w-7 items-center justify-center rounded bg-gray-900 border border-gray-800">
                      {getTypeIcon(ioc.type)}
                    </div>
                    <div>
                      <p className="font-semibold text-gray-200">{ioc.value}</p>
                      <p className="text-[10px] text-gray-500">{ioc.description}</p>
                    </div>
                  </div>
                </td>
                <td className="p-3 text-purple-300 font-medium">{ioc.threatGroup}</td>
                <td className="p-3">
                  <span className="rounded bg-gray-900 px-2 py-0.5 text-[10px] text-cyan-300 border border-gray-800">
                    {ioc.category}
                  </span>
                </td>
                <td className="p-3">
                  <div className="flex items-center gap-1.5">
                    <div className="h-1.5 w-12 rounded-full bg-gray-800 overflow-hidden">
                      <div 
                        className="h-full bg-cyan-400" 
                        style={{ width: `${ioc.confidence}%` }}
                      />
                    </div>
                    <span className="text-[11px] text-gray-300 font-bold">{ioc.confidence}%</span>
                  </div>
                </td>
                <td className="p-3 text-gray-400">{ioc.firstSeen}</td>
                <td className="p-3 text-right">
                  <button
                    onClick={() => onToggleBlock(ioc.id)}
                    className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-semibold transition-all cursor-pointer ${
                      ioc.blocked
                        ? 'bg-rose-950/80 text-rose-300 border border-rose-800 hover:bg-rose-900'
                        : 'bg-gray-900 text-gray-400 border border-gray-800 hover:bg-gray-800 hover:text-gray-200'
                    }`}
                  >
                    {ioc.blocked ? (
                      <>
                        <Ban className="h-3.5 w-3.5 text-rose-400" />
                        <span>BLOCKED</span>
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="h-3.5 w-3.5 text-gray-400" />
                        <span>ALLOW (MONITOR)</span>
                      </>
                    )}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Add IOC Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-md rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-2xl">
            <button
              onClick={() => setIsAddModalOpen(false)}
              className="absolute right-4 top-4 rounded-lg p-1.5 text-gray-400 hover:bg-gray-900 hover:text-gray-200 cursor-pointer"
            >
              <X className="h-5 w-5" />
            </button>

            <h3 className="font-mono text-base font-bold text-gray-100 uppercase mb-4">
              Add New Indicator of Compromise
            </h3>

            <form onSubmit={handleCreate} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-gray-400 mb-1">Indicator Type</label>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value as any)}
                  className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-200 focus:border-cyan-500 focus:outline-none"
                >
                  <option value="ip">IP Address</option>
                  <option value="domain">Domain</option>
                  <option value="sha256">SHA-256 Hash</option>
                  <option value="url">URL</option>
                </select>
              </div>

              <div>
                <label className="block text-gray-400 mb-1">Indicator Value</label>
                <input
                  type="text"
                  required
                  value={newValue}
                  onChange={(e) => setNewValue(e.target.value)}
                  placeholder="e.g. 198.51.100.44 or malware.exe hash"
                  className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-gray-400 mb-1">Threat Group / Attribution</label>
                <input
                  type="text"
                  value={newGroup}
                  onChange={(e) => setNewGroup(e.target.value)}
                  placeholder="e.g. APT28, Lazarus, FIN7"
                  className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-gray-400 mb-1">Threat Category</label>
                <select
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value)}
                  className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-200 focus:border-cyan-500 focus:outline-none"
                >
                  <option value="Command & Control">Command &amp; Control</option>
                  <option value="Ransomware">Ransomware Loader</option>
                  <option value="Credential Phishing">Credential Phishing</option>
                  <option value="Data Exfiltration">Data Exfiltration</option>
                  <option value="Reconnaissance">Reconnaissance</option>
                </select>
              </div>

              <div>
                <label className="block text-gray-400 mb-1">Analyst Context / Description</label>
                <textarea
                  rows={2}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Notes about observed traffic or sandbox analysis..."
                  className="w-full rounded-lg border border-gray-800 bg-gray-900 p-2.5 text-gray-200 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-1.5 text-gray-400 hover:bg-gray-800 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-cyan-600 hover:bg-cyan-500 px-4 py-1.5 font-semibold text-gray-950 cursor-pointer"
                >
                  Save &amp; Block
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
