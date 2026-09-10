import React, { useState, useEffect } from 'react';
import { 
  FileSearch, 
  Filter, 
  Search, 
  Terminal, 
  Clock, 
  Hash, 
  Bookmark, 
  BookmarkCheck, 
  Download,
  AlertCircle,
  Cpu,
  Globe,
  Database
} from 'lucide-react';
import { DFIRArtifact } from '../../types';
import { api } from '../../services/api';

export const DFIRTimelineView: React.FC = () => {
  const [artifacts, setArtifacts] = useState<DFIRArtifact[]>([]);
  const [selectedArtifact, setSelectedArtifact] = useState<DFIRArtifact | null>(null);
  const [sourceFilter, setSourceFilter] = useState('all');
  const [tagOnlyEvidence, setTagOnlyEvidence] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    loadArtifacts();
  }, []);

  const loadArtifacts = async () => {
    try {
      const data = await api.getDFIRArtifacts();
      setArtifacts(data || []);
      if (data && data.length > 0) {
        setSelectedArtifact(data[0]);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const toggleEvidenceTag = (id: string) => {
    setArtifacts(prev => prev.map(a => {
      if (a.id === id) {
        const updated = { ...a, isEvidence: !a.isEvidence };
        if (selectedArtifact?.id === id) {
          setSelectedArtifact(updated);
        }
        return updated;
      }
      return a;
    }));
  };

  const filtered = artifacts.filter(a => {
    if (sourceFilter !== 'all' && a.source !== sourceFilter) return false;
    if (tagOnlyEvidence && !a.isEvidence) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        a.description.toLowerCase().includes(q) ||
        a.eventType.toLowerCase().includes(q) ||
        a.host.toLowerCase().includes(q) ||
        (a.hash && a.hash.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const getSourceIcon = (src: string) => {
    switch (src) {
      case 'Sysmon':
        return <Cpu className="h-4 w-4 text-cyan-400" />;
      case 'Zeek':
        return <Globe className="h-4 w-4 text-purple-400" />;
      case 'CrowdStrike':
        return <AlertCircle className="h-4 w-4 text-rose-400" />;
      default:
        return <Database className="h-4 w-4 text-amber-400" />;
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div>
          <h2 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wide flex items-center gap-2">
            <FileSearch className="h-5 w-5 text-emerald-400" />
            Digital Forensics &amp; Incident Investigation Timeline
          </h2>
          <p className="text-xs text-gray-400">
            Microsecond chronological telemetry reconstruction, memory process injection tracing, and evidence locker.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setTagOnlyEvidence(!tagOnlyEvidence)}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-mono transition-all cursor-pointer border ${
              tagOnlyEvidence
                ? 'bg-amber-950 text-amber-300 border-amber-700'
                : 'bg-gray-900 text-gray-400 border-gray-800 hover:text-gray-200'
            }`}
          >
            <BookmarkCheck className="h-3.5 w-3.5" />
            <span>Tagged Evidence Only ({artifacts.filter(a => a.isEvidence).length})</span>
          </button>
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
            placeholder="Search forensic events by description, host, Event ID, or hash..."
            className="w-full bg-transparent text-xs text-gray-200 placeholder-gray-500 focus:outline-none font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-gray-400">Sensor Source:</span>
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="rounded-md border border-gray-800 bg-gray-900 px-2.5 py-1 text-xs font-mono text-gray-200 focus:border-emerald-500 focus:outline-none"
          >
            <option value="all">All Sources</option>
            <option value="Sysmon">Sysmon (Host)</option>
            <option value="Zeek">Zeek (Network Bro)</option>
            <option value="CrowdStrike">CrowdStrike EDR</option>
            <option value="Windows-Security">Windows Security Event Log</option>
          </select>
        </div>
      </div>

      {/* Split Pane: Timeline on left, Forensic Inspector on right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Timeline List */}
        <div className="lg:col-span-7 space-y-2.5 max-h-[600px] overflow-y-auto pr-1">
          {filtered.map((item, index) => {
            const isSelected = selectedArtifact?.id === item.id;

            return (
              <div
                key={item.id}
                onClick={() => setSelectedArtifact(item)}
                className={`relative flex items-start gap-3 rounded-xl border p-4 transition-all cursor-pointer ${
                  isSelected
                    ? 'border-emerald-500/70 bg-gray-900 shadow-md'
                    : 'border-gray-800/80 bg-gray-950/80 hover:bg-gray-900/50'
                }`}
              >
                {/* Timeline connector visual */}
                <div className="flex flex-col items-center">
                  <div className={`flex h-8 w-8 items-center justify-center rounded-lg border ${
                    isSelected ? 'bg-emerald-950 text-emerald-400 border-emerald-700' : 'bg-gray-900 text-gray-400 border-gray-800'
                  }`}>
                    {getSourceIcon(item.source)}
                  </div>
                  {index < filtered.length - 1 && (
                    <div className="w-0.5 h-10 bg-gray-800 my-1" />
                  )}
                </div>

                <div className="flex-1 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-gray-300">{item.eventType}</span>
                    <span className="font-mono text-[10px] text-gray-500 flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  </div>

                  <p className="text-xs text-gray-300 font-sans leading-relaxed">
                    {item.description}
                  </p>

                  <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-[10px]">
                    <span className="rounded bg-gray-900 px-2 py-0.5 text-gray-400 border border-gray-800">
                      Host: {item.host}
                    </span>
                    <span className="rounded bg-gray-900 px-2 py-0.5 text-cyan-400 border border-gray-800">
                      Sensor: {item.source}
                    </span>
                    {item.isEvidence && (
                      <span className="rounded bg-amber-950 px-2 py-0.5 text-amber-300 border border-amber-800 flex items-center gap-1 font-bold">
                        <Bookmark className="h-3 w-3 fill-current" /> EVIDENCE
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Forensic Artifact Deep Inspector (Right Column) */}
        <div className="lg:col-span-5">
          {selectedArtifact ? (
            <div className="sticky top-4 rounded-2xl border border-gray-800 bg-gray-950 p-5 shadow-2xl space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                <div>
                  <span className="text-gray-500 text-[10px]">ARTIFACT ID: {selectedArtifact.id}</span>
                  <h3 className="text-sm font-bold text-emerald-400 mt-0.5">{selectedArtifact.eventType}</h3>
                </div>
                <button
                  onClick={() => toggleEvidenceTag(selectedArtifact.id)}
                  className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs transition-all cursor-pointer ${
                    selectedArtifact.isEvidence
                      ? 'bg-amber-950 text-amber-300 border border-amber-700'
                      : 'bg-gray-900 text-gray-400 border border-gray-800 hover:text-gray-200'
                  }`}
                >
                  <Bookmark className={`h-3.5 w-3.5 ${selectedArtifact.isEvidence ? 'fill-current' : ''}`} />
                  {selectedArtifact.isEvidence ? 'Tagged as Evidence' : 'Tag as Evidence'}
                </button>
              </div>

              <div>
                <span className="text-gray-400 block mb-1 uppercase text-[10px]">Description &amp; Event Context</span>
                <p className="font-sans text-xs text-gray-200 bg-gray-900/60 p-3 rounded-lg border border-gray-800">
                  {selectedArtifact.description}
                </p>
              </div>

              {selectedArtifact.hash && (
                <div>
                  <span className="text-gray-400 block mb-1 uppercase text-[10px] flex items-center gap-1">
                    <Hash className="h-3.5 w-3.5 text-cyan-400" /> SHA-256 Checksum
                  </span>
                  <div className="bg-gray-900 p-2.5 rounded-lg border border-gray-800 text-[11px] text-cyan-300 break-all select-all">
                    {selectedArtifact.hash}
                  </div>
                </div>
              )}

              <div>
                <span className="text-gray-400 block mb-1 uppercase text-[10px] flex items-center gap-1">
                  <Terminal className="h-3.5 w-3.5 text-emerald-400" /> Raw Hex / Syslog Payload
                </span>
                <div className="max-h-48 overflow-y-auto bg-gray-900/90 p-3 rounded-lg border border-gray-800 text-[10px] text-emerald-400 leading-tight">
                  <pre className="whitespace-pre-wrap">{selectedArtifact.rawPayload}</pre>
                </div>
              </div>

              <div className="pt-2 border-t border-gray-800 flex justify-between text-[10px] text-gray-500">
                <span>Timestamp: {selectedArtifact.timestamp}</span>
                <span>Host: {selectedArtifact.host}</span>
              </div>
            </div>
          ) : (
            <div className="rounded-2xl border border-gray-800 bg-gray-950 p-8 text-center text-gray-500 font-mono text-xs">
              Select an artifact from the timeline to inspect raw hex dump and hash attribution.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
