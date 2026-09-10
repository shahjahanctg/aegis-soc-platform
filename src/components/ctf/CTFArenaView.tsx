import React, { useState, useEffect } from 'react';
import { 
  Flag, 
  Terminal as TerminalIcon, 
  Trophy, 
  CheckCircle2, 
  HelpCircle, 
  Search, 
  Flame, 
  X, 
  AlertCircle,
  ExternalLink,
  Shield
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { CTFChallenge, LeaderboardEntry, UserSession } from '../../types';
import { api } from '../../services/api';

interface CTFArenaViewProps {
  user: UserSession;
  onPointsUpdate: (newScore: number) => void;
}

export const CTFArenaView: React.FC<CTFArenaViewProps> = ({ user, onPointsUpdate }) => {
  const [challenges, setChallenges] = useState<CTFChallenge[]>([]);
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [activeTab, setActiveTab] = useState<'challenges' | 'leaderboard'>('challenges');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [selectedChallenge, setSelectedChallenge] = useState<CTFChallenge | null>(null);

  // Challenge modal state
  const [flagInput, setFlagInput] = useState('');
  const [flagStatus, setFlagStatus] = useState<'idle' | 'success' | 'incorrect'>('idle');
  const [flagMessage, setFlagMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [revealedHint, setRevealedHint] = useState<string | null>(null);

  // Terminal simulator state inside modal
  const [terminalInput, setTerminalInput] = useState('');
  const [terminalHistory, setTerminalHistory] = useState<string[]>([
    'CyberSandbox VM v2.4 (Linux x86_64)',
    'Type `help` for available forensic commands (strings, curl, base64, grep, cat)...',
  ]);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [cData, lData] = await Promise.all([
        api.getCTFChallenges(),
        api.getLeaderboard(),
      ]);
      setChallenges(cData || []);
      setLeaderboard(lData || []);
    } catch (err) {
      console.error(err);
    }
  };

  const handleOpenChallenge = (c: CTFChallenge) => {
    setSelectedChallenge(c);
    setFlagInput('');
    setFlagStatus('idle');
    setFlagMessage('');
    setRevealedHint(null);
    setTerminalHistory([
      `Target host initialized for: ${c.title}`,
      `Payload file mounted at /artifacts/evidence.raw`,
      `Type 'strings evidence.raw' or 'base64 -d' to examine artifacts...`,
    ]);
  };

  const handleSubmitFlag = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedChallenge || !flagInput.trim()) return;

    setIsSubmitting(true);
    try {
      const res = await api.submitFlag(selectedChallenge.id, flagInput.trim(), user.name);
      if (res.success) {
        setFlagStatus('success');
        setFlagMessage(res.message);
        onPointsUpdate(res.newScore || user.score + selectedChallenge.points);
        selectedChallenge.solved = true;

        confetti({
          particleCount: 80,
          spread: 70,
          origin: { y: 0.6 }
        });

        loadData();
      } else {
        setFlagStatus('incorrect');
        setFlagMessage(res.message);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTerminalCommand = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      const cmd = terminalInput.trim();
      if (!cmd) return;

      const newHistory = [...terminalHistory, `$ ${cmd}`];

      if (cmd === 'clear') {
        setTerminalHistory([]);
        setTerminalInput('');
        return;
      } else if (cmd === 'help') {
        newHistory.push(
          'Available commands: ls, cat evidence.raw, strings evidence.raw, base64 -d, grep, id, whoami, clear'
        );
      } else if (cmd === 'ls') {
        newHistory.push('evidence.raw   pcap_dump.pcap   malware_hash.txt');
      } else if (cmd.startsWith('strings')) {
        if (selectedChallenge?.category === 'Forensics') {
          newHistory.push('... vssadmin delete shadows /all /quiet');
          newHistory.push('FLAG{SHADOW_COPIES_ANNIHILATED_2026}');
        } else if (selectedChallenge?.category === 'Web AppSec') {
          newHistory.push('... UNION SELECT 1, column_name FROM information_schema.columns');
          newHistory.push('FLAG{BLIND_SQLI_BYPASS_CONFIRMED}');
        } else {
          newHistory.push('... beacon_egress: 185.220.101.5:443');
          newHistory.push('FLAG{COBALT_STRIKE_MEMORY_EXTRACTED_99}');
        }
      } else if (cmd.startsWith('cat')) {
        newHistory.push('0x00004f: 46 4c 41 47 7b ... [ENCRYPTED ARTIFACT]');
      } else {
        newHistory.push(`bash: ${cmd}: command executed in sandboxed container.`);
      }

      setTerminalHistory(newHistory);
      setTerminalInput('');
    }
  };

  const filteredChallenges = challenges.filter(c => {
    if (categoryFilter !== 'all' && c.category !== categoryFilter) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-gray-800 bg-gray-950 p-4">
        <div>
          <h2 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wide flex items-center gap-2">
            <Flag className="h-5 w-5 text-rose-400" />
            CTF Cyber Combat Arena
          </h2>
          <p className="text-xs text-gray-400">
            Real-world offensive/defensive scenarios. Earn points, exploit vulnerabilities, and dissect incidents.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-gray-800 bg-gray-900 p-0.5 text-xs font-mono">
            <button
              onClick={() => setActiveTab('challenges')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                activeTab === 'challenges' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Challenges
            </button>
            <button
              onClick={() => setActiveTab('leaderboard')}
              className={`rounded-md px-3 py-1.5 transition-all cursor-pointer ${
                activeTab === 'leaderboard' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Live Leaderboard
            </button>
          </div>
        </div>
      </div>

      {activeTab === 'challenges' && (
        <div className="space-y-4">
          {/* Category Filter Pills */}
          <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs font-mono">
            {['all', 'Incident Response', 'Forensics', 'Web AppSec', 'Reverse Engineering', 'Cryptography'].map(cat => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={`rounded-lg px-3 py-1.5 whitespace-nowrap transition-all cursor-pointer ${
                  categoryFilter === cat
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-600 font-semibold'
                    : 'bg-gray-950 text-gray-400 border border-gray-800 hover:border-gray-700 hover:text-gray-200'
                }`}
              >
                {cat === 'all' ? 'All Categories' : cat}
              </button>
            ))}
          </div>

          {/* Challenge Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {filteredChallenges.map(c => (
              <div
                key={c.id}
                onClick={() => handleOpenChallenge(c)}
                className={`group relative flex flex-col justify-between rounded-xl border p-5 shadow-lg transition-all cursor-pointer ${
                  c.solved
                    ? 'border-emerald-900/50 bg-emerald-950/15 hover:border-emerald-700'
                    : 'border-gray-800 bg-gray-950 hover:border-rose-500/50 hover:bg-gray-900/40'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="rounded bg-gray-900 px-2 py-0.5 text-[10px] font-mono font-bold text-cyan-400 border border-gray-800">
                      {c.category}
                    </span>
                    <span className="font-mono text-xs font-bold text-amber-400">
                      +{c.points} PTS
                    </span>
                  </div>

                  <h3 className="font-mono text-sm font-bold text-gray-100 group-hover:text-rose-400 transition-colors">
                    {c.title}
                  </h3>

                  <p className="mt-1 text-xs text-gray-400 line-clamp-2 leading-relaxed">
                    {c.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-gray-800/80 flex items-center justify-between text-xs font-mono">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    c.difficulty === 'Easy' ? 'text-emerald-400 bg-emerald-950/60 border border-emerald-900' :
                    c.difficulty === 'Medium' ? 'text-amber-400 bg-amber-950/60 border border-amber-900' :
                    'text-rose-400 bg-rose-950/60 border border-rose-900'
                  }`}>
                    {c.difficulty}
                  </span>

                  {c.solved ? (
                    <span className="flex items-center gap-1 text-emerald-400 font-semibold text-xs">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Solved
                    </span>
                  ) : (
                    <span className="text-gray-500 text-xs">
                      {c.solvesCount} solves
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Leaderboard Tab */}
      {activeTab === 'leaderboard' && (
        <div className="rounded-xl border border-gray-800 bg-gray-950 p-5 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-mono text-sm font-bold text-gray-200 uppercase flex items-center gap-2">
              <Trophy className="h-4 w-4 text-amber-400" />
              Real-Time Global Analyst Leaderboard
            </h3>
            <span className="text-xs font-mono text-gray-400">Top Competitors</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-gray-800 bg-gray-900/60 text-gray-400">
                <tr>
                  <th className="p-3">Rank</th>
                  <th className="p-3">Analyst Call-Sign</th>
                  <th className="p-3">Total Score</th>
                  <th className="p-3">Solved Flags</th>
                  <th className="p-3 text-right">Last Solved</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {leaderboard.map(entry => (
                  <tr key={entry.rank} className={`hover:bg-gray-900/40 transition-colors ${
                    entry.username === user.name ? 'bg-cyan-950/30 text-cyan-200 font-bold' : ''
                  }`}>
                    <td className="p-3">
                      <span className={`inline-flex h-6 w-6 items-center justify-center rounded font-bold ${
                        entry.rank === 1 ? 'bg-amber-500 text-black' :
                        entry.rank === 2 ? 'bg-gray-400 text-black' :
                        entry.rank === 3 ? 'bg-amber-700 text-white' : 'bg-gray-900 text-gray-400'
                      }`}>
                        #{entry.rank}
                      </span>
                    </td>
                    <td className="p-3 font-semibold text-gray-200">
                      {entry.username} {entry.username === user.name && '(You)'}
                    </td>
                    <td className="p-3 text-cyan-400 font-bold">{entry.score} pts</td>
                    <td className="p-3 text-gray-300">{entry.solvedCount} flags</td>
                    <td className="p-3 text-right text-gray-400">{entry.lastSolved}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Challenge Solve Modal */}
      {selectedChallenge && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-2xl">
            <button
              onClick={() => setSelectedChallenge(null)}
              className="absolute right-4 top-4 rounded-lg p-1.5 text-gray-400 hover:bg-gray-900 hover:text-gray-100 cursor-pointer"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-2 mb-1">
              <span className="rounded bg-cyan-950 px-2 py-0.5 text-[10px] font-mono text-cyan-300 border border-cyan-800">
                {selectedChallenge.category}
              </span>
              <span className="text-xs font-mono text-amber-400 font-bold">
                +{selectedChallenge.points} POINTS
              </span>
            </div>

            <h2 className="text-xl font-bold font-mono text-gray-100">{selectedChallenge.title}</h2>
            <p className="mt-2 text-xs text-gray-300 leading-relaxed font-sans">
              {selectedChallenge.description}
            </p>

            {/* Embedded Web Terminal / Forensics Sandbox */}
            <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-4 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-gray-800 pb-2 mb-2 text-gray-400">
                <span className="flex items-center gap-1.5 text-cyan-400 font-bold">
                  <TerminalIcon className="h-4 w-4" /> Forensics Investigation Terminal
                </span>
                <span className="text-[10px] text-gray-500">Host: sandbox-ctf-01</span>
              </div>

              <div className="max-h-36 overflow-y-auto space-y-1 text-emerald-400 mb-2">
                {terminalHistory.map((line, idx) => (
                  <div key={idx} className="whitespace-pre-wrap">{line}</div>
                ))}
              </div>

              <div className="flex items-center gap-2 text-gray-200 border-t border-gray-800 pt-2">
                <span className="text-cyan-400 font-bold">$</span>
                <input
                  type="text"
                  value={terminalInput}
                  onChange={(e) => setTerminalInput(e.target.value)}
                  onKeyDown={handleTerminalCommand}
                  placeholder="Type forensic command (e.g. strings evidence.raw, ls, help)..."
                  className="w-full bg-transparent text-xs text-gray-100 focus:outline-none placeholder-gray-600 font-mono"
                />
              </div>
            </div>

            {/* Hint reveal button */}
            {selectedChallenge.hints && selectedChallenge.hints.length > 0 && (
              <div className="mt-3">
                {!revealedHint ? (
                  <button
                    onClick={() => setRevealedHint(selectedChallenge.hints![0])}
                    className="flex items-center gap-1.5 text-xs font-mono text-amber-400 hover:text-amber-300 cursor-pointer"
                  >
                    <HelpCircle className="h-3.5 w-3.5" />
                    Unlock Forensic Hint (-25 pts)
                  </button>
                ) : (
                  <div className="rounded-lg bg-amber-950/40 border border-amber-800 p-3 text-xs font-mono text-amber-300">
                    <strong>HINT:</strong> {revealedHint}
                  </div>
                )}
              </div>
            )}

            {/* Flag Submission Form */}
            <form onSubmit={handleSubmitFlag} className="mt-5 border-t border-gray-800 pt-4">
              <label className="block text-xs font-mono text-gray-400 mb-1">
                Enter Captured Flag (Format: <code>FLAG&#123;...&#125;</code>)
              </label>

              <div className="flex gap-2">
                <input
                  type="text"
                  value={flagInput}
                  onChange={(e) => setFlagInput(e.target.value)}
                  placeholder="FLAG{example_flag_here}"
                  className="flex-1 rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-xs font-mono text-gray-100 placeholder-gray-600 focus:border-rose-500 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={isSubmitting || !flagInput.trim()}
                  className="flex items-center gap-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 px-5 py-2 text-xs font-mono font-bold text-white transition-all cursor-pointer"
                >
                  <Flag className="h-3.5 w-3.5" />
                  Submit Flag
                </button>
              </div>

              {flagStatus === 'success' && (
                <div className="mt-3 flex items-center gap-2 rounded-lg bg-emerald-950 border border-emerald-800 p-3 text-xs font-mono text-emerald-300">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  {flagMessage}
                </div>
              )}

              {flagStatus === 'incorrect' && (
                <div className="mt-3 flex items-center gap-2 rounded-lg bg-rose-950 border border-rose-800 p-3 text-xs font-mono text-rose-300">
                  <AlertCircle className="h-4 w-4 text-rose-400" />
                  {flagMessage}
                </div>
              )}
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
