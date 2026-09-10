import React, { useState } from 'react';
import { 
  ShieldAlert, 
  GraduationCap, 
  Flag, 
  Bot, 
  SearchCode, 
  Radio, 
  Flame, 
  ChevronDown,
  Trophy,
  Activity,
  Globe,
  Network,
  FileText,
  Binary,
  Server
} from 'lucide-react';
import { ActiveModule, UserSession } from '../../types';
import { api } from '../../services/api';
import { LogOut } from 'lucide-react';

interface HeaderProps {
  activeModule: ActiveModule;
  onSelectModule: (mod: ActiveModule) => void;
  socSubView?: 'alerts' | 'intel' | 'topology' | 'threatmap' | 'telemetry' | 'ingest' | 'reports';
  onSelectSocSubView?: (sub: 'alerts' | 'intel' | 'topology' | 'threatmap' | 'telemetry' | 'ingest' | 'reports') => void;
  alertCount?: number;
  score?: number;
  onOpenSimulator: () => void;
  user?: UserSession;
  onLogout?: () => void;
}

interface NavItem {
  id: ActiveModule;
  label: string;
  icon: any;
  badge?: string;
}

export const Header: React.FC<HeaderProps> = ({
  activeModule,
  onSelectModule,
  socSubView = 'alerts',
  onSelectSocSubView,
  alertCount = 0,
  score = 1450,
  onOpenSimulator,
  user = { id: 'usr-1', name: 'Cipher_Lead', role: 'Lead SOC Analyst', score: 1450, permissions: [], badge: undefined },
  onLogout,
}) => {
  const [roleDropdownOpen, setRoleDropdownOpen] = useState(false);

  const modules: NavItem[] = [
    { id: 'soc', label: 'SOC Operations', icon: ShieldAlert, badge: alertCount > 0 ? `${alertCount} ALERTS` : undefined },
    { id: 'training', label: 'Training & LMS', icon: GraduationCap },
    { id: 'ctf', label: 'CTF Arena', icon: Flag, badge: 'LIVE' },
    { id: 'ai', label: 'AI Security Hub', icon: Bot, badge: 'GEMINI 3.8' },
    { id: 'dfir', label: 'DFIR Timeline', icon: SearchCode },
  ];

  const socSubTabs = [
    { id: 'alerts' as const, label: 'Alerts & Triage', icon: ShieldAlert },
    { id: 'intel' as const, label: 'Threat Intel & IOCs', icon: Binary },
    { id: 'topology' as const, label: '3D Network Topology', icon: Network },
    { id: 'threatmap' as const, label: 'Cyber Threat Map', icon: Globe },
    { id: 'telemetry' as const, label: 'Live Telemetry', icon: Activity },
    { id: 'ingest' as const, label: 'Syslog & Ingestion Setup', icon: Server },
    { id: 'reports' as const, label: 'Audit Reports', icon: FileText },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-cyan-950/60 bg-gray-950/95 backdrop-blur-md">
      <div className="flex h-16 items-center justify-between px-4 lg:px-6">
        {/* Brand */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-black tracking-widest text-cyan-400 uppercase">
                AegisSOC
              </span>
              <span className="rounded bg-cyan-950 px-1.5 py-0.5 text-[10px] font-mono font-medium text-cyan-300 border border-cyan-800">
                SUITE v1.0
              </span>
            </div>
            <p className="hidden sm:block text-[11px] font-mono text-gray-400">
              UNIFIED SEC-OPS &bull; TRAINING &bull; CTF &bull; AI
            </p>
          </div>
        </div>

        {/* Primary Module Navigation */}
        <nav className="flex items-center gap-1 overflow-x-auto py-1 mx-2">
          {modules.map(mod => {
            const Icon = mod.icon;
            const isActive = activeModule === mod.id;
            return (
              <button
                key={mod.id}
                onClick={() => onSelectModule(mod.id)}
                className={`relative flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition-all whitespace-nowrap cursor-pointer ${
                  isActive
                    ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.15)] font-semibold'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900/60 border border-transparent'
                }`}
              >
                <Icon className={`h-4 w-4 ${isActive ? 'text-cyan-400' : 'text-gray-400'}`} />
                <span>{mod.label}</span>
                {mod.badge && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                    mod.badge.includes('ALERT') 
                      ? 'bg-rose-950 text-rose-300 border border-rose-800 animate-pulse' 
                      : 'bg-cyan-900/60 text-cyan-300 border border-cyan-800'
                  }`}>
                    {mod.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Right side actions */}
        <div className="flex items-center gap-2.5 shrink-0">
          {/* Live Feed Status */}
          <div className="hidden lg:flex items-center gap-1.5 rounded-md bg-gray-900/80 px-2.5 py-1.5 border border-gray-800 text-xs font-mono">
            <Radio className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
            <span className="text-emerald-400 font-semibold">LIVE MESH</span>
          </div>

          {/* User Score Badge */}
          <div className="flex items-center gap-1.5 rounded-lg bg-amber-950/40 border border-amber-800/80 px-2.5 py-1.5 text-xs font-mono text-amber-300">
            <Trophy className="h-3.5 w-3.5 text-amber-400" />
            <span className="font-bold">{score} pts</span>
          </div>

          {/* Drill simulator trigger */}
          <button
            onClick={onOpenSimulator}
            className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-amber-600/30 to-rose-600/30 hover:from-amber-600/40 hover:to-rose-600/40 border border-amber-500/40 px-2.5 py-1.5 text-xs font-mono text-amber-300 transition-all shadow-[0_0_15px_rgba(245,158,11,0.15)] cursor-pointer"
            title="Inject real-time attack telemetry simulation"
          >
            <Flame className="h-3.5 w-3.5 text-amber-400 animate-pulse" />
            <span className="hidden sm:inline">Attack Drill</span>
          </button>

          {/* Persona Switcher */}
          <div className="relative">
            <button
              onClick={() => setRoleDropdownOpen(!roleDropdownOpen)}
              className="flex items-center gap-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 px-2 py-1.5 text-xs text-gray-200 transition-all cursor-pointer"
            >
              <div className="flex h-6 w-6 items-center justify-center rounded-full bg-cyan-950 text-cyan-400 font-mono text-[10px] font-bold border border-cyan-800">
                {user.name.slice(0, 2).toUpperCase()}
              </div>
              <div className="text-left hidden xl:block">
                <p className="text-[11px] font-medium leading-tight text-gray-200">{user.name}</p>
                <p className="text-[9px] font-mono text-cyan-400">{user.role}</p>
              </div>
              <ChevronDown className="h-3 w-3 text-gray-400" />
            </button>

            {roleDropdownOpen && (
              <div className="absolute right-0 mt-2 w-64 rounded-xl border border-gray-800 bg-gray-950 p-2 shadow-2xl z-50">
                <div className="px-2 py-1.5 border-b border-gray-800 mb-1">
                  <p className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Signed in as</p>
                  <p className="text-xs font-medium text-gray-200 mt-1">{user.name}</p>
                  <p className="text-[10px] font-mono text-cyan-400">{user.role}{user.badge ? ` · ${user.badge}` : ''}</p>
                </div>
                {user.permissions && user.permissions.length > 0 && (
                  <div className="px-2 py-1.5 border-b border-gray-800 mb-1">
                    <p className="text-[10px] font-mono text-gray-500 leading-relaxed">{user.permissions.filter(p => p !== '*').slice(0, 6).join(' · ')}</p>
                  </div>
                )}
                <button
                  onClick={async () => {
                    setRoleDropdownOpen(false);
                    await api.logout();
                    onLogout?.();
                  }}
                  className="w-full flex items-center gap-2 rounded-lg px-2.5 py-2 text-left text-xs text-rose-300 hover:bg-rose-950/40 transition-colors cursor-pointer"
                >
                  <LogOut className="h-4 w-4" />
                  <span className="font-medium">Sign out</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Secondary Sub-navigation when in SOC mode */}
      {activeModule === 'soc' && onSelectSocSubView && (
        <div className="border-t border-gray-900 bg-gray-950/90 px-4 lg:px-6 py-2 overflow-x-auto flex items-center gap-2">
          <span className="text-[11px] font-mono text-gray-500 uppercase mr-1 shrink-0">SOC Views:</span>
          {socSubTabs.map(sub => {
            const SubIcon = sub.icon;
            const isSubActive = socSubView === sub.id;
            return (
              <button
                key={sub.id}
                onClick={() => onSelectSocSubView(sub.id)}
                className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-mono transition-all whitespace-nowrap cursor-pointer ${
                  isSubActive
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900 border border-transparent'
                }`}
              >
                <SubIcon className={`h-3.5 w-3.5 ${isSubActive ? 'text-cyan-400' : 'text-gray-500'}`} />
                <span>{sub.label}</span>
              </button>
            );
          })}
        </div>
      )}
    </header>
  );
};
