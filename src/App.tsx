import React, { useState, useEffect, useRef } from 'react';
import { Header } from './components/layout/Header';
import { LogAnalysisModal } from './components/layout/LogAnalysisModal';
import { AlertsView } from './components/soc/AlertsView';
import { AlertDetailModal } from './components/soc/AlertDetailModal';
import { ThreatIntelView } from './components/soc/ThreatIntelView';
import { TopologyView } from './components/soc/TopologyView';
import { ThreatMapView } from './components/soc/ThreatMapView';
import { TelemetryView } from './components/soc/TelemetryView';
import { SyslogIngestView } from './components/soc/SyslogIngestView';
import { ReportsView } from './components/soc/ReportsView';
import { TrainingView } from './components/training/TrainingView';
import { CTFArenaView } from './components/ctf/CTFArenaView';
import { AISecurityHubView } from './components/ai/AISecurityHubView';
import { DFIRTimelineView } from './components/dfir/DFIRTimelineView';
import { SettingsView } from './components/settings/SettingsView';

import { ActiveModule, Alert, IOC, UserSession, AnalysisRun } from './types';
import { api } from './services/api';
import { useAuthStore } from './stores/authStore';
import { LoginPage } from './components/layout/LoginPage';
import { InviteAcceptPage } from './components/layout/InviteAcceptPage';
import { Bell, ShieldAlert, Sparkles, X } from 'lucide-react';

export default function App() {
  const [activeModule, setActiveModule] = useState<ActiveModule>('soc');
  const [socSubView, setSocSubView] = useState<'alerts' | 'intel' | 'topology' | 'threatmap' | 'telemetry' | 'ingest' | 'reports'>('alerts');

  // Auth state (JWT session via zustand store, persisted to localStorage)
  const authUser = useAuthStore((s) => s.user);
  const accessToken = useAuthStore((s) => s.accessToken);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const setStoreUser = useAuthStore((s) => s.setUser);
  const user: UserSession | null = authUser;

  // Global 401-after-refresh handler: session died → back to login
  useEffect(() => {
    const onUnauthorized = () => clearAuth();
    window.addEventListener('aegis:unauthorized', onUnauthorized);
    return () => window.removeEventListener('aegis:unauthorized', onUnauthorized);
  }, [clearAuth]);

  // Data state
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [isLogAnalysisOpen, setIsLogAnalysisOpen] = useState(false);
  const [notificationToast, setNotificationToast] = useState<{ title: string; desc: string; sev: string } | null>(null);

  // Play subtle web audio blip for alerts
  const playAlertSound = (frequency = 650) => {
    try {
      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(frequency, ctx.currentTime);
      gain.gain.setValueAtTime(0.08, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.35);
    } catch {
      // AudioContext unavailable or blocked
    }
  };

  // Initial fetch — keyed on accessToken so data loads once the session exists
  // (previously [] deps meant it ran before login and never re-ran).
  useEffect(() => {
    if (!accessToken) return;
    const initData = async () => {
      try {
        const [alertsData, iocsData] = await Promise.all([
          api.getAlerts(),
          api.getIOCs(),
        ]);
        const alertsList = Array.isArray(alertsData)
          ? alertsData
          : (Array.isArray(alertsData?.alerts) ? alertsData.alerts : []);
        const iocsList = Array.isArray(iocsData)
          ? iocsData
          : (Array.isArray(iocsData?.iocs) ? iocsData.iocs : []);

        setAlerts(alertsList);
        setIocs(iocsList);
      } catch (err) {
        console.error('Failed to load initial data:', err);
      }
    };
    initData();
  }, [accessToken]);

  // Server-Sent Events listener — reconnects with the token once logged in so
  // newly ingested/analyzed alerts update the live totals.
  useEffect(() => {
    if (!accessToken) return;
    const sse = api.getTelemetryEventSource();

    sse.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'NEW_ALERT' && data.alert) {
          setAlerts(prev => [data.alert, ...(Array.isArray(prev) ? prev : [])]);
          playAlertSound(720);
          setNotificationToast({
            title: `NEW ${data.alert.severity.toUpperCase()} ALERT DETECTED`,
            desc: data.alert.title,
            sev: data.alert.severity,
          });
          setTimeout(() => setNotificationToast(null), 5000);
        }
      } catch (err) {
        console.error('SSE parse error:', err);
      }
    };

    return () => {
      sse.close();
    };
  }, [accessToken]);

  // Handler for completed log analysis runs
  const handleAnalysisComplete = (run: AnalysisRun) => {
    if (run.alertsCreated > 0) playAlertSound(880);
    setNotificationToast({
      title: 'LOG ANALYSIS COMPLETE',
      desc: `${run.source}: ${run.findings.length} finding(s), ${run.alertsCreated} alert(s) created`,
      sev: run.alertsCreated > 0 ? 'high' : 'medium',
    });
    setTimeout(() => setNotificationToast(null), 5000);
  };

  // Quick triage from alerts card
  const handleQuickTriage = async (alertId: string, newStatus: 'investigating' | 'resolved') => {
    try {
      const updated = await api.triageAlert(alertId, { status: newStatus, analyst: user?.name ?? 'Unknown Analyst' });
      setAlerts(prev => (Array.isArray(prev) ? prev.map(a => a.id === alertId ? updated : a) : [updated]));
    } catch (err) {
      console.error(err);
    }
  };

  // Update alert from modal
  const handleUpdateAlert = (updated: Alert) => {
    setAlerts(prev => (Array.isArray(prev) ? prev.map(a => a.id === updated.id ? updated : a) : [updated]));
    setSelectedAlert(updated);
  };

  // Toggle IOC block status
  const handleToggleBlockIOC = async (id: string) => {
    try {
      const res = await api.toggleBlockIOC(id);
      setIocs(prev => (Array.isArray(prev) ? prev.map(ioc => ioc.id === id ? { ...ioc, blocked: res.blocked } : ioc) : []));
    } catch (err) {
      console.error(err);
    }
  };

  // Add new IOC
  const handleAddIOC = async (iocData: Partial<IOC>) => {
    try {
      const created = await api.addIOC(iocData);
      setIocs(prev => [created, ...(Array.isArray(prev) ? prev : [])]);
    } catch (err) {
      console.error(err);
    }
  };

  const handlePointsUpdate = (newScore: number) => {
    if (user) setStoreUser({ ...user, score: newScore });
    playAlertSound(1040);
  };

  // Public one-time invite links: ?invite=<setup token> opens the accept page.
  const inviteToken = new URLSearchParams(window.location.search).get('invite');

  // Auth gate: unauthenticated users see the login page (or invite accept page)
  if (!accessToken || !user) {
    if (inviteToken) {
      return <InviteAcceptPage token={inviteToken} onAccepted={() => { /* session stored by api */ }} />;
    }
    return <LoginPage onLogin={() => { /* session already stored by api.login */ }} />;
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Real-time Notification Toast */}
      {notificationToast && (
        <div className="fixed top-18 right-6 z-50 flex items-start gap-3 rounded-xl border border-rose-500/80 bg-gray-950/95 p-4 shadow-[0_0_30px_rgba(244,63,94,0.3)] backdrop-blur-md max-w-sm animate-bounce">
          <ShieldAlert className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1 font-mono text-xs">
            <span className="font-bold text-rose-400 block">{notificationToast.title}</span>
            <span className="text-gray-300 block mt-0.5">{notificationToast.desc}</span>
          </div>
          <button
            onClick={() => setNotificationToast(null)}
            className="text-gray-400 hover:text-gray-200 cursor-pointer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Main Tactical Header */}
      <Header
        activeModule={activeModule}
        onSelectModule={setActiveModule}
        socSubView={socSubView}
        onSelectSocSubView={setSocSubView}
        alertCount={Array.isArray(alerts) ? alerts.filter(a => a.status === 'new' || a.status === 'investigating').length : 0}
        score={user.score}
        onOpenLogAnalysis={() => setIsLogAnalysisOpen(true)}
        user={user}
        onLogout={clearAuth}
      />

      {/* Main Workspace Canvas */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {/* MODULE 1: SOC Command Dashboard */}
        {activeModule === 'soc' && (
          <div className="space-y-6">
            {socSubView === 'alerts' && (
              <AlertsView
                alerts={Array.isArray(alerts) ? alerts : []}
                onSelectAlert={(alert) => setSelectedAlert(alert)}
                onQuickTriage={handleQuickTriage}
              />
            )}
            {socSubView === 'intel' && (
              <ThreatIntelView
                iocs={Array.isArray(iocs) ? iocs : []}
                onToggleBlock={handleToggleBlockIOC}
                onAddIOC={handleAddIOC}
              />
            )}
            {socSubView === 'topology' && <TopologyView />}
            {socSubView === 'threatmap' && <ThreatMapView />}
            {socSubView === 'telemetry' && <TelemetryView />}
            {socSubView === 'ingest' && <SyslogIngestView />}
            {socSubView === 'reports' && <ReportsView alerts={Array.isArray(alerts) ? alerts : []} />}
          </div>
        )}

        {/* MODULE 2: Training Academy & LMS */}
        {activeModule === 'training' && <TrainingView />}

        {/* MODULE 3: CTF Cyber Arena */}
        {activeModule === 'ctf' && (
          <CTFArenaView
            user={user}
            onPointsUpdate={handlePointsUpdate}
          />
        )}

        {/* MODULE 4: AI Security Hub & Copilot */}
        {activeModule === 'ai' && <AISecurityHubView user={user} />}

        {/* MODULE 5: Digital Forensics & Incident Response (DFIR) */}
        {activeModule === 'dfir' && <DFIRTimelineView />}

        {/* MODULE 6: Settings — user management, retention, Gemini key (admin) */}
        {activeModule === 'settings' && <SettingsView user={user} />}
      </main>

      {/* Footer Status Bar */}
      <footer className="border-t border-gray-900 bg-gray-950 px-6 py-3 font-mono text-[11px] text-gray-500 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            AEGIS DEFENSE MESH // CONNECTED
          </span>
          <span className="hidden sm:inline text-gray-700">|</span>
          <span className="hidden sm:inline">Port 3000 Ingress Secure</span>
          <span className="hidden sm:inline text-gray-700">|</span>
          <span className="hidden sm:inline">SSE Feed Active</span>
        </div>
        <div className="flex items-center gap-4">
          <span>CLASSIFICATION: OPERATIONAL DEFENSE</span>
          <span className="text-cyan-500 font-semibold">Gemini 3.8 Flash Engine</span>
        </div>
      </footer>

      {/* Log Analysis Modal */}
      <LogAnalysisModal
        isOpen={isLogAnalysisOpen}
        onClose={() => setIsLogAnalysisOpen(false)}
        onAnalysisComplete={handleAnalysisComplete}
      />

      {/* Alert Deep Triage & Investigation Modal */}
      <AlertDetailModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onUpdateAlert={handleUpdateAlert}
        onNavigateToCTF={() => setActiveModule('ctf')}
        user={user}
      />
    </div>
  );
}
