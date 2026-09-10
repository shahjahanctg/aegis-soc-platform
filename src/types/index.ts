export type ActiveModule = 'soc' | 'training' | 'ctf' | 'ai' | 'dfir' | 'settings';
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'new' | 'triaged' | 'investigating' | 'resolved';

export interface Alert {
  id: string;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  description: string;
  source: string;
  mitreTechnique: string;
  mitreTactic: string;
  sourceIp: string;
  destIp: string;
  asset: string;
  created_at: string;
  updated_at: string;
  triage_notes?: string;
  analyst?: string;
  aiVerdict?: {
    classification: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'SUSPICIOUS';
    confidence: number;
    reasoning: string;
    recommendedAction: string;
  };
}

export interface IOC {
  id: string;
  type: 'ip' | 'domain' | 'sha256' | 'url';
  value: string;
  threatGroup: string;
  confidence: number;
  blocked: boolean;
  firstSeen: string;
  description: string;
  category: string;
}

export interface Lesson {
  id: string;
  title: string;
  duration: string;
  type: 'video' | 'interactive_lab' | 'quiz';
  completed: boolean;
  content: string;
  quiz?: {
    question: string;
    options: string[];
    correctIndex: number;
    explanation: string;
  };
}

export interface Course {
  id: string;
  title: string;
  category: 'SOC Operations' | 'DFIR' | 'Offensive / Red Team' | 'Cloud Security' | 'AI & Threat Hunting';
  level: 'Beginner' | 'Intermediate' | 'Advanced';
  description: string;
  instructor: string;
  lessons: Lesson[];
}

export interface PhishingCampaign {
  id: string;
  name: string;
  template: string;
  targetCount: number;
  sentCount: number;
  openedCount: number;
  clickedCount: number;
  compromisedCount: number;
  status: 'active' | 'completed' | 'draft';
  createdAt: string;
}

export interface CTFChallenge {
  id: string;
  title: string;
  category: 'Web Exploitation' | 'Forensics' | 'Reverse Engineering' | 'Cryptography' | 'OSINT' | 'Pwn / Binary';
  points: number;
  difficulty: 'Easy' | 'Medium' | 'Hard' | 'Insane';
  solved: boolean;
  solvesCount: number;
  description: string;
  hint: string;
  hintPenalty: number;
  hintUnlocked: boolean;
  /** Server never sends the flag to clients; present only as a legacy type shape. */
  flag?: string;
  artifactSnippet?: string;
  author: string;
}

export interface CTFLeaderboardEntry {
  rank: number;
  team: string;
  username?: string;
  score: number;
  solves?: number;
  solvedCount?: number;
  lastSolved?: string;
  avatar?: string;
  country?: string;
}

export type LeaderboardEntry = CTFLeaderboardEntry;

export interface DFIRTimelineEvent {
  id: string;
  timestamp: string;
  artifact: 'MFT' | 'Prefetch' | 'EventLog' | 'Registry' | 'Network' | 'Memory';
  system: string;
  source: string;
  action: string;
  details: string;
  isMalicious: boolean;
}

export interface DFIRArtifact {
  id: string;
  timestamp: string;
  source: string;
  eventType: string;
  description: string;
  host: string;
  rawPayload: string;
  hash?: string;
  isEvidence?: boolean;
}

export interface TelemetryPoint {
  timestamp: string;
  eps: number;
  networkMbps: number;
  cpuUsage: number;
  threatsBlocked: number;
}

export interface SensorStatus {
  name: string;
  status: 'online' | 'warning' | 'offline';
  eps: number;
  uptime: string;
}

export interface UserSession {
  id: string;
  name: string;
  email?: string;
  role: string;
  permissions?: string[];
  badge?: string;
  score: number;
  solvedChallenges?: string[];
}

export interface MetricBaseline {
  mean: number;
  std: number;
  min: number;
  max: number;
  current: number;
}

export interface AnomalyPoint {
  timestamp: string;
  metric: string;
  value: number;
  mean: number;
  std: number;
  zScore: number;
  severity: 'medium' | 'high' | 'critical';
}

export interface AnomalyResult {
  window: number;
  analyzedPoints: number;
  sensitivity: number;
  baseline: Record<string, MetricBaseline>;
  anomalies: AnomalyPoint[];
  summary: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface CorrelationCluster {
  key: string;
  technique: string;
  tactic: string;
  sourceIp: string;
  destIps: string[];
  assets: string[];
  alertIds: string[];
  count: number;
  timeSpanMinutes: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  investigation: string;
  recommendedAction: string;
}

export interface CorrelationResult {
  windowMinutes: number;
  analyzedAlerts: number;
  clusters: CorrelationCluster[];
  summary: string;
}

export interface AnalysisEvent {
  line: string;
  timestamp?: string;
  severity: string;
  source?: string;
  message: string;
  ips: string[];
}

export interface AnalysisFinding {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence: string[];
}

export interface AnalysisRun {
  id: string;
  userId: string;
  source: string;
  eventCount: number;
  suspiciousCount: number;
  findings: AnalysisFinding[];
  summary: string;
  alertsCreated: number;
  createdAt: string;
}

export interface AnalysisRunSummary {
  id: string;
  source: string;
  eventCount: number;
  suspiciousCount: number;
  findingsCount: number;
  summary: string;
  createdAt: string;
}

export interface AnalysisRunDetail extends AnalysisRun {
  events: AnalysisEvent[];
}

export interface ManagedUser {
  id: string;
  username: string;
  name: string;
  role: 'admin' | 'analyst' | 'trainer' | 'viewer';
  badge?: string;
  score: number;
}

export interface AppSettings {
  alertRetention: number;
  telemetryRetention: number;
  analysisRetention: number;
  geminiConfigured: boolean;
}
