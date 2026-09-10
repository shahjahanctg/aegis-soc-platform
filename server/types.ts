export interface AlertItem {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'new' | 'triaged' | 'investigating' | 'resolved';
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

export interface IOCItem {
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

export interface CourseLesson {
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

export interface CourseItem {
  id: string;
  title: string;
  category: 'SOC Operations' | 'DFIR' | 'Offensive / Red Team' | 'Cloud Security' | 'AI & Threat Hunting';
  level: 'Beginner' | 'Intermediate' | 'Advanced';
  description: string;
  instructor: string;
  lessons: CourseLesson[];
}

export interface PhishingCampaignItem {
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

export interface CTFChallengeItem {
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
  flag: string;
  artifactSnippet?: string;
  author: string;
}

export interface LeaderboardEntry {
  rank: number;
  team: string;
  username?: string;      // display name for real platform users (matches session name)
  score: number;
  solves: number;
  solvedCount?: number;   // alias the frontend renders
  lastSolved?: string;    // short date of most recent solve
  avatar: string;
  country: string;
}

export interface DFIRTimelineEvent {
  id: string;
  timestamp: string;
  artifact: 'MFT' | 'Prefetch' | 'EventLog' | 'Registry' | 'Network' | 'Memory' | string;
  system: string;
  source: string;
  action: string;
  details: string;
  isMalicious: boolean;
}

export interface TelemetryPoint {
  timestamp: string;
  eps: number;
  networkMbps: number;
  cpuUsage: number;
  threatsBlocked: number;
}

export interface AnalysisEvent {
  line: string;
  timestamp?: string;
  severity: 'info' | 'warn' | 'error' | 'critical' | string;
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