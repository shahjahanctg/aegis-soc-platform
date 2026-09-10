import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import helmet from 'helmet';
import { z } from 'zod';
import {
  issueAccessToken, issueRefreshToken, verifyRefreshToken, requireAuth,
  requirePermission, requireIngestAuth, sseAuth, authLimiter, aiLimiter,
  ingestLimiter, mutationLimiter, toSessionUser, ROLE_PERMISSIONS, verifyPassword,
  findUserById, JWT_ACCESS_TTL_SEC, type Role, type AuthedRequest,
} from './server/security';
import { LoginSchema, RefreshSchema, TriageSchema, CreateAlertSchema, IngestSchema, SimulationSchema, IOCAddSchema, CampaignLaunchSchema, FlagSubmitSchema, HintUnlockSchema, DFIRAddSchema, AIChatSchema, AITriageSchema, AINlToRulesSchema, AIPhishingSchema } from './server/schemas';
import { recordAudit, setAuditBroadcaster, getAuditLog } from './server/audit';
import { makeAlertId, addAlertBounded } from './server/alertsStore';
import type { AlertItem, IOCItem } from './server/types';

// Initialize Gemini Client server-side safely
const getGeminiClient = () => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
};

// Initial Seed Data for SOC, Training, CTF, DFIR, and AI
// (AlertItem / IOCItem interfaces live in server/types.ts)

const alerts: AlertItem[] = [
  {
    id: 'ALT-1092',
    severity: 'critical',
    status: 'new',
    title: 'Cobalt Strike C2 Beaconing Detected via DNS Tunneling',
    description: 'Repeated high-entropy TXT record requests to suspicious domain c2-update-service.xyz from DC-PROD-01',
    source: 'Suricata NIDS / Core DNS Sensor',
    mitreTechnique: 'T1071.004 - DNS Application Layer Protocol',
    mitreTactic: 'Command and Control',
    sourceIp: '10.0.4.12',
    destIp: '185.220.101.5',
    asset: 'DC-PROD-01 (Active Directory Domain Controller)',
    created_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
  },
  {
    id: 'ALT-1091',
    severity: 'high',
    status: 'investigating',
    title: 'LSASS Memory Dumping via MiniDumpWriteDump API',
    description: 'Unusual process procdump.exe invoked by svchost.exe targeting lsass.exe process memory space',
    source: 'Sysmon Event ID 10',
    mitreTechnique: 'T1003.001 - OS Credential Dumping: LSASS Memory',
    mitreTactic: 'Credential Access',
    sourceIp: '10.0.5.45',
    destIp: '10.0.5.45',
    asset: 'WS-FINANCE-09 (Finance Workstation)',
    created_at: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    analyst: 'Sarah Chen (Lead SOC Analyst)',
    triage_notes: 'Confirmed unauthorized process execution. Host isolated via EDR agent.',
  },
  {
    id: 'ALT-1090',
    severity: 'high',
    status: 'triaged',
    title: 'Multiple Failed Kerberos Pre-Authentication (AS-REP Roasting)',
    description: 'Over 45 failed AS-REQ attempts without pre-authentication for service accounts (krbtgt, svc_sql, svc_backup)',
    source: 'Windows Security Event ID 4768',
    mitreTechnique: 'T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting',
    mitreTactic: 'Credential Access',
    sourceIp: '10.0.8.21',
    destIp: '10.0.4.12',
    asset: 'DC-PROD-01',
    created_at: new Date(Date.now() - 1000 * 60 * 58).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    analyst: 'Marcus Vance',
  },
  {
    id: 'ALT-1089',
    severity: 'medium',
    status: 'new',
    title: 'Potential SQL Injection in Web Payment Gateway',
    description: 'WAF blocked UNION SELECT pattern in parameter `invoice_id` on endpoint /api/v1/checkout',
    source: 'ModSecurity WAF / Cloud Ingress',
    mitreTechnique: 'T1190 - Exploit Public-Facing Application',
    mitreTactic: 'Initial Access',
    sourceIp: '194.26.29.114',
    destIp: '172.16.10.80',
    asset: 'WEB-PORTAL-01',
    created_at: new Date(Date.now() - 1000 * 60 * 95).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 95).toISOString(),
  },
  {
    id: 'ALT-1088',
    severity: 'low',
    status: 'resolved',
    title: 'Outbound Port Scan to External Subnet',
    description: 'Host probed 120 destinations on TCP port 445 (SMB) within 30 seconds',
    source: 'Palo Alto Perimeter FW',
    mitreTechnique: 'T1046 - Network Service Discovery',
    mitreTactic: 'Discovery',
    sourceIp: '10.0.3.88',
    destIp: 'Various External',
    asset: 'DEV-CONTAINER-03',
    created_at: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    updated_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    analyst: 'Elena Rostova',
    triage_notes: 'False positive caused by misconfigured Docker vulnerability scanner script. Scanner reconfigured.',
  }
];

const iocs: IOCItem[] = [
  {
    id: 'IOC-01',
    type: 'ip',
    value: '185.220.101.5',
    threatGroup: 'APT29 / Cozy Bear',
    confidence: 96,
    blocked: true,
    firstSeen: '2026-03-01',
    description: 'Active Cobalt Strike C2 redirection server hosted on bulletproof VPS',
    category: 'Command & Control',
  },
  {
    id: 'IOC-02',
    type: 'domain',
    value: 'c2-update-service.xyz',
    threatGroup: 'UNC2452',
    confidence: 92,
    blocked: true,
    firstSeen: '2026-03-04',
    description: 'Fast-flux DNS tunnel domain used for staging PowerShell payloads',
    category: 'Malware Distribution',
  },
  {
    id: 'IOC-03',
    type: 'sha256',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    threatGroup: 'LockBit 3.0 Affiliate',
    confidence: 99,
    blocked: true,
    firstSeen: '2026-02-28',
    description: 'Ransomware loader compiled with anti-sandbox VM evasion techniques',
    category: 'Ransomware',
  },
  {
    id: 'IOC-04',
    type: 'ip',
    value: '194.26.29.114',
    threatGroup: 'FIN7 / Carbanak',
    confidence: 84,
    blocked: false,
    firstSeen: '2026-03-08',
    description: 'Scanning infrastructure conducting automated SQLi & DirBuster sweeps',
    category: 'Reconnaissance',
  },
  {
    id: 'IOC-05',
    type: 'domain',
    value: 'auth-verify-portal-office365.online',
    threatGroup: 'Storm-0837',
    confidence: 98,
    blocked: true,
    firstSeen: '2026-03-07',
    description: 'Adversary-in-the-Middle (AiTM) Microsoft 365 token harvesting reverse proxy',
    category: 'Credential Phishing',
  }
];

interface CourseLesson {
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

interface CourseItem {
  id: string;
  title: string;
  category: 'SOC Operations' | 'DFIR' | 'Offensive / Red Team' | 'Cloud Security' | 'AI & Threat Hunting';
  level: 'Beginner' | 'Intermediate' | 'Advanced';
  description: string;
  instructor: string;
  lessons: CourseLesson[];
}

const courses: CourseItem[] = [
  {
    id: 'CRS-01',
    title: 'SOC Tier 1: Incident Triage & MITRE ATT&CK Mapping',
    category: 'SOC Operations',
    level: 'Beginner',
    description: 'Master fast-paced alert triage, distinguishing false positives from true positives, and mapping indicators to the MITRE ATT&CK enterprise matrix.',
    instructor: 'Alex Mercer, CISSP',
    lessons: [
      {
        id: 'CRS-01-L1',
        title: 'Anatomy of a Modern SIEM Alert Pipeline',
        duration: '15 min',
        type: 'interactive_lab',
        completed: true,
        content: 'Understanding Syslog, Windows Event IDs (4624, 4625, 4688), Zeek connection logs, and correlation rules.',
        quiz: {
          question: 'Which Windows Event ID signifies successful logon?',
          options: ['Event ID 4625', 'Event ID 4624', 'Event ID 4688', 'Event ID 1102'],
          correctIndex: 1,
          explanation: 'Event ID 4624 documents successful logons, whereas 4625 records failed attempts.',
        }
      },
      {
        id: 'CRS-01-L2',
        title: 'Triage Workflow: Investigating Suspicious PowerShell',
        duration: '25 min',
        type: 'interactive_lab',
        completed: false,
        content: 'Learn to decode Base64 encoded PowerShell commands (-EncodedCommand), trace parent-child process relationships, and extract staged payloads.',
        quiz: {
          question: 'What PowerShell flag indicates an execution policy bypass commonly used by adversaries?',
          options: ['-WindowStyle Hidden', '-ExecutionPolicy Bypass', '-NoProfile', 'All of the above'],
          correctIndex: 3,
          explanation: 'Attackers routinely combine -ExecutionPolicy Bypass, -NoProfile, and -WindowStyle Hidden to execute unauthorized scripts invisibly.',
        }
      },
      {
        id: 'CRS-01-L3',
        title: 'Containing Active Host Compromise',
        duration: '20 min',
        type: 'interactive_lab',
        completed: false,
        content: 'Network isolation procedures, process termination, credential revocation, and snapshot capture.',
      }
    ]
  },
  {
    id: 'CRS-02',
    title: 'DFIR: Windows Memory & Volatility 3 Forensics',
    category: 'DFIR',
    level: 'Advanced',
    description: 'Extract actionable forensic evidence from compromised RAM dumps using Volatility 3, malfind, pslist, and netscan.',
    instructor: 'Dr. Evelyn Vance, EnCE',
    lessons: [
      {
        id: 'CRS-02-L1',
        title: 'RAM Acquisition & Memory Dump Integrity',
        duration: '20 min',
        type: 'interactive_lab',
        completed: false,
        content: 'Comparing raw memory dumps, WinPmem acquisition, and validating SHA256 integrity hashes.',
      },
      {
        id: 'CRS-02-L2',
        title: 'Detecting Injected Code with Volatility Malfind',
        duration: '35 min',
        type: 'interactive_lab',
        completed: false,
        content: 'Identifying PAGE_EXECUTE_READWRITE permissions and unbacked VAD segments characteristic of process hollowing.',
      }
    ]
  },
  {
    id: 'CRS-03',
    title: 'Phishing Defense & Email Header Forensics',
    category: 'SOC Operations',
    level: 'Intermediate',
    description: 'Inspect raw RFC 5322 email headers, diagnose SPF/DKIM/DMARC alignment failures, and identify Adversary-in-the-Middle token stealers.',
    instructor: 'David Kim, Threat Intel Lead',
    lessons: [
      {
        id: 'CRS-03-L1',
        title: 'SPF, DKIM, and DMARC Verification Mechanics',
        duration: '18 min',
        type: 'interactive_lab',
        completed: false,
        content: 'Understand Return-Path vs From alignment, public DKIM cryptographic selectors, and DMARC reject policies.',
      }
    ]
  }
];

interface PhishingCampaignItem {
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

const phishingCampaigns: PhishingCampaignItem[] = [
  {
    id: 'PHISH-2026-01',
    name: 'Quarterly Executive Urgent Wire Transfer',
    template: 'CFO Urgent Financial Authorization',
    targetCount: 150,
    sentCount: 150,
    openedCount: 88,
    clickedCount: 22,
    compromisedCount: 4,
    status: 'completed',
    createdAt: '2026-02-20',
  },
  {
    id: 'PHISH-2026-02',
    name: 'IT Helpdesk: Mandatory MFA Reset Simulation',
    template: 'Microsoft Authenticator Migration Notification',
    targetCount: 320,
    sentCount: 320,
    openedCount: 245,
    clickedCount: 41,
    compromisedCount: 7,
    status: 'active',
    createdAt: '2026-03-05',
  }
];

interface CTFChallengeItem {
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

const ctfChallenges: CTFChallengeItem[] = [
  {
    id: 'CTF-WEB-01',
    title: 'SQLi Through the Looking Glass',
    category: 'Web Exploitation',
    points: 150,
    difficulty: 'Easy',
    solved: false,
    solvesCount: 68,
    description: 'An internal employee directory API endpoint `/api/staff/search?dept=finance` suffers from improper input sanitization. Can you extract the secret administrator access token stored in the `secrets` table?',
    hint: 'Try standard UNION SELECT payloads with 3 columns: NULL, NULL, flag FROM secrets--',
    hintPenalty: 25,
    hintUnlocked: false,
    flag: 'FLAG{un10n_s3l3ct_byp4ss_2026}',
    artifactSnippet: "GET /api/staff/search?dept=finance' UNION SELECT 1,table_name,3 FROM information_schema.tables-- HTTP/1.1",
    author: 'ZeroDayZero',
  },
  {
    id: 'CTF-FOR-02',
    title: 'The Phantom Packet (PCAP Deep Dive)',
    category: 'Forensics',
    points: 250,
    difficulty: 'Medium',
    solved: false,
    solvesCount: 34,
    description: 'We intercepted a suspicious packet capture during a data exfiltration incident. The adversary hid binary chunks inside ICMP Echo Request payload fields. Reconstruct the payload to recover the flag.',
    hint: 'Examine packet data offsets starting at byte 48 in ICMP type 8 requests.',
    hintPenalty: 40,
    hintUnlocked: false,
    flag: 'FLAG{1cmp_tunn3l_3xf1ltr4t10n_m4st3r}',
    artifactSnippet: "Packet #44: IP 10.0.4.12 > 185.220.101.5: ICMP echo request, id 0x1337, seq 1, data: 'RkxBR3sxY21wX3R1bm4zbA=='",
    author: 'PacketWhisperer',
  },
  {
    id: 'CTF-REV-03',
    title: 'Ransomware Deobfuscation',
    category: 'Reverse Engineering',
    points: 350,
    difficulty: 'Hard',
    solved: false,
    solvesCount: 19,
    description: 'A malicious ELF binary checks an encrypted key before detonating. Inspect the disassembly string lookup table and reverse the XOR decryption key.',
    hint: 'The XOR single-byte key is 0x5A applied to the ciphertext buffer at address 0x402100.',
    hintPenalty: 60,
    hintUnlocked: false,
    flag: 'FLAG{x0r_k3y_r3v3rs3d_0x5a_succ3ss}',
    artifactSnippet: "00401122: mov eax, [rbp-0x10]\n00401125: xor eax, 0x5a\n00401128: cmp eax, [rbp-0x14]\n0040112b: jne 0x401140",
    author: 'HexMaster99',
  },
  {
    id: 'CTF-CRYPTO-04',
    title: 'Broken RSA Nonce Reuse',
    category: 'Cryptography',
    points: 200,
    difficulty: 'Medium',
    solved: false,
    solvesCount: 42,
    description: 'An authentication daemon reused identical private exponents across two distinct public moduli. Compute the greatest common divisor (GCD) to factorize the prime factors.',
    hint: 'gcd(N1, N2) yields common prime factor p.',
    hintPenalty: 35,
    hintUnlocked: false,
    flag: 'FLAG{c0mm0n_f4ct0r_f41lur3_gcd}',
    artifactSnippet: "N1 = 0xc7f198...\nN2 = 0x8a912e...\ne = 65537",
    author: 'CryptoNerd',
  },
  {
    id: 'CTF-OSINT-05',
    title: 'Shadow Infrastructure Attribution',
    category: 'OSINT',
    points: 100,
    difficulty: 'Easy',
    solved: false,
    solvesCount: 91,
    description: 'An adversary registered multiple typosquatting domains using a specific ProtonMail address and custom JARM fingerprint. Trace their GitHub repo or Gist to discover their alias.',
    hint: 'Search certificate transparency logs (crt.sh) for SSL serial hashes associated with the email.',
    hintPenalty: 15,
    hintUnlocked: false,
    flag: 'FLAG{0s1nt_tr4ck1ng_j4rm_2026}',
    artifactSnippet: "JARM: 2ad2ad0002ad2ad00042d42d000000e3e5... Email: adversary-red@proton.me",
    author: 'SherlockBytes',
  },
  {
    id: 'CTF-PWN-06',
    title: 'Return-to-libc Buffer Overflow',
    category: 'Pwn / Binary',
    points: 450,
    difficulty: 'Insane',
    solved: false,
    solvesCount: 11,
    description: 'Exploit an unconstrained `strcpy` buffer on an x86_64 service with NX enabled. Chain ROP gadgets to invoke `system("/bin/sh")`.',
    hint: 'Locate pop rdi; ret gadget inside libc.so.6 to populate first argument register.',
    hintPenalty: 75,
    hintUnlocked: false,
    flag: 'FLAG{r0p_g4dg3t_r3t2l1bc_pwn3d}',
    artifactSnippet: "[0x0000000000023b6a] pop rdi; ret\n[0x00000000001b45bd] '/bin/sh'\n[0x0000000000052290] system()",
    author: 'StackSmasher',
  }
];

const ctfLeaderboard = [
  { rank: 1, team: 'ByteVipers', score: 1450, solves: 6, avatar: '🐍', country: 'SG' },
  { rank: 2, team: 'NullSec_Squad', score: 1200, solves: 5, avatar: '⚡', country: 'US' },
  { rank: 3, team: 'DhakaCyberGuard', score: 950, solves: 4, avatar: '🐯', country: 'BD' },
  { rank: 4, team: 'KernelPanicOps', score: 750, solves: 3, avatar: '💻', country: 'DE' },
  { rank: 5, team: 'You (Current Analyst)', score: 0, solves: 0, avatar: '🛡️', country: 'LOCAL' },
];

interface DFIRTimelineEvent {
  id: string;
  timestamp: string;
  artifact: 'MFT' | 'Prefetch' | 'EventLog' | 'Registry' | 'Network' | 'Memory';
  system: string;
  source: string;
  action: string;
  details: string;
  isMalicious: boolean;
}

const dfirTimeline: DFIRTimelineEvent[] = [
  {
    id: 'EVT-01',
    timestamp: '2026-03-09T08:14:22Z',
    artifact: 'Network',
    system: 'FIREWALL-EDGE-01',
    source: 'Snort/Bro',
    action: 'Inbound HTTP POST with encoded payload',
    details: 'Suspicious URI /upload.php from IP 185.220.101.5 containing multipart form data with PHP webshell signature',
    isMalicious: true,
  },
  {
    id: 'EVT-02',
    timestamp: '2026-03-09T08:14:45Z',
    artifact: 'MFT',
    system: 'WEB-PORTAL-01',
    source: '$MFT Record 10452',
    action: 'File Creation on disk',
    details: 'Created C:\\inetpub\\wwwroot\\uploads\\cmd_mini.php ($STANDARD_INFORMATION timestamp matched)',
    isMalicious: true,
  },
  {
    id: 'EVT-03',
    timestamp: '2026-03-09T08:15:10Z',
    artifact: 'EventLog',
    system: 'WEB-PORTAL-01',
    source: 'Security Event ID 4688',
    action: 'Process Creation: w3wp.exe spawned cmd.exe',
    details: 'Command line: cmd.exe /c whoami /all && net group "Domain Admins" /domain',
    isMalicious: true,
  },
  {
    id: 'EVT-04',
    timestamp: '2026-03-09T08:16:30Z',
    artifact: 'Prefetch',
    system: 'WEB-PORTAL-01',
    source: 'PROCDUMP.EXE-A81E9B12.pf',
    action: 'Application Execution Recorded',
    details: 'Procdump executed 1 time with run count incremented. Target binary: lsass.exe',
    isMalicious: true,
  },
  {
    id: 'EVT-05',
    timestamp: '2026-03-09T08:18:04Z',
    artifact: 'Registry',
    system: 'WEB-PORTAL-01',
    source: 'NTUSER.DAT\\RunOnce',
    action: 'Persistence Value Injected',
    details: 'Key added: "SecurityHealthSys" -> "powershell.exe -w hidden -enc JABjAD0AbgBlAHc..."',
    isMalicious: true,
  }
];

let telemetryHistory: { timestamp: string; eps: number; networkMbps: number; cpuUsage: number; threatsBlocked: number }[] = [];
// Seed 20 historical telemetry datapoints
const now = Date.now();
for (let i = 20; i >= 0; i--) {
  telemetryHistory.push({
    timestamp: new Date(now - i * 5000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    eps: Math.floor(450 + Math.random() * 320),
    networkMbps: Math.floor(120 + Math.random() * 80),
    cpuUsage: Math.floor(40 + Math.random() * 35),
    threatsBlocked: Math.floor(5 + Math.random() * 8),
  });
}

// Global SSE clients
const sseClients = new Set<express.Response>();

export function broadcastSSE(event: string, data: any) {
  const namedPayload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  const defaultPayload = `data: ${JSON.stringify({ type: event === 'alert:new' ? 'NEW_ALERT' : event, alert: data, ...data })}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(namedPayload);
      client.write(defaultPayload);
    } catch {
      // client disconnected
    }
  }
}

// Stream audit trail entries to connected clients in real time
setAuditBroadcaster((entry) => broadcastSSE('audit:entry', entry));

// Background simulation ticker
setInterval(() => {
  const latestEps = Math.floor(450 + Math.random() * 350);
  const latestNetwork = Math.floor(110 + Math.random() * 95);
  const latestCpu = Math.floor(38 + Math.random() * 40);
  const latestThreats = Math.floor(3 + Math.random() * 12);
  const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const newPoint = {
    timestamp: timeStr,
    eps: latestEps,
    networkMbps: latestNetwork,
    cpuUsage: latestCpu,
    threatsBlocked: latestThreats,
  };

  telemetryHistory.push(newPoint);
  if (telemetryHistory.length > 30) telemetryHistory.shift();

  broadcastSSE('telemetry:live', newPoint);
}, 5000);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
    crossOriginEmbedderPolicy: false,
  }));
  app.use(express.json({ limit: '256kb' }));

  // -------------------------------------------------------------
  // SSE Real-time stream endpoint
  // -------------------------------------------------------------
  const sseHandler = (req: AuthedRequest, res: express.Response) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    // Initial greeting
    res.write(`event: connected\ndata: ${JSON.stringify({ status: 'connected', clientsCount: sseClients.size + 1, userId: req.user?.id ?? null, role: req.user?.role ?? 'anonymous' })}\n\n`);

    sseClients.add(res);

    req.on('close', () => {
      sseClients.delete(res);
    });
  };

  app.get('/api/events/stream', sseAuth, sseHandler);
  app.get('/api/telemetry/stream', sseAuth, sseHandler);

  // -------------------------------------------------------------
  // Health & Current Session
  // -------------------------------------------------------------
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      platform: 'SOC & Training Platform Suite v1.0',
      geminiConfigured: !!process.env.GEMINI_API_KEY,
    });
  });

  // -------------------------------------------------------------
  // Auth: login / refresh / me / logout
  // -------------------------------------------------------------
  app.post('/api/auth/login', authLimiter, async (req, res) => {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Username and password are required', code: 'INVALID_INPUT' });
    }
    const user = verifyPassword(parsed.data.username, parsed.data.password);
    if (!user) {
      recordAudit(req, 'auth.login', `user:${parsed.data.username}`, 'denied', 'Invalid credentials');
      return res.status(401).json({ error: 'Invalid username or password', code: 'BAD_CREDENTIALS' });
    }

    const accessToken = await issueAccessToken(user);
    const refreshToken = await issueRefreshToken(user);
    recordAudit(req, 'auth.login', `user:${user.username}`, 'allowed');
    res.json({
      accessToken,
      refreshToken,
      expiresIn: JWT_ACCESS_TTL_SEC,
      user: toSessionUser(user),
    });
  });

  app.post('/api/auth/refresh', authLimiter, async (req, res) => {
    const parsed = RefreshSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Refresh token required', code: 'INVALID_INPUT' });
    }
    const payload = await verifyRefreshToken(parsed.data.refreshToken);
    if (!payload || typeof payload.sub !== 'string') {
      return res.status(401).json({ error: 'Invalid or expired refresh token', code: 'BAD_REFRESH_TOKEN' });
    }
    const user = findUserById(payload.sub);
    if (!user) {
      return res.status(401).json({ error: 'User no longer exists', code: 'UNKNOWN_USER' });
    }
    const accessToken = await issueAccessToken(user);
    res.json({ accessToken, expiresIn: JWT_ACCESS_TTL_SEC, user: toSessionUser(user) });
  });

  app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res) => {
    res.json({ user: toSessionUser(req.user!) });
  });

  app.post('/api/auth/logout', requireAuth, (req: AuthedRequest, res) => {
    recordAudit(req, 'auth.logout', `user:${req.user!.username}`, 'allowed');
    res.json({ success: true });
  });

  app.get('/api/audit', requireAuth, requirePermission('admin'), (req, res) => {
    res.json({ entries: getAuditLog(Number(req.query.limit) || 200) });
  });

  // -------------------------------------------------------------
  // Alerts Endpoints
  // -------------------------------------------------------------
  app.get('/api/alerts', requireAuth, requirePermission('alerts:read'), (req: AuthedRequest, res) => {
    const { severity, status, search } = req.query;
    let filtered = [...alerts];

    if (severity && severity !== 'all') {
      filtered = filtered.filter(a => a.severity === severity);
    }
    if (status && status !== 'all') {
      filtered = filtered.filter(a => a.status === status);
    }
    if (search && typeof search === 'string') {
      const q = search.toLowerCase();
      filtered = filtered.filter(a =>
        a.title.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        a.sourceIp.includes(q) ||
        a.destIp.includes(q) ||
        a.mitreTechnique.toLowerCase().includes(q)
      );
    }

    res.json({
      alerts: filtered,
      total: filtered.length,
      stats: {
        critical: alerts.filter(a => a.severity === 'critical').length,
        high: alerts.filter(a => a.severity === 'high').length,
        medium: alerts.filter(a => a.severity === 'medium').length,
        low: alerts.filter(a => a.severity === 'low').length,
        new: alerts.filter(a => a.status === 'new').length,
        investigating: alerts.filter(a => a.status === 'investigating').length,
        resolved: alerts.filter(a => a.status === 'resolved').length,
      }
    });
  });

  app.get('/api/alerts/:id', requireAuth, requirePermission('alerts:read'), (req: AuthedRequest, res) => {
    const alert = alerts.find(a => a.id === req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    res.json(alert);
  });

  app.patch('/api/alerts/:id/triage', requireAuth, requirePermission('alerts:triage'), mutationLimiter, (req: AuthedRequest, res) => {
    const parsed = TriageSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid triage payload', code: 'INVALID_INPUT' });
    }
    const alert = alerts.find(a => a.id === req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    const { status, triage_notes, analyst } = parsed.data;
    if (status) alert.status = status;
    if (triage_notes !== undefined) alert.triage_notes = triage_notes;
    if (analyst) alert.analyst = analyst;
    alert.updated_at = new Date().toISOString();

    recordAudit(req, 'alerts.triage', `alert:${alert.id}`, 'allowed', `status=${alert.status}`);
    broadcastSSE('alert:updated', alert);
    res.json(alert);
  });

  app.post('/api/alerts/create', requireAuth, requirePermission('alerts:create'), mutationLimiter, (req: AuthedRequest, res) => {
    const parsed = CreateAlertSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid alert payload', code: 'INVALID_INPUT', details: parsed.error.flatten().fieldErrors });
    }
    const d = parsed.data;
    const newAlert: AlertItem = {
      id: makeAlertId(),
      severity: d.severity,
      status: 'new',
      title: d.title,
      description: d.description,
      source: d.source,
      mitreTechnique: d.mitreTechnique || 'T1059 - Command and Scripting Interpreter',
      mitreTactic: d.mitreTactic || 'Execution',
      sourceIp: d.sourceIp || '198.51.100.44',
      destIp: d.destIp || '10.0.4.12',
      asset: d.asset || 'CORE-SERVER-01',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    addAlertBounded(alerts, newAlert);
    recordAudit(req, 'alerts.create', `alert:${newAlert.id}`, 'allowed', newAlert.title);
    broadcastSSE('alert:new', newAlert);
    res.json(newAlert);
  });

  // -------------------------------------------------------------
  // Threat Intel & IOCs
  // -------------------------------------------------------------
  app.get('/api/threat-intel/iocs', requireAuth, requirePermission('intel:read'), (req: AuthedRequest, res) => {
    res.json({
      iocs,
      totalCount: iocs.length,
      blockedCount: iocs.filter(i => i.blocked).length,
    });
  });

  app.post('/api/threat-intel/iocs/add', requireAuth, requirePermission('intel:write'), mutationLimiter, (req: AuthedRequest, res) => {
    const parsed = IOCAddSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid IOC payload', code: 'INVALID_INPUT', details: parsed.error.flatten().fieldErrors });
    }
    const { type, value, threatGroup, description, category } = parsed.data;

    const newIoc: IOCItem = {
      id: `IOC-${crypto.randomUUID().slice(0, 12)}`,
      type,
      value,
      threatGroup: threatGroup || 'Unknown Threat Actor',
      confidence: 85,
      blocked: true,
      firstSeen: new Date().toISOString().split('T')[0],
      description: description || 'Manually added IOC from analyst investigation',
      category: category || 'Investigation Artifact',
    };

    iocs.unshift(newIoc);
    if (iocs.length > 500) iocs.length = 500; // bound memory
    recordAudit(req, 'intel.add', `ioc:${newIoc.id}`, 'allowed', `${type}:${value.slice(0, 80)}`);
    res.json(newIoc);
  });

  app.patch('/api/threat-intel/iocs/:id/toggle-block', requireAuth, requirePermission('intel:write'), mutationLimiter, (req: AuthedRequest, res) => {
    const ioc = iocs.find(i => i.id === req.params.id);
    if (!ioc) {
      return res.status(404).json({ error: 'IOC not found' });
    }
    ioc.blocked = !ioc.blocked;
    recordAudit(req, 'intel.toggleBlock', `ioc:${ioc.id}`, 'allowed', `blocked=${ioc.blocked}`);
    res.json(ioc);
  });

  // -------------------------------------------------------------
  // Telemetry API
  // -------------------------------------------------------------
  app.get('/api/telemetry', requireAuth, requirePermission('telemetry:read'), (req: AuthedRequest, res) => {
    res.json({
      history: telemetryHistory,
      current: telemetryHistory[telemetryHistory.length - 1],
      sensors: [
        { name: 'DC-PROD-01 (Sysmon)', status: 'online', eps: 142, uptime: '99.98%' },
        { name: 'SURICATA-NIDS-CORE', status: 'online', eps: 320, uptime: '100%' },
        { name: 'MODSECURITY-WAF-01', status: 'online', eps: 85, uptime: '99.94%' },
        { name: 'ZEEK-NETWORK-MON', status: 'online', eps: 210, uptime: '100%' },
        { name: 'ENDPOINT-CROWDSTRIKE', status: 'warning', eps: 12, uptime: '98.5%' },
      ]
    });
  });

  // Telemetry & Event Ingestion endpoint for forwarders / log shippers
  app.post('/api/telemetry/ingest', requireIngestAuth, ingestLimiter, (req: AuthedRequest, res) => {
    const payload = req.body;
    const parsed = IngestSchema.safeParse(payload);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid ingest payload', code: 'INVALID_INPUT', details: parsed.error.flatten().fieldErrors });
    }
    const data = parsed.data;
    const events = Array.isArray(data) ? data : (Array.isArray(data?.events) ? data.events : [data]);
    let generatedAlert: AlertItem | null = null;

    for (const evt of events) {
      // If the incoming event qualifies as a security incident / alert
      if (evt.isAlert || evt.severity === 'critical' || evt.severity === 'high' || evt.severity === 'medium') {
        generatedAlert = {
          id: makeAlertId(),
          severity: evt.severity || 'high',
          status: 'new',
          title: evt.title || evt.name || evt.message || 'Security Telemetry Alert',
          description: evt.description || evt.details || JSON.stringify(evt).slice(0, 4000),
          source: evt.source || evt.sensor || 'Enterprise Log Ingest',
          mitreTechnique: evt.mitreTechnique || 'T1059 - Command and Scripting Interpreter',
          mitreTactic: evt.mitreTactic || 'Execution',
          sourceIp: evt.sourceIp || evt.src_ip || '192.168.1.50',
          destIp: evt.destIp || evt.dst_ip || '10.0.0.1',
          asset: evt.asset || evt.host || 'INGESTED-HOST',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };

        addAlertBounded(alerts, generatedAlert);
        broadcastSSE('alert:new', generatedAlert);

        // Also record to DFIR timeline for immediate digital forensics
        dfirTimeline.push({
          id: `EVT-${crypto.randomUUID().slice(0, 12)}`,
          timestamp: new Date().toISOString(),
          artifact: evt.artifact || 'Syslog/EDR Event',
          system: generatedAlert.asset,
          source: generatedAlert.source,
          action: generatedAlert.title,
          details: generatedAlert.description,
          isMalicious: true,
        });
      }
    }

    res.json({
      status: 'accepted',
      eventsReceived: events.length,
      alertGenerated: !!generatedAlert,
      alertId: generatedAlert?.id,
    });
  });


  // -------------------------------------------------------------
  // Training & LMS API
  // -------------------------------------------------------------
  app.get('/api/training/courses', requireAuth, requirePermission('training:read'), (req: AuthedRequest, res) => {
    res.json(courses);
  });

  app.post('/api/training/courses/:courseId/lessons/:lessonId/complete', requireAuth, requirePermission('training:write'), mutationLimiter, (req: AuthedRequest, res) => {
    const { courseId, lessonId } = req.params;
    const course = courses.find(c => c.id === courseId);
    if (!course) return res.status(404).json({ error: 'Course not found' });

    const lesson = course.lessons.find(l => l.id === lessonId);
    if (!lesson) return res.status(404).json({ error: 'Lesson not found' });

    lesson.completed = true;
    res.json({ success: true, lesson, courseProgress: Math.round((course.lessons.filter(l => l.completed).length / course.lessons.length) * 100) });
  });

  app.get('/api/training/phishing/campaigns', requireAuth, requirePermission('training:read'), (req: AuthedRequest, res) => {
    res.json(phishingCampaigns);
  });

  app.post('/api/training/phishing/launch', requireAuth, requirePermission('training:write'), mutationLimiter, (req: AuthedRequest, res) => {
    const parsed = CampaignLaunchSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid campaign payload', code: 'INVALID_INPUT', details: parsed.error.flatten().fieldErrors });
    }
    const { name, template, targetCount } = parsed.data;
    const targets = targetCount ?? 100;
    const newCampaign: PhishingCampaignItem = {
      id: `PHISH-${Date.now().toString().slice(-4)}`,
      name: name || 'Security Awareness Drill',
      template: template || 'Microsoft 365 Password Expiry',
      targetCount: targets,
      sentCount: targets,
      openedCount: Math.round(targets * 0.65),
      clickedCount: Math.round(targets * 0.18),
      compromisedCount: Math.round(targets * 0.04),
      status: 'active',
      createdAt: new Date().toISOString().split('T')[0],
    };

    phishingCampaigns.unshift(newCampaign);
    res.json(newCampaign);
  });

  // -------------------------------------------------------------
  // CTF Sub-Platform API
  // -------------------------------------------------------------
  /** CTF challenges are serialized without the flag — flags never leave the server. */
  const publicChallenge = (ch: CTFChallengeItem) => {
    const { flag, ...publicPart } = ch;
    return publicPart;
  };

  app.get('/api/ctf/challenges', requireAuth, requirePermission('ctf:read'), (req: AuthedRequest, res) => {
    res.json(ctfChallenges.map(publicChallenge));
  });

  app.post('/api/ctf/challenges/:id/unlock-hint', requireAuth, requirePermission('ctf:hints'), mutationLimiter, (req: AuthedRequest, res) => {
    const ch = ctfChallenges.find(c => c.id === req.params.id);
    if (!ch) return res.status(404).json({ error: 'Challenge not found' });

    if (!ch.hintUnlocked) {
      ch.hintUnlocked = true;
      recordAudit(req, 'ctf.hint', `challenge:${ch.id}`, 'allowed', `-${ch.hintPenalty} pts`);
    }
    res.json({ hint: ch.hint, penalty: ch.hintPenalty });
  });

  app.post('/api/ctf/challenges/:id/submit', requireAuth, requirePermission('ctf:submit'), mutationLimiter, (req: AuthedRequest, res) => {
    const parsed = FlagSubmitSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, message: 'Flag is required' });
    }
    const ch = ctfChallenges.find(c => c.id === req.params.id);
    if (!ch) return res.status(404).json({ error: 'Challenge not found' });

    const trimmedInput = parsed.data.flag.trim();
    if (trimmedInput === ch.flag) {
      const netPoints = ch.hintUnlocked ? Math.max(10, ch.points - ch.hintPenalty) : ch.points;

      if (!ch.solved) {
        ch.solved = true;
        ch.solvesCount += 1;

        // Update player score in leaderboard
        const player = ctfLeaderboard.find(l => l.country === 'LOCAL');
        if (player) {
          player.score += netPoints;
          player.solves = (player.solves || 0) + 1;
        }

        // Re-sort leaderboard
        ctfLeaderboard.sort((a, b) => b.score - a.score);
        ctfLeaderboard.forEach((item, idx) => { item.rank = idx + 1; });

        recordAudit(req, 'ctf.solve', `challenge:${ch.id}`, 'allowed', `+${netPoints} pts`);
        broadcastSSE('ctf:score', {
          team: req.user!.name,
          challenge: ch.title,
          points: netPoints,
          leaderboard: ctfLeaderboard
        });
      }

      return res.json({
        success: true,
        message: `Flag Correct! +${netPoints} Points Awarded.`,
        pointsAwarded: netPoints,
        challenge: publicChallenge(ch),
      });
    } else {
      recordAudit(req, 'ctf.submit', `challenge:${ch.id}`, 'denied', 'Incorrect flag');
      return res.status(400).json({
        success: false,
        message: 'Incorrect flag. Check formatting (FLAG{...}) and verify extraction.',
      });
    }
  });

  app.get('/api/ctf/leaderboard', requireAuth, requirePermission('ctf:read'), (req: AuthedRequest, res) => {
    res.json(ctfLeaderboard);
  });

  // -------------------------------------------------------------
  // DFIR & Forensics API
  // -------------------------------------------------------------
  app.get('/api/dfir/timeline', requireAuth, requirePermission('dfir:read'), (req: AuthedRequest, res) => {
    res.json(dfirTimeline);
  });

  app.post('/api/dfir/timeline/add', requireAuth, requirePermission('dfir:write'), mutationLimiter, (req: AuthedRequest, res) => {
    const parsed = DFIRAddSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid DFIR event payload', code: 'INVALID_INPUT', details: parsed.error.flatten().fieldErrors });
    }
    const { timestamp, artifact, system, source, action, details, isMalicious } = parsed.data;
    const newEvt: DFIRTimelineEvent = {
      id: `EVT-${crypto.randomUUID().slice(0, 12)}`,
      timestamp: timestamp || new Date().toISOString(),
      artifact: (artifact as DFIRTimelineEvent['artifact']) || 'EventLog',
      system: system || 'HOST-INVESTIGATION',
      source: source || 'Analyst Manual Addition',
      action: action || 'Action recorded',
      details: details || 'Artifact note',
      isMalicious: !!isMalicious,
    };
    dfirTimeline.push(newEvt);
    recordAudit(req, 'dfir.add', `event:${newEvt.id}`, 'allowed', newEvt.action);
    res.json(newEvt);
  });

  // -------------------------------------------------------------
  // AI Module: Gemini Powered endpoints (Chat, Triage, NL->Rules, Phishing)
  // -------------------------------------------------------------
  app.post('/api/ai/chat', requireAuth, requirePermission('ai:chat'), aiLimiter, async (req: AuthedRequest, res) => {
    const parsed = AIChatSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Message is required', code: 'INVALID_INPUT' });
    const { message, contextAlertId } = parsed.data;

    let contextText = '';
    if (contextAlertId) {
      const alert = alerts.find(a => a.id === contextAlertId);
      if (alert) {
        contextText = `\nContext Alert: ID=${alert.id}, Title="${alert.title}", Severity=${alert.severity}, SourceIP=${alert.sourceIp}, DestIP=${alert.destIp}, MITRE=${alert.mitreTechnique}.\n`;
      }
    }

    try {
      const gemini = getGeminiClient();
      if (gemini) {
        const prompt = `You are a high-level SOC Lead Analyst and Incident Response Specialist. Answer the analyst's security query clearly, providing technical precision, MITRE ATT&CK references, forensic commands (PowerShell, bash, Volatility, YARA, or Sigma), and immediate triage containment recommendations where relevant.${contextText}\n\nUser Question: ${message}`;
        const response = await gemini.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
        });

        return res.json({ reply: response.text });
      }
    } catch (err: any) {
      console.warn('Gemini chat API fallback due to:', err?.message || err);
    }

    // Built-in intelligent cybersecurity knowledge fallback
    const msg = message.toLowerCase();
    let reply = '';
    if (msg.includes('dns') || msg.includes('tunnel') || msg.includes('cobalt')) {
      reply = `**Cobalt Strike DNS Tunneling Analysis:**
- **Technique:** MITRE ATT&CK T1071.004 (DNS Application Layer Protocol).
- **Behavior:** Look for high-volume TXT/A queries with Shannon entropy > 4.2 directed to external nameservers.
- **Immediate Containment:**
  1. Blackhole destination domain \`c2-update-service.xyz\` on local DNS resolvers.
  2. Isolate host \`10.0.4.12\` at the switch/EDR layer.
  3. Dump active socket connections via \`netstat -ano\` or \`Get-NetTCPConnection\`.
  4. Perform volatile memory dump using WinPmem before rebooting.`;
    } else if (msg.includes('lsass') || msg.includes('mimikatz') || msg.includes('dump')) {
      reply = `**LSASS Memory Dumping Triage (MITRE T1003.001):**
- **Trigger:** Process memory access to \`lsass.exe\` with rights \`PROCESS_VM_READ\` (0x0010) or \`PROCESS_QUERY_INFORMATION\` (0x0400).
- **Investigative Steps:**
  1. Inspect Sysmon Event ID 10 for source binary and call trace.
  2. Verify if Windows Credential Guard is enabled (\`reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LsaCfgFlags\`).
  3. Check C:\\Windows\\Temp or AppData for dumped \`.dmp\` files.
  4. Force immediate password reset for all accounts logged into WS-FINANCE-09.`;
    } else if (msg.includes('sqli') || msg.includes('sql injection')) {
      reply = `**SQL Injection Containment Playbook (MITRE T1190):**
- **Vector:** Parameter manipulation on \`/api/v1/checkout\`.
- **Validation:** Look at web server access logs for SQL keywords (\`UNION\`, \`SELECT\`, \`SLEEP()\`, \`OR 1=1\`).
- **Remediation:**
  1. Add strict regex WAF rule blocking \`UNION.*SELECT\` patterns.
  2. Ensure parameterized queries (Prepared Statements / ORM) in database calls.
  3. Validate database user privileges to prevent arbitrary \`INTO OUTFILE\` or \`xp_cmdshell\`.`;
    } else {
      reply = `**SOC Analyst Tactical Assessment:**
- **Analysis:** Based on observed security telemetry, correlate source IP with recent threat intelligence feeds and review endpoint parent-child execution trees.
- **Recommended Actions:**
  1. Inspect Windows Event ID 4688 / Sysmon Event ID 1 for process ancestry.
  2. Cross-reference source hashes against internal blocklists.
  3. Open a forensic timeline ticket in the DFIR module to track lateral movement.`;
    }

    res.json({ reply });
  });

  // AI Triage Verdict for a specific alert
  app.post('/api/ai/triage', requireAuth, requirePermission('ai:chat'), aiLimiter, async (req: AuthedRequest, res) => {
    const parsed = AITriageSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'alertId is required', code: 'INVALID_INPUT' });
    const alert = alerts.find(a => a.id === parsed.data.alertId);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    try {
      const gemini = getGeminiClient();
      if (gemini) {
        const prompt = `Analyze this SOC security alert and produce a JSON verdict.
Alert Details:
Title: ${alert.title}
Description: ${alert.description}
Source: ${alert.source}
MITRE: ${alert.mitreTechnique}
Source IP: ${alert.sourceIp}
Destination IP: ${alert.destIp}
Asset: ${alert.asset}

Return JSON with exact keys:
classification: ("TRUE_POSITIVE" or "FALSE_POSITIVE" or "SUSPICIOUS")
confidence: (number between 70 and 99)
reasoning: (2-3 concise sentences explaining the threat or legitimate explanation)
recommendedAction: (1-2 clear immediate containment actions)`;

        const response = await gemini.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
          }
        });

        const parsed = JSON.parse(response.text || '{}');
        alert.aiVerdict = parsed;
        return res.json(parsed);
      }
    } catch (err: any) {
      console.warn('Gemini triage fallback:', err?.message || err);
    }

    // High fidelity fallback verdict
    const isCritical = alert.severity === 'critical' || alert.severity === 'high';
    const fallbackVerdict = {
      classification: (isCritical ? 'TRUE_POSITIVE' : 'SUSPICIOUS') as 'TRUE_POSITIVE' | 'SUSPICIOUS',
      confidence: isCritical ? 94 : 78,
      reasoning: `Analysis of ${alert.source} telemetry confirms signature heuristics matching ${alert.mitreTechnique}. Network flow between ${alert.sourceIp} and ${alert.destIp} matches known adversary TTPs.`,
      recommendedAction: `Quarantine endpoint ${alert.asset}, revoke active Kerberos TGTs, and add ${alert.destIp} to perimeter firewall drop rules.`
    };
    alert.aiVerdict = fallbackVerdict;
    res.json(fallbackVerdict);
  });

  // AI Natural Language to Detection Rules (Sigma, YARA, Suricata)
  app.post('/api/ai/nl-to-rules', requireAuth, requirePermission('ai:chat'), aiLimiter, async (req: AuthedRequest, res) => {
    const parsed = AINlToRulesSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'prompt is required', code: 'INVALID_INPUT' });
    const prompt = parsed.data.prompt;
    const format = parsed.data.ruleFormat;

    try {
      const gemini = getGeminiClient();
      if (gemini) {
        const sysPrompt = `You are a detection engineer expert. Given an English description of a cyber threat or attack vector, generate a valid, production-ready ${format.toUpperCase()} detection rule with standard metadata, condition blocks, and appropriate logsource or strings. Return ONLY the raw code for the rule.`;
        const response = await gemini.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: `Threat to detect: "${prompt}". Generate a ${format.toUpperCase()} rule.`,
          config: { systemInstruction: sysPrompt }
        });
        return res.json({ rule: response.text, format });
      }
    } catch (err: any) {
      console.warn('Gemini NL to rules fallback:', err?.message || err);
    }

    // Default template fallbacks based on format
    let rule = '';
    if (format === 'yara') {
      rule = `rule Detect_${prompt.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 30)} {
    meta:
        description = "Detects ${prompt}"
        author = "SOC & Training AI Engine"
        date = "2026-03-09"
        severity = "High"
    strings:
        $s1 = "cmd.exe /c powershell" nocase
        $s2 = "-ExecutionPolicy Bypass" nocase
        $s3 = "MiniDumpWriteDump" ascii
        $hex_magic = { 4D 5A 90 00 03 00 00 00 }
    condition:
        $hex_magic at 0 and (2 of ($s*))
}`;
    } else if (format === 'suricata') {
      rule = `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SOC_ALERT Possible ${prompt}"; flow:established,to_server; content:"POST"; http_method; content:"/upload.php"; http_uri; pcre:"/cmd|shell|eval/i"; classtype:trojan-activity; sid:2026001; rev:1;)`;
    } else {
      rule = `title: Detect ${prompt}
id: 4a2b91c0-2026-4444-9999-1337c0de0001
status: experimental
description: Generated detection rule for "${prompt}"
author: SOC Platform Detection Engine
references:
    - https://attack.mitre.org/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - 'DownloadString'
    condition: selection
falsepositives:
    - Administrative maintenance scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001`;
    }

    res.json({ rule, format });
  });

  // AI Phishing Email Analyzer
  app.post('/api/ai/phishing-analyze', requireAuth, requirePermission('ai:chat'), aiLimiter, async (req: AuthedRequest, res) => {
    const parsed = AIPhishingSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Email content is required', code: 'INVALID_INPUT' });
    const rawEmail = parsed.data.rawEmail;

    try {
      const gemini = getGeminiClient();
      if (gemini) {
        const prompt = `Perform forensic email phishing analysis on the following raw email content/headers.
Email Content:
${rawEmail.slice(0, 3000)}

Return JSON with exact structure:
{
  "riskScore": (number between 0 and 100),
  "verdict": ("Phishing / Malicious" or "Suspicious" or "Likely Clean"),
  "spfDkimStatus": (string, e.g. "FAIL - Domain mismatch"),
  "urgencyIndicators": [string array of detected high-urgency/fear triggers],
  "maliciousUrls": [string array of deceptive links],
  "executiveSummary": (short 2-sentence summary of the threat),
  "recommendations": [string array of 3 actions for security team]
}`;

        const response = await gemini.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
          config: { responseMimeType: 'application/json' }
        });

        return res.json(JSON.parse(response.text || '{}'));
      }
    } catch (err: any) {
      console.warn('Gemini phishing fallback:', err?.message || err);
    }

    // Smart heuristic analysis
    const hasUrgent = /urgent|immediately|suspend|within 24 hours|action required/i.test(rawEmail);
    const hasMfa = /mfa|password|login|verify|authenticator/i.test(rawEmail);
    const hasSuspiciousDomain = /\.online|\.xyz|\.top|\.ru|free-|login-/i.test(rawEmail);

    const score = (hasUrgent ? 35 : 0) + (hasMfa ? 30 : 0) + (hasSuspiciousDomain ? 30 : 15);
    res.json({
      riskScore: Math.min(score, 98),
      verdict: score > 60 ? 'Phishing / Malicious' : 'Suspicious',
      spfDkimStatus: 'FAIL - Return-Path domain does not match DKIM d= signature',
      urgencyIndicators: [
        'Artificial urgency demanding immediate action within strict deadline',
        'Impersonation of executive IT or Helpdesk credential authority',
        'Coercive threat of account suspension or payroll freeze'
      ],
      maliciousUrls: [
        'http://auth-verify-portal-office365.online/login/sso-saml?auth=session_sync'
      ],
      executiveSummary: 'Email exhibits hallmark characteristics of an Adversary-in-the-Middle credential harvesting campaign targeting corporate Microsoft 365 sessions.',
      recommendations: [
        'Purge message from all mailboxes via M365 Security & Compliance API',
        'Add sending IP and envelope domain to global perimeter firewall drop list',
        'Trigger automated phishing awareness refresher training for targeted recipients'
      ]
    });
  });

  // Cross-module workflow: Convert Alert to CTF Challenge or Training Scenario
  app.post('/api/alerts/:id/convert-to-ctf', requireAuth, requirePermission('alerts:triage'), mutationLimiter, (req: AuthedRequest, res) => {
    const alert = alerts.find(a => a.id === req.params.id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const newChallenge: CTFChallengeItem = {
      id: `CTF-AUTO-${Math.floor(10 + Math.random() * 89)}`,
      title: `Incident Replay: ${alert.title.slice(0, 32)}`,
      category: alert.mitreTactic === 'Initial Access' ? 'Web Exploitation' : 'Forensics',
      points: alert.severity === 'critical' ? 300 : 200,
      difficulty: alert.severity === 'critical' ? 'Hard' : 'Medium',
      solved: false,
      solvesCount: 0,
      description: `Based on real SOC Incident ${alert.id} (${alert.mitreTechnique}). Investigate the artifact snippet extracted from ${alert.asset} and locate the hidden flag.`,
      hint: `Search for encoded payloads sent from ${alert.sourceIp} to ${alert.destIp}.`,
      hintPenalty: 30,
      hintUnlocked: false,
      flag: `FLAG{real_incident_${alert.id.toLowerCase()}_solved}`,
      artifactSnippet: `[LOG EXTRACT ${alert.created_at}]\nSource: ${alert.sourceIp} -> ${alert.destIp}\nPayload: Base64(FLAG{real_incident_${alert.id.toLowerCase()}_solved})`,
      author: 'SOC Automated Scenario Builder',
    };

    ctfChallenges.unshift(newChallenge);
    recordAudit(req, 'alerts.convertToCTF', `alert:${alert.id}`, 'allowed', `challenge:${newChallenge.id}`);
    // Broadcast the public (flag-less) shape — never leak flags over SSE
    broadcastSSE('ctf:new_challenge', publicChallenge(newChallenge));
    res.json({ success: true, challenge: publicChallenge(newChallenge) });
  });

  // Simulation injector for demonstration
  app.post('/api/simulation/inject', requireAuth, requirePermission('alerts:create'), mutationLimiter, (req: AuthedRequest, res) => {
    const parsed = SimulationSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid scenario. Use: ransomware | beacon | sqli', code: 'INVALID_INPUT' });
    }
    const scenario = parsed.data.scenario;

    let newAlert: AlertItem;
    if (scenario === 'ransomware') {
      newAlert = {
        id: makeAlertId(),
        severity: 'critical',
        status: 'new',
        title: 'High-Volume File Renaming & Shadow Copy Deletion (Ransomware Burst)',
        description: 'VSSADMIN.EXE delete shadows /all /quiet executed by suspicious service winhost32.exe followed by .lock extension append on 450 files',
        source: 'EDR Behavioral Engine',
        mitreTechnique: 'T1490 - Inhibit System Recovery',
        mitreTactic: 'Impact',
        sourceIp: '10.0.7.19',
        destIp: '10.0.7.19',
        asset: 'FILE-SERVER-BACKUP-02',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
    } else if (scenario === 'beacon') {
      newAlert = {
        id: makeAlertId(),
        severity: 'high',
        status: 'new',
        title: 'Sliver / Mythic C2 Jitter Beacon Detected',
        description: 'Periodic HTTPS connections at 15.2s intervals (+/- 10% jitter) with static 148-byte POST requests',
        source: 'Zeek Network Anomaly Sensor',
        mitreTechnique: 'T1071.001 - Web Protocols',
        mitreTactic: 'Command and Control',
        sourceIp: '10.0.2.14',
        destIp: '194.26.29.114',
        asset: 'HR-LAPTOP-22',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
    } else {
      newAlert = {
        id: makeAlertId(),
        severity: 'medium',
        status: 'new',
        title: 'Blind SSRF Probe Against Cloud Metadata Endpoint',
        description: 'HTTP request parameter triggered outbound connection attempt to 169.254.169.254 (AWS/GCP metadata service)',
        source: 'AppSec Ingress Filter',
        mitreTechnique: 'T1552.005 - Cloud Instance Metadata API',
        mitreTactic: 'Credential Access',
        sourceIp: '45.154.255.8',
        destIp: '172.16.10.80',
        asset: 'API-GW-PUBLIC',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
    }

    addAlertBounded(alerts, newAlert);
    recordAudit(req, 'simulation.inject', `scenario:${scenario}`, 'allowed', newAlert.title);
    broadcastSSE('alert:new', newAlert);
    res.json({ success: true, alert: newAlert });
  });

  // -------------------------------------------------------------
  // Vite Middleware (Dev) or Static dist serving (Prod)
  // -------------------------------------------------------------
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Unified SOC & Training Platform Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
