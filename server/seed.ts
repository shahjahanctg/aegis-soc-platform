import type {
  AlertItem, IOCItem, CourseItem, PhishingCampaignItem,
  CTFChallengeItem, LeaderboardEntry, DFIRTimelineEvent, TelemetryPoint,
} from "./types";

// ---------------------------------------------------------------------------
// Seed / demo data. Loaded into the Postgres store on first boot (when
// DATABASE_URL is set) or used directly by the in-memory store (local dev).
// ---------------------------------------------------------------------------
export const seedAlerts: AlertItem[] = [
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

export const seedIocs: IOCItem[] = [
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

export const seedCourses: CourseItem[] = [
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

export const seedPhishingCampaigns: PhishingCampaignItem[] = [
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

export const seedCtfChallenges: CTFChallengeItem[] = [
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

export const seedCtfLeaderboard: LeaderboardEntry[] = [
  { rank: 1, team: 'ByteVipers', score: 1450, solves: 6, avatar: '🐍', country: 'SG' },
  { rank: 2, team: 'NullSec_Squad', score: 1200, solves: 5, avatar: '⚡', country: 'US' },
  { rank: 3, team: 'DhakaCyberGuard', score: 950, solves: 4, avatar: '🐯', country: 'BD' },
  { rank: 4, team: 'KernelPanicOps', score: 750, solves: 3, avatar: '💻', country: 'DE' },
  { rank: 5, team: 'You (Current Analyst)', score: 0, solves: 0, avatar: '🛡️', country: 'LOCAL' },
];

export const seedDfirTimeline: DFIRTimelineEvent[] = [
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

export function makeSeedTelemetry(): TelemetryPoint[] {
  const points: TelemetryPoint[] = [];
  const now = Date.now();
  for (let i = 20; i >= 0; i--) {
    points.push({
      timestamp: new Date(now - i * 5000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      eps: Math.floor(450 + Math.random() * 320),
      networkMbps: Math.floor(120 + Math.random() * 80),
      cpuUsage: Math.floor(40 + Math.random() * 35),
      threatsBlocked: Math.floor(5 + Math.random() * 8),
    });
  }
  return points;
}
