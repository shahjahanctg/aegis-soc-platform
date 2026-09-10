import { makeAlertId } from './alertsStore';
import type { AnalysisEvent, AnalysisFinding, AlertItem } from './types';

// ---------------------------------------------------------------------------
// Log parsing & threat analysis engine (zero training data).
// Parses common log formats (RFC 3164/5424 syslog, JSON lines, key=value,
// Apache/nginx, plain text) into structured events, then runs a deterministic
// threat-rule engine over them. No ML, no external intelligence feeds.
// ---------------------------------------------------------------------------

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

const SYSLOG_SEVERITIES: Record<number, string> = {
  0: 'critical', 1: 'critical', 2: 'critical', 3: 'error',
  4: 'warn', 5: 'info', 6: 'info', 7: 'info',
};

const RFC5424_RE = /^<(\d+)>(\d{4}-\d{2}-\d{2}T[\d:.Z+-]+)\s+(\S+)\s+(\S+)(?:\s+\S+)?\s*(.*)$/;
const RFC3164_RE = /^<(\d+)>([A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]+)\s+(\S+)\s+(\S+)\s*(.*)$/;
const ISO_TS_RE = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/;
const APP_RE = /^(\S+)\s*[:\[]\s*(.*)$/;

function severityFromText(line: string): string {
  if (/\b(emergency|fatal|critical|severe)\b/i.test(line)) return 'critical';
  if (/\berror|err\b|\bfailed\b/i.test(line)) return 'error';
  if (/\bwarn(ing)?\b/i.test(line)) return 'warn';
  return 'info';
}

/** Parses one log line into a structured event (best effort). */
export function parseLogLine(line: string): AnalysisEvent {
  const trimmed = line.trim();
  const event: AnalysisEvent = {
    line: trimmed,
    severity: 'info',
    message: trimmed,
    ips: trimmed.match(IP_RE) ?? [],
  };

  const rfc5424 = trimmed.match(RFC5424_RE);
  if (rfc5424) {
    event.timestamp = rfc5424[2];
    event.source = rfc5424[3];
    event.message = rfc5424[5] || rfc5424[4];
    event.severity = SYSLOG_SEVERITIES[Number(rfc5424[1]) & 7] ?? 'info';
    const app = event.message.match(APP_RE);
    if (app) event.source = `${rfc5424[3]} ${app[1]}`;
    return event;
  }

  const rfc3164 = trimmed.match(RFC3164_RE);
  if (rfc3164) {
    event.timestamp = rfc3164[2];
    event.source = rfc3164[3];
    event.message = rfc3164[5] || rfc3164[4];
    event.severity = SYSLOG_SEVERITIES[Number(rfc3164[1]) & 7] ?? 'info';
    return event;
  }

  // JSON lines (common structured logging / CEF-ish / EDR exports)
  const jsonStart = trimmed.indexOf('{');
  if (jsonStart === 0 || (jsonStart > 0 && !/[a-z]/i.test(trimmed.slice(0, jsonStart)))) {
    try {
      const obj = JSON.parse(trimmed.slice(jsonStart));
      const msg = (typeof obj === 'object' && obj !== null)
        ? (obj.message ?? obj.msg ?? obj.event ?? obj.details ?? obj.log ?? JSON.stringify(obj))
        : String(obj);
      event.message = String(msg).slice(0, 2000);
      event.timestamp = String(obj?.timestamp ?? obj?.ts ?? obj?.time ?? event.timestamp ?? '').slice(0, 64) || undefined;
      event.source = String(obj?.source ?? obj?.host ?? obj?.app ?? obj?.logger ?? '').slice(0, 200) || undefined;
      const lvl = String(obj?.level ?? obj?.severity ?? '').toLowerCase();
      if (lvl.includes('crit') || lvl === 'fatal' || lvl === 'emerg') event.severity = 'critical';
      else if (lvl.includes('err') || lvl === 'fail') event.severity = 'error';
      else if (lvl.includes('warn')) event.severity = 'warn';
      else if (lvl) event.severity = 'info';
    } catch {
      // fall through to generic parsing
    }
  }

  // Generic: ISO timestamp + optional source prefix
  const ts = trimmed.match(ISO_TS_RE);
  if (ts && !event.timestamp) event.timestamp = ts[0];
  const afterTs = ts ? trimmed.slice(trimmed.indexOf(ts[0]) + ts[0].length).trim() : trimmed;
  const app = afterTs.match(APP_RE);
  if (app && !event.source) event.source = app[1];
  if (app) event.message = app[2] || event.message;

  event.severity = event.severity === 'info' ? severityFromText(line) : event.severity;
  return event;
}

// ---------------------------------------------------------------------------
// Threat rules (deterministic; evidence = matching raw lines)
// ---------------------------------------------------------------------------

interface ThreatRule {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  test: (line: string) => boolean;
}

const THREAT_RULES: ThreatRule[] = [
  {
    type: 'sqli',
    severity: 'high',
    title: 'SQL Injection Attempt Detected',
    description: 'SQL injection signatures (UNION SELECT, boolean/error-based probes, information_schema) observed in log traffic.',
    test: (l) => /\bunion\s+(all\s+)?select\b|\bselect\b[^;]*\bfrom\b|information_schema|\bsleep\s*\(|\bwaitfor\s+delay\b|'\s*or\s*'\s*1\s*=\s*'?\s*1|\b(?:sql\s?injection)\b/i.test(l),
  },
  {
    type: 'encoded_powershell',
    severity: 'critical',
    title: 'Encoded PowerShell / Script Block Execution',
    description: 'Encoded or obfuscated PowerShell execution (-EncodedCommand, hidden windows, download cradle) — common malware delivery.',
    test: (l) => /powershell[^\n]{0,120}?-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|-windowstyle\s+hidden|-executionpolicy\s+bypass|\biex\s*\(|downloadstring|invoke-(?:expression|webrequest)/i.test(l),
  },
  {
    type: 'credential_dump',
    severity: 'critical',
    title: 'Credential Dumping Activity',
    description: 'LSASS/procdump/mimikatz-style credential access patterns detected.',
    test: (l) => /\b(mimikatz|lsass|procdump|sekurlsa|dumpcred|sam\.dmp|ntds\.dit|kerberoast(ing)?)\b/i.test(l),
  },
  {
    type: 'c2_beacon',
    severity: 'high',
    title: 'C2 / Beacon Communication Indicators',
    description: 'Command-and-control or beaconing indicators (Cobalt Strike, beacon jitter, DNS tunneling).',
    test: (l) => /\b(cobalt\s?strike|beacon(ing)?\b|sliver\b|mythic\b|metasploit|dns\s*tunneling|high.entropy\s*txt|c2-update-service)\b/i.test(l),
  },
  {
    type: 'ransomware',
    severity: 'critical',
    title: 'Ransomware Behavioral Indicators',
    description: 'Ransomware activity — shadow-copy deletion, bulk file encryption, known families.',
    test: (l) => /\b(?:ransomware|vssadmin|shadow\s*cop(y|ies)|\.lock\b|wannacry|lockbit|cryptolocker|encrypt(ing|ed)?\s+files|delete\s+shadows)\b/i.test(l),
  },
  {
    type: 'webshell',
    severity: 'critical',
    title: 'Web Shell / Remote Access Upload',
    description: 'Web shell or backdoor upload indicators (cmd.php, eval() in web paths, suspicious uploads).',
    test: (l) => /\b(cmd\.php|shell\.php|webshell|eval\s*\(|base64_decode\s*\(|upload\.php)\b/i.test(l),
  },
  {
    type: 'brute_force',
    severity: 'medium',
    title: 'Brute Force / Credential Stuffing',
    description: 'Credential stuffing or brute-force keywords detected across the log.',
    test: (l) => /\b(brute.?force|credential\s*stuffing|password\s*spray|many\s*failed|repeated\s*failures)\b/i.test(l),
  },
  {
    type: 'port_scan',
    severity: 'medium',
    title: 'Network Scanning / Reconnaissance',
    description: 'Port scanning or host probing activity (SYN scans, nmap, sweep patterns).',
    test: (l) => /\b(port\s*scan|syn\s*scan|nmap|probing|sweep|reconnaissance)\b/i.test(l),
  },
  {
    type: 'exfiltration',
    severity: 'high',
    title: 'Data Exfiltration Indicators',
    description: 'Large/irregular data transfers, base64 payload transfers, or exfiltration keywords.',
    test: (l) => /\b(exfiltrat|data\s*transfer.{0,40}(large|bulk)|ftp[^\n]{0,60}upload|base64[^\n]{0,80}(transfer|upload))\b/i.test(l),
  },
  {
    type: 'privilege_escalation',
    severity: 'high',
    title: 'Privilege Escalation / Persistence',
    description: 'Persistence or privilege-escalation patterns (RunOnce, service creation, admin group add).',
    test: (l) => /\b(runonce|run\s*key|net\s+localgroup\s+administrators|schtasks|persistence)\b/i.test(l),
  },
  {
    type: 'tunneling',
    severity: 'high',
    title: 'Tunneling / Exfil Transport',
    description: 'Tunneling protocols (ICMP/SSH/HTTP tunneling) often used for covert C2 transport.',
    test: (l) => /\b(icmp\s*tunnel|ssh\s*tunnel|http\s*tunnel|dnscat|iodine|tunneling)\b/i.test(l),
  },
];

const FAILED_LOGIN_RE = /(authentication\s+failure|failed\s+(?:password|logon|login|authentication)|invalid\s+(?:password|credentials?)|logon\s+failure)/i;

export function analyzeEvents(events: AnalysisEvent[]): AnalysisFinding[] {
  const findings: AnalysisFinding[] = [];

  for (const rule of THREAT_RULES) {
    const matches = events.filter((e) => rule.test(e.line));
    if (matches.length === 0) continue;
    findings.push({
      type: rule.type,
      severity: rule.severity,
      title: rule.title,
      description: `${rule.description} ${matches.length} matching line(s).`,
      evidence: matches.slice(0, 5).map((e) => e.line.slice(0, 500)),
    });
  }

  // Aggregate: repeated failed logins from the same source IP
  const failedByIp = new Map<string, number>();
  for (const e of events) {
    if (!FAILED_LOGIN_RE.test(e.line)) continue;
    for (const ip of e.ips) failedByIp.set(ip, (failedByIp.get(ip) ?? 0) + 1);
  }
  for (const [ip, count] of [...failedByIp.entries()].sort((a, b) => b[1] - a[1])) {
    if (count < 3) continue;
    findings.push({
      type: 'failed_logins',
      severity: count >= 10 ? 'high' : 'medium',
      title: `Repeated Failed Logins from ${ip}`,
      description: `${count} failed authentication attempts observed from ${ip} — possible brute-force or credential attack.`,
      evidence: events.filter((e) => e.ips.includes(ip) && FAILED_LOGIN_RE.test(e.line)).slice(0, 5).map((e) => e.line.slice(0, 500)),
    });
  }

  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  return findings;
}

const SEVERITY_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function buildAnalysisSummary(events: AnalysisEvent[], findings: AnalysisFinding[]): string {
  const ips = new Set(events.flatMap((e) => e.ips));
  const top = findings.slice(0, 3).map((f) => `${f.title} (${f.severity})`).join('; ');
  if (findings.length === 0) {
    return `Analyzed ${events.length} log line(s) from ${ips.size} unique IP(s) — no known threat signatures matched. Log appears clean.`;
  }
  return `Analyzed ${events.length} log line(s) from ${ips.size} unique IP(s): ${findings.length} finding(s) — ${top}.`;
}

/** Converts an AnalysisFinding to a persisted AlertItem (server-side). */
export function findingToAlert(f: AnalysisFinding): AlertItem {
  const mitreByType: Record<string, string> = {
    sqli: 'T1190 - Exploit Public-Facing Application',
    encoded_powershell: 'T1059.001 - Command and Scripting Interpreter: PowerShell',
    credential_dump: 'T1003 - OS Credential Dumping',
    c2_beacon: 'T1071 - Application Layer Protocol',
    ransomware: 'T1486 - Data Encrypted for Impact',
    webshell: 'T1505.003 - Server Software Component: Web Shell',
    exfiltration: 'T1048 - Exfiltration Over Alternative Protocol',
    tunneling: 'T1572 - Protocol Tunneling',
    privilege_escalation: 'T1547 - Boot or Logon Autostart Execution',
    failed_logins: 'T1110 - Brute Force',
    brute_force: 'T1110 - Brute Force',
    port_scan: 'T1046 - Network Service Discovery',
  };
  const ip = f.evidence.join(' ').match(IP_RE)?.[0];
  const now = new Date().toISOString();
  return {
    id: makeAlertId(),
    severity: f.severity,
    status: 'new',
    title: f.title,
    description: f.description,
    source: 'Log Analysis Engine',
    mitreTechnique: mitreByType[f.type] ?? 'T1059 - Command and Scripting Interpreter',
    mitreTactic: f.severity === 'critical' || f.severity === 'high' ? 'Initial Access' : 'Discovery',
    sourceIp: ip ?? 'N/A',
    destIp: '10.0.0.1',
    asset: 'LOG-ANALYSIS',
    created_at: now,
    updated_at: now,
  };
}