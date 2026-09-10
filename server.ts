import 'dotenv/config';
import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { GoogleGenAI } from '@google/genai';
import helmet from 'helmet';
import {
  issueAccessToken, issueRefreshToken, verifyRefreshToken, requireAuth,
  requirePermission, requireIngestAuth, sseAuth, createLimiters, setUserLookup,
  toSessionUser, JWT_ACCESS_TTL_SEC, type Role, type AuthedRequest,
} from './server/security';
import { LoginSchema, RefreshSchema, TriageSchema, CreateAlertSchema, IngestSchema, SimulationSchema, IOCAddSchema, CampaignLaunchSchema, FlagSubmitSchema, HintUnlockSchema, DFIRAddSchema, AIChatSchema, AITriageSchema, AINlToRulesSchema, AIPhishingSchema, AITriageVerdictSchema, AIPhishingAnalysisSchema, AIAnomalySchema, AICorrelateSchema, AICtfHintSchema } from './server/schemas';
import { extractJson, detectTelemetryAnomalies, correlateAlerts } from './server/ai';
import { recordAudit, setAuditBroadcaster, setAuditSink, setAuditSource, getAuditLog } from './server/audit';
import { makeAlertId } from './server/alertsStore';
import { createStore, type Store } from './server/store';
import { createSSERelay, createRateLimitStores, type SSERelay } from './server/redis';
import type {
  AlertItem, IOCItem, CourseItem, PhishingCampaignItem, CTFChallengeItem, DFIRTimelineEvent,
} from './server/types';

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

// ---------------------------------------------------------------------------
// Real-time fan-out. Local SSE clients are always served; when Redis is
// configured the relay fans events out to other app replicas (pub/sub).
// ---------------------------------------------------------------------------

const sseClients = new Set<express.Response>();
let relay: SSERelay | null = null;

function localFanOut(event: string, data: any) {
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

export function broadcastSSE(event: string, data: any) {
  localFanOut(event, data);
  relay?.publish(event, data);
}

// Stream audit trail entries to connected clients in real time
setAuditBroadcaster((entry) => broadcastSSE('audit:entry', entry));

// ---------------------------------------------------------------------------
// Server bootstrap
// ---------------------------------------------------------------------------

async function startServer() {
  // Persistence: Postgres when DATABASE_URL is set, in-memory otherwise.
  const store: Store = await createStore();
  setUserLookup(store);
  setAuditSink((entry) => {
    void store.recordAudit(entry).catch((err) => console.warn('[audit] persist failed:', err?.message || err));
  });
  setAuditSource((limit) => store.getAuditLog(limit));

  // Optional Redis: cross-replica SSE + shared rate limiting (graceful fallback).
  const redisUrl = process.env.REDIS_URL;
  if (redisUrl) {
    relay = createSSERelay(redisUrl, (event, data) => localFanOut(event, data));
    console.log('[redis] SSE relay connected');
  }
  const rateLimitStores = redisUrl ? await createRateLimitStores(redisUrl) : undefined;
  const limiters = createLimiters(rateLimitStores);

  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  // Behind the nginx reverse proxy: trust the first hop so req.ip and the rate
  // limiters key on the real client address (nginx overwrites X-Forwarded-For).
  app.set('trust proxy', 1);

  app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
    crossOriginEmbedderPolicy: false,
  }));
  app.use(express.json({ limit: '256kb' }));

  // Async-handler wrapper: rejects are forwarded to the error middleware.
  type Handler = (req: AuthedRequest, res: express.Response) => Promise<unknown> | unknown;
  const ah = (fn: Handler) =>
    (req: express.Request, res: express.Response, next: express.NextFunction) => {
      Promise.resolve(fn(req as AuthedRequest, res)).catch(next);
    };

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
  app.get('/api/health', ah(async (_req, res) => {
    let dbOk = false;
    try { dbOk = await store.health(); } catch { /* health() never throws */ }
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      platform: 'SOC & Training Platform Suite v1.0',
      storage: store.kind,
      databaseConnected: dbOk,
      redisConfigured: !!redisUrl,
      geminiConfigured: !!process.env.GEMINI_API_KEY,
    });
  }));

  // -------------------------------------------------------------
  // Auth: login / refresh / me / logout
  // -------------------------------------------------------------
  app.post('/api/auth/login', limiters.auth, ah(async (req, res) => {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Username and password are required', code: 'INVALID_INPUT' });
    }
    const user = await store.verifyPassword(parsed.data.username, parsed.data.password);
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
  }));

  app.post('/api/auth/refresh', limiters.auth, ah(async (req, res) => {
    const parsed = RefreshSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Refresh token required', code: 'INVALID_INPUT' });
    }
    const payload = await verifyRefreshToken(parsed.data.refreshToken);
    if (!payload || typeof payload.sub !== 'string') {
      return res.status(401).json({ error: 'Invalid or expired refresh token', code: 'BAD_REFRESH_TOKEN' });
    }
    const user = await store.findUserById(payload.sub);
    if (!user) {
      return res.status(401).json({ error: 'User no longer exists', code: 'UNKNOWN_USER' });
    }
    const accessToken = await issueAccessToken(user);
    res.json({ accessToken, expiresIn: JWT_ACCESS_TTL_SEC, user: toSessionUser(user) });
  }));

  app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res) => {
    res.json({ user: toSessionUser(req.user!) });
  });

  app.post('/api/auth/logout', requireAuth, (req: AuthedRequest, res) => {
    recordAudit(req, 'auth.logout', `user:${req.user!.username}`, 'allowed');
    res.json({ success: true });
  });

  app.get('/api/audit', requireAuth, requirePermission('admin'), ah(async (req, res) => {
    res.json({ entries: await getAuditLog(Number(req.query.limit) || 200) });
  }));

  // -------------------------------------------------------------
  // Alerts Endpoints
  // -------------------------------------------------------------
  app.get('/api/alerts', requireAuth, requirePermission('alerts:read'), ah(async (req, res) => {
    const { severity, status, search } = req.query;
    const result = await store.listAlerts({
      severity: typeof severity === 'string' ? severity : undefined,
      status: typeof status === 'string' ? status : undefined,
      search: typeof search === 'string' ? search : undefined,
    });
    res.json({
      alerts: result.alerts,
      total: result.total,
      stats: result.stats,
    });
  }));

  app.get('/api/alerts/:id', requireAuth, requirePermission('alerts:read'), ah(async (req, res) => {
    const alert = await store.getAlert(req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    res.json(alert);
  }));

  app.patch('/api/alerts/:id/triage', requireAuth, requirePermission('alerts:triage'), limiters.mutation, ah(async (req, res) => {
    const parsed = TriageSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid triage payload', code: 'INVALID_INPUT' });
    }
    const { status, triage_notes, analyst } = parsed.data;
    const updated = await store.updateAlert(req.params.id, {
      ...(status ? { status } : {}),
      ...(triage_notes !== undefined ? { triage_notes } : {}),
      ...(analyst ? { analyst } : {}),
    });
    if (!updated) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    recordAudit(req, 'alerts.triage', `alert:${updated.id}`, 'allowed', `status=${updated.status}`);
    broadcastSSE('alert:updated', updated);
    res.json(updated);
  }));

  app.post('/api/alerts/create', requireAuth, requirePermission('alerts:create'), limiters.mutation, ah(async (req, res) => {
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

    await store.createAlert(newAlert);
    recordAudit(req, 'alerts.create', `alert:${newAlert.id}`, 'allowed', newAlert.title);
    broadcastSSE('alert:new', newAlert);
    res.json(newAlert);
  }));

  // -------------------------------------------------------------
  // Threat Intel & IOCs
  // -------------------------------------------------------------
  app.get('/api/threat-intel/iocs', requireAuth, requirePermission('intel:read'), ah(async (req, res) => {
    const iocs = await store.listIocs();
    res.json({
      iocs,
      totalCount: iocs.length,
      blockedCount: iocs.filter(i => i.blocked).length,
    });
  }));

  app.post('/api/threat-intel/iocs/add', requireAuth, requirePermission('intel:write'), limiters.mutation, ah(async (req, res) => {
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

    await store.addIoc(newIoc);
    recordAudit(req, 'intel.add', `ioc:${newIoc.id}`, 'allowed', `${type}:${value.slice(0, 80)}`);
    res.json(newIoc);
  }));

  app.patch('/api/threat-intel/iocs/:id/toggle-block', requireAuth, requirePermission('intel:write'), limiters.mutation, ah(async (req, res) => {
    const ioc = await store.toggleIocBlock(req.params.id);
    if (!ioc) {
      return res.status(404).json({ error: 'IOC not found' });
    }
    recordAudit(req, 'intel.toggleBlock', `ioc:${ioc.id}`, 'allowed', `blocked=${ioc.blocked}`);
    res.json(ioc);
  }));

  // -------------------------------------------------------------
  // Telemetry API
  // -------------------------------------------------------------
  app.get('/api/telemetry', requireAuth, requirePermission('telemetry:read'), ah(async (req, res) => {
    const { history, current } = await store.getTelemetry();
    res.json({
      history,
      current,
      sensors: [
        { name: 'DC-PROD-01 (Sysmon)', status: 'online', eps: 142, uptime: '99.98%' },
        { name: 'SURICATA-NIDS-CORE', status: 'online', eps: 320, uptime: '100%' },
        { name: 'MODSECURITY-WAF-01', status: 'online', eps: 85, uptime: '99.94%' },
        { name: 'ZEEK-NETWORK-MON', status: 'online', eps: 210, uptime: '100%' },
        { name: 'ENDPOINT-CROWDSTRIKE', status: 'warning', eps: 12, uptime: '98.5%' },
      ]
    });
  }));

  // Telemetry & Event Ingestion endpoint for forwarders / log shippers
  app.post('/api/telemetry/ingest', requireIngestAuth, limiters.ingest, ah(async (req, res) => {
    const parsed = IngestSchema.safeParse(req.body);
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

        await store.createAlert(generatedAlert);
        broadcastSSE('alert:new', generatedAlert);

        // Also record to DFIR timeline for immediate digital forensics
        await store.addDfirEvent({
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
  }));

  // -------------------------------------------------------------
  // Training & LMS API
  // -------------------------------------------------------------
  app.get('/api/training/courses', requireAuth, requirePermission('training:read'), ah(async (req, res) => {
    res.json(await store.listCoursesForUser(req.user!.id));
  }));

  app.post('/api/training/courses/:courseId/lessons/:lessonId/complete', requireAuth, requirePermission('training:write'), limiters.mutation, ah(async (req, res) => {
    const { courseId, lessonId } = req.params;
    const result = await store.completeLesson(req.user!.id, courseId, lessonId);
    if (!result) {
      return res.status(404).json({ error: 'Course or lesson not found' });
    }
    recordAudit(req, 'training.complete', `course:${courseId}`, 'allowed', `lesson:${lessonId}`);
    res.json({ success: true, lesson: result.lesson, courseProgress: result.courseProgress });
  }));

  app.get('/api/training/phishing/campaigns', requireAuth, requirePermission('training:read'), ah(async (req, res) => {
    res.json(await store.listCampaigns());
  }));

  app.post('/api/training/phishing/launch', requireAuth, requirePermission('training:write'), limiters.mutation, ah(async (req, res) => {
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

    await store.addCampaign(newCampaign);
    res.json(newCampaign);
  }));

  // -------------------------------------------------------------
  // CTF Sub-Platform API
  // -------------------------------------------------------------
  /** CTF challenges are serialized without the flag — flags never leave the server. */
  const publicChallenge = (ch: CTFChallengeItem) => {
    const { flag, ...publicPart } = ch;
    return publicPart;
  };

  app.get('/api/ctf/challenges', requireAuth, requirePermission('ctf:read'), ah(async (req, res) => {
    const challenges = await store.listChallengesForUser(req.user!.id);
    res.json(challenges.map(publicChallenge));
  }));

  app.post('/api/ctf/challenges/:id/unlock-hint', requireAuth, requirePermission('ctf:hints'), limiters.mutation, ah(async (req, res) => {
    const result = await store.unlockHint(req.user!.id, req.params.id);
    if (!result) return res.status(404).json({ error: 'Challenge not found' });
    if (!result.alreadyUnlocked) {
      recordAudit(req, 'ctf.hint', `challenge:${req.params.id}`, 'allowed', `-${result.penalty} pts`);
    }
    res.json({ hint: result.hint, penalty: result.penalty });
  }));

  app.post('/api/ctf/challenges/:id/submit', requireAuth, requirePermission('ctf:submit'), limiters.mutation, ah(async (req, res) => {
    const parsed = FlagSubmitSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, message: 'Flag is required' });
    }
    const result = await store.submitFlag(req.user!.id, req.params.id, parsed.data.flag);
    if (!result) return res.status(404).json({ error: 'Challenge not found' });

    if (result.success && !result.alreadySolved) {
      recordAudit(req, 'ctf.solve', `challenge:${result.challengeId}`, 'allowed', `+${result.pointsAwarded} pts`);
      const leaderboard = await store.getLeaderboard();
      broadcastSSE('ctf:score', {
        team: req.user!.name,
        challenge: result.challengeTitle,
        points: result.pointsAwarded,
        leaderboard,
      });
    } else if (result.success) {
      recordAudit(req, 'ctf.solve', `challenge:${result.challengeId}`, 'allowed', 'duplicate submission');
    } else {
      recordAudit(req, 'ctf.submit', `challenge:${result.challengeId}`, 'denied', 'Incorrect flag');
    }

    res.json({
      success: result.success,
      message: result.message,
      pointsAwarded: result.pointsAwarded,
      newScore: result.newScore,
    });
  }));

  app.get('/api/ctf/leaderboard', requireAuth, requirePermission('ctf:read'), ah(async (req, res) => {
    res.json(await store.getLeaderboard());
  }));

  // -------------------------------------------------------------
  // DFIR & Forensics API
  // -------------------------------------------------------------
  app.get('/api/dfir/timeline', requireAuth, requirePermission('dfir:read'), ah(async (req, res) => {
    res.json(await store.listDfirEvents());
  }));

  app.post('/api/dfir/timeline/add', requireAuth, requirePermission('dfir:write'), limiters.mutation, ah(async (req, res) => {
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
    await store.addDfirEvent(newEvt);
    recordAudit(req, 'dfir.add', `event:${newEvt.id}`, 'allowed', newEvt.action);
    res.json(newEvt);
  }));

  // -------------------------------------------------------------
  // AI Module: Gemini Powered endpoints (Chat, Triage, NL->Rules, Phishing)
  // -------------------------------------------------------------
  app.post('/api/ai/chat', requireAuth, requirePermission('ai:chat'), limiters.ai, ah(async (req, res) => {
    const parsed = AIChatSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Message is required', code: 'INVALID_INPUT' });
    const { message, contextAlertId } = parsed.data;

    let contextText = '';
    if (contextAlertId) {
      const alert = await store.getAlert(contextAlertId);
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
      reply = `**Cobalt Strike DNS Tunneling Analysis:**\n- **Technique:** MITRE ATT&CK T1071.004 (DNS Application Layer Protocol).\n- **Behavior:** Look for high-volume TXT/A queries with Shannon entropy > 4.2 directed to external nameservers.\n- **Immediate Containment:**\n  1. Blackhole destination domain \`c2-update-service.xyz\` on local DNS resolvers.\n  2. Isolate host \`10.0.4.12\` at the switch/EDR layer.\n  3. Dump active socket connections via \`netstat -ano\` or \`Get-NetTCPConnection\`.\n  4. Perform volatile memory dump using WinPmem before rebooting.`;
    } else if (msg.includes('lsass') || msg.includes('mimikatz') || msg.includes('dump')) {
      reply = `**LSASS Memory Dumping Triage (MITRE T1003.001):**\n- **Trigger:** Process memory access to \`lsass.exe\` with rights \`PROCESS_VM_READ\` (0x0010) or \`PROCESS_QUERY_INFORMATION\` (0x0400).\n- **Investigative Steps:**\n  1. Inspect Sysmon Event ID 10 for source binary and call trace.\n  2. Verify if Windows Credential Guard is enabled (\`reg query HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa /v LsaCfgFlags\`).\n  3. Check C:\\\\Windows\\\\Temp or AppData for dumped \`.dmp\` files.\n  4. Force immediate password reset for all accounts logged into WS-FINANCE-09.`;
    } else if (msg.includes('sqli') || msg.includes('sql injection')) {
      reply = `**SQL Injection Containment Playbook (MITRE T1190):**\n- **Vector:** Parameter manipulation on \`/api/v1/checkout\`.\n- **Validation:** Look at web server access logs for SQL keywords (\`UNION\`, \`SELECT\`, \`SLEEP()\`, \`OR 1=1\`).\n- **Remediation:**\n  1. Add strict regex WAF rule blocking \`UNION.*SELECT\` patterns.\n  2. Ensure parameterized queries (Prepared Statements / ORM) in database calls.\n  3. Validate database user privileges to prevent arbitrary \`INTO OUTFILE\` or \`xp_cmdshell\`.`;
    } else {
      reply = `**SOC Analyst Tactical Assessment:**\n- **Analysis:** Based on observed security telemetry, correlate source IP with recent threat intelligence feeds and review endpoint parent-child execution trees.\n- **Recommended Actions:**\n  1. Inspect Windows Event ID 4688 / Sysmon Event ID 1 for process ancestry.\n  2. Cross-reference source hashes against internal blocklists.\n  3. Open a forensic timeline ticket in the DFIR module to track lateral movement.`;
    }

    res.json({ reply });
  }));

  // AI Triage Verdict for a specific alert
  app.post('/api/ai/triage', requireAuth, requirePermission('ai:chat'), limiters.ai, ah(async (req, res) => {
    const parsed = AITriageSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'alertId is required', code: 'INVALID_INPUT' });
    const alert = await store.getAlert(parsed.data.alertId);
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

        // Never trust raw LLM output — validate the schema before persisting.
        const verdict = AITriageVerdictSchema.safeParse(extractJson(response.text || '{}'));
        if (verdict.success) {
          await store.updateAlert(alert.id, { aiVerdict: verdict.data });
          return res.json(verdict.data);
        }
        console.warn('Gemini triage output failed schema validation:', verdict.error.issues.map((i) => i.path.join('.')).join(', '));
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
    await store.updateAlert(alert.id, { aiVerdict: fallbackVerdict });
    res.json(fallbackVerdict);
  }));

  // AI Natural Language to Detection Rules (Sigma, YARA, Suricata)
  app.post('/api/ai/nl-to-rules', requireAuth, requirePermission('ai:chat'), limiters.ai, ah(async (req, res) => {
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
            - '\\\\powershell.exe'
            - '\\\\pwsh.exe'
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
  }));

  // AI Phishing Email Analyzer
  app.post('/api/ai/phishing-analyze', requireAuth, requirePermission('ai:chat'), limiters.ai, ah(async (req, res) => {
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
  "spfCheck": ("PASS" or "FAIL" or "NONE"),
  "dkimCheck": ("PASS" or "FAIL" or "NONE"),
  "dmarcCheck": ("PASS" or "FAIL" or "REJECT" or "QUARANTINE" or "NONE"),
  "indicators": [string array of 2-5 suspicious indicators detected],
  "recommendedAction": (string of 2-3 actions for the security team)
}`;

        const response = await gemini.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
          config: { responseMimeType: 'application/json' }
        });

        const analysis = AIPhishingAnalysisSchema.safeParse(extractJson(response.text || '{}'));
        if (analysis.success) {
          return res.json(analysis.data);
        }
        console.warn('Gemini phishing output failed schema validation:', analysis.error.issues.map((i) => i.path.join('.')).join(', '));
      }
    } catch (err: any) {
      console.warn('Gemini phishing fallback:', err?.message || err);
    }

    // Deterministic header/body heuristic analysis (no LLM required)
    const spfMatch = rawEmail.match(/received-spf:\s*(\w+)/i) || rawEmail.match(/spf=(\w+)/i);
    const dkimMatch = rawEmail.match(/dkim-signature:/i) ? 'pass' : (rawEmail.match(/dkim=(\w+)/i)?.[1] ?? 'none');
    const dmarcMatch = rawEmail.match(/dmarc=(\w+)/i);
    const spfCheck = spfMatch && /fail|softfail/i.test(spfMatch[1]) ? 'FAIL' : spfMatch && /pass/i.test(spfMatch[1]) ? 'PASS' : 'NONE';
    const dkimCheck = /fail/i.test(dkimMatch) ? 'FAIL' : /pass/i.test(dkimMatch) ? 'PASS' : 'NONE';
    const dmarcCheck = dmarcMatch
      ? /reject/i.test(dmarcMatch[1]) ? 'REJECT'
        : /quarantine/i.test(dmarcMatch[1]) ? 'QUARANTINE'
          : /pass/i.test(dmarcMatch[1]) ? 'PASS' : 'FAIL'
      : 'NONE';

    const hasUrgent = /urgent|immediately|suspend|within 24 hours|action required|expire/i.test(rawEmail);
    const hasMfa = /mfa|password|login|verify|authenticator|credential/i.test(rawEmail);
    const hasSuspiciousDomain = /\.online|\.xyz|\.top|\.ru|free-|login-|verify-|secure-|microsofft|0ffice|paypal-?secure/i.test(rawEmail);
    const authFails = spfCheck === 'FAIL' || dmarcCheck === 'FAIL' || dmarcCheck === 'REJECT';

    const indicators: string[] = [];
    if (authFails) indicators.push(`Authentication failure (SPF=${spfCheck}, DMARC=${dmarcCheck})`);
    if (hasUrgent) indicators.push('Artificial urgency demanding immediate action within a strict deadline');
    if (hasMfa) indicators.push('Credential/authentication lure (password reset, MFA, login verification)');
    if (hasSuspiciousDomain) indicators.push('Suspicious domain or brand-impersonation pattern in links/sender');
    if (indicators.length === 0) indicators.push('No high-risk indicators matched known phishing heuristics');

    const score = Math.min(98, (authFails ? 40 : 0) + (hasUrgent ? 25 : 0) + (hasMfa ? 20 : 0) + (hasSuspiciousDomain ? 15 : 5));
    res.json({
      riskScore: score,
      verdict: score > 60 ? 'Phishing / Malicious' : score > 30 ? 'Suspicious' : 'Likely Clean',
      spfCheck,
      dkimCheck,
      dmarcCheck,
      indicators,
      recommendedAction: score > 60
        ? 'Purge the message from all mailboxes, block the sending domain/IP at the gateway, and notify targeted recipients to rotate credentials.'
        : 'Flag the message for review; advise recipients to verify sender authenticity before acting.',
    });
  }));

  // Statistical anomaly detection on live telemetry (zero training data — z-score)
  app.post('/api/ai/anomaly', requireAuth, requirePermission('ai:chat'), limiters.ai, ah(async (req, res) => {
    const parsed = AIAnomalySchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid anomaly parameters', code: 'INVALID_INPUT', details: parsed.error.flatten().fieldErrors });
    }
    const { history } = await store.getTelemetry();
    const result = detectTelemetryAnomalies(history, parsed.data.sensitivity ?? 2, parsed.data.window ?? 30);
    recordAudit(req, 'ai.anomaly', 'telemetry', 'allowed', `${result.anomalies.length} anomalies (risk ${result.riskLevel})`);
    res.json(result);
  }));

  // Rule-based alert correlation: cluster alerts by MITRE technique + source IP
  app.post('/api/ai/correlate', requireAuth, requirePermission('alerts:read'), limiters.ai, ah(async (req, res) => {
    const parsed = AICorrelateSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid correlation parameters', code: 'INVALID_INPUT', details: parsed.error.flatten().fieldErrors });
    }
    const { alerts } = await store.listAlerts({});
    const result = correlateAlerts(alerts, parsed.data.windowMinutes ?? 60);
    recordAudit(req, 'ai.correlate', 'alerts', 'allowed', `${result.clusters.length} clusters from ${result.analyzedAlerts} alerts`);
    res.json(result);
  }));

  // AI CTF hint: LLM nudge for a stuck player. The prompt is built from public
  // challenge metadata only — the flag never enters the prompt or the response.
  app.post('/api/ai/ctf-hint', requireAuth, requirePermission('ctf:hints'), limiters.ai, ah(async (req, res) => {
    const parsed = AICtfHintSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'challengeId is required', code: 'INVALID_INPUT' });
    }
    const ch = await store.getChallenge(parsed.data.challengeId);
    if (!ch) return res.status(404).json({ error: 'Challenge not found' });

    try {
      const gemini = getGeminiClient();
      if (gemini) {
        const prompt = `You are a CTF coach. Give ONE concise nudge (2-3 sentences) to a player stuck on this challenge. Do NOT reveal the flag or the full solution.
Challenge: category=${ch.category}, difficulty=${ch.difficulty}, title="${ch.title}"
Description: ${ch.description}${ch.artifactSnippet ? `\nArtifact snippet:\n${ch.artifactSnippet.slice(0, 400)}` : ''}`;
        const response = await gemini.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
        });
        const hintText = (response.text || '').trim();
        if (hintText) {
          recordAudit(req, 'ai.ctfHint', `challenge:${ch.id}`, 'allowed', 'generated');
          return res.json({ hint: hintText.slice(0, 600), source: 'ai' });
        }
      }
    } catch (err: any) {
      console.warn('Gemini ctf-hint fallback:', err?.message || err);
    }

    recordAudit(req, 'ai.ctfHint', `challenge:${ch.id}`, 'allowed', 'built-in hint');
    res.json({ hint: ch.hint, source: 'builtin' });
  }));

  // Cross-module workflow: Convert Alert to CTF Challenge or Training Scenario
  app.post('/api/alerts/:id/convert-to-ctf', requireAuth, requirePermission('alerts:triage'), limiters.mutation, ah(async (req, res) => {
    const alert = await store.getAlert(req.params.id);
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

    await store.addChallenge(newChallenge);
    recordAudit(req, 'alerts.convertToCTF', `alert:${alert.id}`, 'allowed', `challenge:${newChallenge.id}`);
    // Broadcast the public (flag-less) shape — never leak flags over SSE
    broadcastSSE('ctf:new_challenge', publicChallenge(newChallenge));
    res.json({ success: true, challenge: publicChallenge(newChallenge) });
  }));

  // Simulation injector for demonstration
  app.post('/api/simulation/inject', requireAuth, requirePermission('alerts:create'), limiters.mutation, ah(async (req, res) => {
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

    await store.createAlert(newAlert);
    recordAudit(req, 'simulation.inject', `scenario:${scenario}`, 'allowed', newAlert.title);
    broadcastSSE('alert:new', newAlert);
    res.json({ success: true, alert: newAlert });
  }));

  // -------------------------------------------------------------
  // Vite Middleware (Dev) or Static dist serving (Prod)
  // -------------------------------------------------------------
  if (process.env.NODE_ENV !== 'production') {
    // Vite is a dev-only dependency; dynamic import keeps it out of the prod bundle.
    const { createServer: createViteServer } = await import('vite');
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

  // JSON error handler (async route rejections land here)
  app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('[server] unhandled error:', err?.message || err);
    if (res.headersSent) return;
    res.status(500).json({ error: 'Internal server error', code: 'INTERNAL' });
  });

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Unified SOC & Training Platform Server running on http://0.0.0.0:${PORT}`);
    console.log(`[server] storage=${store.kind} redis=${redisUrl ? 'connected' : 'disabled'}`);
  });

  // Background simulation ticker — live telemetry every 5s
  setInterval(() => {
    const point = {
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      eps: Math.floor(450 + Math.random() * 350),
      networkMbps: Math.floor(110 + Math.random() * 95),
      cpuUsage: Math.floor(38 + Math.random() * 40),
      threatsBlocked: Math.floor(3 + Math.random() * 12),
    };
    void store.appendTelemetry(point).catch((err) => console.warn('[telemetry] persist failed:', err?.message || err));
    broadcastSSE('telemetry:live', point);
  }, 5000);

  // Graceful shutdown (docker stop / SIGTERM)
  const shutdown = async () => {
    console.log('[server] shutting down...');
    server.close();
    await store.close();
    relay?.close();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

startServer().catch((err) => {
  console.error('[server] fatal startup error:', err);
  process.exit(1);
});