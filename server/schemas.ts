import { z } from 'zod';

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const LoginSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(256),
});

export const RefreshSchema = z.object({
  refreshToken: z.string().min(10).max(4096),
});

export const RoleEnum = z.enum(['admin', 'analyst', 'trainer', 'viewer']);

export const CreateUserSchema = z.object({
  username: z.string().min(2).max(64).regex(/^[a-zA-Z0-9_.-]+$/, 'Username may only contain letters, numbers, _ . -'),
  name: z.string().min(1).max(120),
  password: z.string().min(8).max(256),
  role: RoleEnum,
});

export const ResetPasswordSchema = z.object({
  password: z.string().min(8).max(256),
});

export const SettingsUpdateSchema = z.object({
  alertRetention: z.number().int().min(0).max(1_000_000).optional(),
  telemetryRetention: z.number().int().min(0).max(1_000_000).optional(),
  analysisRetention: z.number().int().min(0).max(100_000).optional(),
  // null clears the configured key; string sets it.
  geminiApiKey: z.union([z.string().max(512), z.null()]).optional(),
});

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

export const AlertSeverityEnum = z.enum(['low', 'medium', 'high', 'critical']);
export const AlertStatusEnum = z.enum(['new', 'triaged', 'investigating', 'resolved']);

const IpOrText = z.string().min(1).max(255);

export const TriageSchema = z.object({
  status: AlertStatusEnum.optional(),
  triage_notes: z.string().max(4000).optional(),
  analyst: z.string().min(1).max(120).optional(),
});

export const CreateAlertSchema = z.object({
  severity: AlertSeverityEnum.default('medium'),
  title: z.string().min(1).max(300),
  description: z.string().min(1).max(4000),
  source: z.string().min(1).max(200),
  mitreTechnique: z.string().max(200).optional(),
  mitreTactic: z.string().max(120).optional(),
  sourceIp: IpOrText.optional(),
  destIp: IpOrText.optional(),
  asset: z.string().max(200).optional(),
});

// Telemetry ingest accepts either a single event, an array, or { events: [...] }
export const IngestEventSchema = z.object({
  isAlert: z.boolean().optional(),
  severity: AlertSeverityEnum.optional(),
  title: z.string().max(300).optional(),
  name: z.string().max(300).optional(),
  message: z.string().max(4000).optional(),
  description: z.string().max(4000).optional(),
  details: z.string().max(4000).optional(),
  source: z.string().max(200).optional(),
  sensor: z.string().max(200).optional(),
  mitreTechnique: z.string().max(200).optional(),
  mitreTactic: z.string().max(120).optional(),
  sourceIp: z.string().max(255).optional(),
  destIp: z.string().max(255).optional(),
  asset: z.string().max(200).optional(),
  host: z.string().max(200).optional(),
  artifact: z.string().max(100).optional(),
}).passthrough();

export const IngestSchema = z.union([
  IngestEventSchema,
  z.array(IngestEventSchema).min(1).max(500),
  z.object({ events: z.array(IngestEventSchema).min(1).max(500) }),
]);


// ---------------------------------------------------------------------------
// Threat intel
// ---------------------------------------------------------------------------

export const IOCTypeEnum = z.enum(['ip', 'domain', 'sha256', 'url']);

export const IOCAddSchema = z.object({
  type: IOCTypeEnum,
  value: z.string().min(1).max(512),
  threatGroup: z.string().max(200).optional(),
  description: z.string().max(1000).optional(),
  category: z.string().max(120).optional(),
});

// ---------------------------------------------------------------------------
// Training
// ---------------------------------------------------------------------------

export const LessonCompleteSchema = z.object({}).passthrough();

export const CampaignLaunchSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  template: z.string().max(200).optional(),
  targetCount: z.number().int().min(1).max(100000).optional(),
});

// ---------------------------------------------------------------------------
// CTF
// ---------------------------------------------------------------------------

export const FlagSubmitSchema = z.object({
  flag: z.string().min(1).max(256),
});

export const HintUnlockSchema = z.object({}).passthrough();

// ---------------------------------------------------------------------------
// DFIR
// ---------------------------------------------------------------------------

export const DFIRAddSchema = z.object({
  timestamp: z.string().max(64).optional(),
  artifact: z.string().max(100).optional(),
  system: z.string().max(200).optional(),
  source: z.string().max(200).optional(),
  action: z.string().max(300).optional(),
  details: z.string().max(4000).optional(),
  isMalicious: z.boolean().optional(),
});

// ---------------------------------------------------------------------------
// AI
// ---------------------------------------------------------------------------

export const AIChatSchema = z.object({
  message: z.string().min(1).max(8000),
  contextAlertId: z.string().max(64).optional(),
  context: z.unknown().optional(),
});

export const AITriageSchema = z.object({
  alertId: z.string().min(1).max(64),
});

export const AINlToRulesSchema = z.object({
  prompt: z.string().min(1).max(4000),
  ruleFormat: z.enum(['sigma', 'yara', 'suricata']).default('sigma'),
});

export const AIPhishingSchema = z.object({
  rawEmail: z.string().min(1).max(30000),
});

// ---------------------------------------------------------------------------
// AI — structured LLM outputs (validated before trust / persistence)
// ---------------------------------------------------------------------------

export const AITriageVerdictSchema = z.object({
  classification: z.enum(['TRUE_POSITIVE', 'FALSE_POSITIVE', 'SUSPICIOUS']),
  confidence: z.number().min(0).max(100),
  reasoning: z.string().min(1).max(3000),
  recommendedAction: z.string().min(1).max(3000),
});

export const AIPhishingAnalysisSchema = z.object({
  riskScore: z.number().min(0).max(100),
  verdict: z.string().min(1).max(120),
  spfCheck: z.string().min(1).max(40),
  dkimCheck: z.string().min(1).max(40),
  dmarcCheck: z.string().min(1).max(40),
  indicators: z.array(z.string().min(1).max(300)).max(40),
  recommendedAction: z.string().min(1).max(3000),
});

export const AIAnomalySchema = z.object({
  window: z.number().int().min(5).max(500).optional(),
  sensitivity: z.number().min(1).max(4).optional(),
});

export const AICorrelateSchema = z.object({
  windowMinutes: z.number().int().min(5).max(1440).optional(),
});

export const AICtfHintSchema = z.object({
  challengeId: z.string().min(1).max(64),
});
