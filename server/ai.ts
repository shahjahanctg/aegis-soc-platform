import type { AlertItem, TelemetryPoint } from './types';

// ---------------------------------------------------------------------------
// Zero-training-data AI engine.
// No models are trained here — every capability is either deterministic
// statistics (z-score anomaly detection), rule-based correlation, or LLM
// output that is schema-validated before it is trusted or persisted.
// ---------------------------------------------------------------------------

/** Robust JSON extraction from LLM output: tolerates markdown fences and stray prose. */
export function extractJson(text: string): unknown {
  let cleaned = text.trim();
  const fence = cleaned.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) cleaned = fence[1].trim();
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start >= 0 && end > start) cleaned = cleaned.slice(start, end + 1);
  try {
    return JSON.parse(cleaned);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Anomaly detection — rolling z-score against the telemetry window baseline.
// ---------------------------------------------------------------------------

const METRICS = ['eps', 'networkMbps', 'cpuUsage', 'threatsBlocked'] as const;
type MetricName = (typeof METRICS)[number];

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
  baseline: Record<MetricName, MetricBaseline>;
  anomalies: AnomalyPoint[];
  summary: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

export function detectTelemetryAnomalies(points: TelemetryPoint[], sensitivity = 2, windowLimit = 30): AnomalyResult {
  const window = points.slice(-windowLimit);
  const baseline: Record<MetricName, MetricBaseline> = {} as Record<MetricName, MetricBaseline>;

  if (window.length === 0) {
    return {
      window: 0, analyzedPoints: 0, sensitivity, baseline,
      anomalies: [], riskLevel: 'low',
      summary: 'No telemetry data available yet — ingest real sensor/log data to enable anomaly detection.',
    };
  }

  for (const metric of METRICS) {
    const values = window.map((p) => p[metric]);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
    const std = Math.sqrt(variance);
    baseline[metric] = {
      mean: round2(mean),
      std: round2(std),
      min: Math.min(...values),
      max: Math.max(...values),
      current: values[values.length - 1],
    };
  }

  const anomalies: AnomalyPoint[] = [];
  for (const point of window) {
    for (const metric of METRICS) {
      const { mean, std } = baseline[metric];
      const denom = std || Math.max(Math.abs(mean) * 0.05, 1e-6);
      const z = Math.abs((point[metric] - mean) / denom);
      if (z >= sensitivity) {
        anomalies.push({
          timestamp: point.timestamp,
          metric,
          value: point[metric],
          mean: round2(mean),
          std: round2(std),
          zScore: round2(z),
          severity: z >= 3 ? 'critical' : z >= 2.5 ? 'high' : 'medium',
        });
      }
    }
  }

  const riskLevel: AnomalyResult['riskLevel'] =
    anomalies.some((a) => a.severity === 'critical') ? 'critical'
      : anomalies.some((a) => a.severity === 'high') ? 'high'
        : anomalies.length > 0 ? 'medium' : 'low';

  const summary = anomalies.length === 0
    ? `No anomalies detected across ${METRICS.length} telemetry metrics in the rolling ${window.length}-point window (threshold: |z| >= ${sensitivity}).`
    : `${anomalies.length} anomaly point(s) flagged across ${METRICS.length} metrics (threshold: |z| >= ${sensitivity}). Highest risk: ${riskLevel.toUpperCase()}.`;

  return { window: window.length, analyzedPoints: window.length, sensitivity, baseline, anomalies, summary, riskLevel };
}

// ---------------------------------------------------------------------------
// Alert correlation — rule-based clustering by base MITRE technique + source IP
// within a time window. Deterministic; no training data.
// ---------------------------------------------------------------------------

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

const SEVERITY_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function correlateAlerts(alerts: AlertItem[], windowMinutes = 60): CorrelationResult {
  interface Acc extends CorrelationCluster {
    times: number[];
  }
  const byKey = new Map<string, Acc>();

  for (const a of alerts) {
    const techMatch = a.mitreTechnique.match(/T\d{3,5}/);
    const technique = techMatch ? techMatch[0] : (a.mitreTechnique.split(' - ')[0] || 'UNKNOWN');
    const key = `${technique}|${a.sourceIp || '?'}`;

    let acc = byKey.get(key);
    if (!acc) {
      acc = {
        key, technique, tactic: a.mitreTactic || '', sourceIp: a.sourceIp || '?',
        destIps: [], assets: [], alertIds: [], count: 0, timeSpanMinutes: 0,
        severity: 'low', investigation: '', recommendedAction: '', times: [],
      };
      byKey.set(key, acc);
    }
    acc.alertIds.push(a.id);
    acc.count++;
    if (!acc.destIps.includes(a.destIp)) acc.destIps.push(a.destIp);
    if (!acc.assets.includes(a.asset)) acc.assets.push(a.asset);
    acc.times.push(new Date(a.created_at).getTime());
    if (SEVERITY_ORDER[a.severity] > SEVERITY_ORDER[acc.severity]) acc.severity = a.severity;
  }

  const clusters: CorrelationCluster[] = [];
  for (const acc of byKey.values()) {
    if (acc.count < 2) continue;
    const spanMin = (Math.max(...acc.times) - Math.min(...acc.times)) / 60000;
    if (spanMin > windowMinutes) continue;
    acc.timeSpanMinutes = Math.round(spanMin * 10) / 10;
    acc.investigation = `${acc.technique} activity from ${acc.sourceIp} across ${acc.assets.join(', ') || 'unknown assets'} (${acc.count} correlated alerts, ${acc.timeSpanMinutes} min span).`;
    acc.recommendedAction = acc.severity === 'critical' || acc.severity === 'high'
      ? `Isolate affected assets (${acc.assets.join(', ')}) and block ${acc.sourceIp} at the perimeter; escalate to incident response.`
      : `Monitor ${acc.sourceIp} and review the ${acc.technique} pattern; request host triage if volume continues.`;
    clusters.push(acc);
  }

  clusters.sort((a, b) => b.count - a.count || SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

  const summary = clusters.length === 0
    ? `No correlated alert clusters found across ${alerts.length} alerts (grouping: MITRE technique + source IP, span <= ${windowMinutes} min).`
    : `${clusters.length} correlation cluster(s) identified across ${alerts.length} alerts (span <= ${windowMinutes} min). Top: ${clusters[0].technique} from ${clusters[0].sourceIp}.`;

  return { windowMinutes, analyzedAlerts: alerts.length, clusters, summary };
}