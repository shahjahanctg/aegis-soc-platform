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
