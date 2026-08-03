export interface User {
  id: string;
  email: string;
  role: string;
  is_active: boolean;
}

export interface AlertSummary {
  id: string;
  email_id: string;
  sender: string;
  subject: string;
  risk_score: number;
  status: string;
  assigned_to?: string;
  created_at: string;
}

export interface AlertDetail {
  id: string;
  risk_score: number;
  status: string;
  assigned_to?: string;
  email: {
    id: string;
    message_id: string;
    sender: string;
    recipient: string;
    subject: string;
    body_text?: string;
    received_at: string;
  };
  ai_analysis?: {
    phishing_probability: number;
    spam_probability: number;
    critical_tokens: string[];
  };
  attachments: Array<{
    id: string;
    filename: string;
    file_size: number;
    file_hash_sha256: string;
    virus_found: boolean;
    threat_label?: string;
  }>;
  urls: Array<{
    url: string;
    vt_positives: number;
    status: string;
  }>;
  yara_matches: Array<{
    rule_name: string;
    tags?: string;
  }>;
}

export interface CaseSummary {
  id: string;
  title: string;
  severity: string;
  status: string;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  tags?: string;
  alert_id?: string;
}

export interface CaseDetail {
  id: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  assigned_to?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  tags?: string;
  notes: Array<{
    id: string;
    content: string;
    author_id?: string;
    created_at: string;
  }>;
  timeline: Array<{
    id: string;
    event_type: string;
    description: string;
    timestamp: string;
  }>;
  evidence: Array<{
    id: string;
    evidence_type: string;
    reference_id?: string;
    description: string;
    added_at: string;
  }>;
}

export interface TaskRecord {
  id: string;
  task_type: string;
  status: string;
  retry_count: number;
  created_at: string;
  completed_at?: string;
  error_message?: string;
}

export interface ProviderHealth {
  provider: string;
  health: string;
  circuit_state: string;
  supported_types: string[];
  total_requests: number;
  success_requests: number;
  failed_requests: number;
  consecutive_failures: number;
}

export interface MetricsSummary {
  statistics: {
    total_processed_today: number;
    unresolved_alerts_count: number;
    quarantined_today: number;
    false_positives_today: number;
  };
  threat_distribution: {
    phishing: number;
    spam: number;
    malware: number;
  };
}
