export interface StatusResponse {
    status: string;
    db_status: string;
    version: string;
}

export interface AlertSummary {
    id: number;
    remote_ip: string;
    severity: string;
    risk_score: number;
    title: string;
    summary: string;
    status: string;
    created_at: string;
    context_reasons?: string;
    url?: string;
    user_agent?: string;
    ai_explanation?: string;
    signal_breakdown?: string;
}

export interface AlertListResponse {
    total: number;
    alerts: AlertSummary[];
}

export interface TrendPoint {
    bucket: string;
    event_count: number;
    avg_risk: number;
    peak_risk: number;
}

export interface OverviewStats {
    period_minutes: number;
    alert_counts: Record<string, number>;
    top_ips: Array<{ remote_ip: string; event_count: number; max_risk: number }>;
    attack_types: Record<string, number>;
    risk_trend: TrendPoint[];
}

export interface FlagSummary {
    flag_id: string;
    severity: string;
}

export interface AlertMini {
    severity: string;
    title: string;
    created_at: string;
}

export interface IPDetail {
    remote_ip: string;
    total_events_24h: number;
    triggered_flags: FlagSummary[];
    recent_alerts: AlertMini[];
}

export interface AIAnalysisResult {
    is_attack:     boolean;
    attack_type:   string;
    confidence:    number;
    severity:      string;
    ai_score:      number;
    explanation:   string;
    intent:        string;
    zero_day_risk: boolean;
    model_used:    string;
}

export interface FlowViolation {
    violation_id: string;
    name:         string;
    severity:     string;
    confidence:   number;
    evidence:     string;
    sequence:     string[];
}

export interface FlowAnalysis {
    remote_ip:         string;
    session_count:     number;
    total_events:      number;
    recent_sequence:   Array<{ timestamp: string; path: string; method: string; status: number }>;
    violations:        FlowViolation[];
}

export interface AISummaryResponse {
    summary: string;
}
