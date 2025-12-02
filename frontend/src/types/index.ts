/**
 * TypeScript type definitions for the application
 */

export interface LogEntry {
    id?: string;
    timestamp: string;
    raw?: string;
    appname?: string;
    file?: string;
    host?: string;
    hostname?: string;
    message?: string;
    procid?: number;
    source_type?: string;
    normalized?: Record<string, any>;
    metadata?: Record<string, any>;
    ingestion_time?: string;
}

export enum Severity {
    CRITICAL = 'critical',
    HIGH = 'high',
    MEDIUM = 'medium',
    LOW = 'low',
    INFO = 'info',
}

export interface Alert {
    id: string;
    log_id?: string;
    alert_type?: string;
    detection_method?: string;
    severity: Severity;
    description?: string;
    metadata?: Record<string, any>;
    created_at: string;
    acknowledged: boolean;
    priority_score: number;
    source_ip?: string;
    dest_ip?: string;
    user?: string;
    host?: string;
}

export interface ThreatIntel {
    id: string;
    indicator_type: string;
    indicator_value: string;
    threat_type?: string;
    confidence: number;
    source?: string;
    metadata?: Record<string, any>;
    created_at: string;
    expires_at?: string;
}

export interface DetectionRule {
    id: string;
    rule_name: string;
    rule_type: string;
    rule_definition: Record<string, any>;
    enabled: boolean;
    created_at: string;
    updated_at: string;
}

export interface DashboardStats {
    total_logs: number;
    total_alerts: number;
    critical_alerts: number;
    logs_last_hour: number;
    alerts_last_hour: number;
}
