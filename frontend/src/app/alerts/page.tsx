"use client";

import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
    AlertTriangle,
    Shield,
    Info,
    AlertCircle,
    RefreshCw,
    Filter,
    X,
    TrendingUp,
    Activity,
    Zap,
    Eye,
    ChevronDown,
    ChevronUp
} from "lucide-react";

interface Alert {
    id: string;
    log_id?: string;
    alert_type?: string;
    detection_method?: string;
    severity: string;
    description?: string;
    metadata?: any;
    created_at: string;
    acknowledged: boolean;
    priority_score: number;
    source_ip?: string;
    host?: string;
    user?: string;
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

const severityConfig = {
    critical: { color: "text-red-400", bg: "bg-red-400/10", border: "border-red-400/20", icon: AlertTriangle },
    high: { color: "text-orange-400", bg: "bg-orange-400/10", border: "border-orange-400/20", icon: AlertCircle },
    medium: { color: "text-yellow-400", bg: "bg-yellow-400/10", border: "border-yellow-400/20", icon: Shield },
    low: { color: "text-blue-400", bg: "bg-blue-400/10", border: "border-blue-400/20", icon: Info },
    info: { color: "text-zinc-400", bg: "bg-zinc-400/10", border: "border-zinc-400/20", icon: Info },
};

const detectionMethodConfig = {
    signature_detection: {
        label: "Signature",
        icon: Shield,
        color: "text-purple-400",
        description: "Pattern-based detection using known attack signatures"
    },
    anomaly_detection: {
        label: "Anomaly",
        icon: TrendingUp,
        color: "text-blue-400",
        description: "Statistical analysis detecting unusual behavior"
    },
    heuristic: {
        label: "Heuristic",
        icon: Activity,
        color: "text-green-400",
        description: "Rule-of-thumb based detection"
    },
    behavioral: {
        label: "Behavioral",
        icon: Eye,
        color: "text-cyan-400",
        description: "Behavior pattern analysis"
    },
};

export default function AlertsPage() {
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedSeverity, setSelectedSeverity] = useState("");
    const [selectedMethod, setSelectedMethod] = useState("");
    const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
    const [expandedAlerts, setExpandedAlerts] = useState<Set<string>>(new Set());

    const fetchAlerts = useCallback(async () => {
        setLoading(true);
        try {
            const params = new URLSearchParams();
            params.append("limit", "100");
            if (selectedSeverity) params.append("severity", selectedSeverity);

            const response = await fetch(`${API_BASE}/api/v1/alerts?${params}`);
            const data = await response.json();

            // Filter by detection method on client side
            let filteredData = Array.isArray(data) ? data : [];
            if (selectedMethod) {
                filteredData = filteredData.filter(alert => alert.detection_method === selectedMethod);
            }

            setAlerts(filteredData);
        } catch (err) {
            console.error("Error fetching alerts:", err);
            setAlerts([]);
        } finally {
            setLoading(false);
        }
    }, [selectedSeverity, selectedMethod]);

    useEffect(() => {
        fetchAlerts();
        const interval = setInterval(fetchAlerts, 10000);
        return () => clearInterval(interval);
    }, [fetchAlerts]);

    const toggleExpanded = (alertId: string) => {
        const newExpanded = new Set(expandedAlerts);
        if (newExpanded.has(alertId)) {
            newExpanded.delete(alertId);
        } else {
            newExpanded.add(alertId);
        }
        setExpandedAlerts(newExpanded);
    };

    const formatTimestamp = (timestamp: string) => {
        try {
            return new Date(timestamp).toLocaleString();
        } catch {
            return timestamp;
        }
    };

    const getSeverityConfig = (severity: string) => {
        return severityConfig[severity.toLowerCase() as keyof typeof severityConfig] || severityConfig.info;
    };

    const getDetectionMethodConfig = (method?: string) => {
        if (!method) return null;
        return detectionMethodConfig[method as keyof typeof detectionMethodConfig];
    };

    const renderExplanation = (alert: Alert) => {
        const method = alert.detection_method;

        if (method === "signature_detection") {
            return (
                <div className="space-y-3">
                    <div className="flex items-start gap-2">
                        <Shield className="w-4 h-4 text-purple-400 mt-1 flex-shrink-0" />
                        <div>
                            <h5 className="text-sm font-semibold text-white mb-1">Why This Was Detected</h5>
                            <p className="text-sm text-zinc-300">
                                This alert was triggered by a known attack pattern matching one of our security signatures.
                            </p>
                        </div>
                    </div>

                    {alert.metadata?.signature_id && (
                        <div className="pl-6 space-y-2">
                            <div className="text-xs">
                                <span className="text-zinc-500">Signature ID:</span>
                                <span className="ml-2 text-zinc-300 font-mono">{alert.metadata.signature_id}</span>
                            </div>
                            {alert.metadata?.matched_pattern && (
                                <div className="text-xs">
                                    <span className="text-zinc-500">Matched Pattern:</span>
                                    <div className="mt-1 bg-zinc-900 rounded p-2 font-mono text-zinc-300 overflow-auto">
                                        {alert.metadata.matched_pattern}
                                    </div>
                                </div>
                            )}
                            {alert.metadata?.category && (
                                <div className="text-xs">
                                    <span className="text-zinc-500">Attack Category:</span>
                                    <span className="ml-2 text-zinc-300">{alert.metadata.category}</span>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            );
        }

        if (method === "anomaly_detection") {
            return (
                <div className="space-y-3">
                    <div className="flex items-start gap-2">
                        <TrendingUp className="w-4 h-4 text-blue-400 mt-1 flex-shrink-0" />
                        <div>
                            <h5 className="text-sm font-semibold text-white mb-1">Why This Was Detected</h5>
                            <p className="text-sm text-zinc-300">
                                This alert was triggered because the observed behavior significantly deviates from the established baseline.
                            </p>
                        </div>
                    </div>

                    <div className="pl-6 space-y-2">
                        {alert.metadata?.current_value !== undefined && alert.metadata?.baseline_mean !== undefined && (
                            <div className="grid grid-cols-2 gap-4 text-xs">
                                <div>
                                    <span className="text-zinc-500">Current Value:</span>
                                    <div className="text-lg font-bold text-white mt-1">
                                        {typeof alert.metadata.current_value === 'number'
                                            ? alert.metadata.current_value.toFixed(1)
                                            : alert.metadata.current_value}
                                    </div>
                                </div>
                                <div>
                                    <span className="text-zinc-500">Normal Baseline:</span>
                                    <div className="text-lg font-bold text-zinc-400 mt-1">
                                        {alert.metadata.baseline_mean.toFixed(1)}
                                        {alert.metadata.baseline_std && ` ± ${alert.metadata.baseline_std.toFixed(1)}`}
                                    </div>
                                </div>
                            </div>
                        )}

                        {alert.metadata?.z_score && (
                            <div className="text-xs">
                                <span className="text-zinc-500">Statistical Deviation (Z-Score):</span>
                                <div className="mt-1 flex items-center gap-2">
                                    <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                                        <div
                                            className={`h-full ${Math.abs(alert.metadata.z_score) > 3 ? 'bg-red-500' : 'bg-yellow-500'}`}
                                            style={{ width: `${Math.min(Math.abs(alert.metadata.z_score) * 20, 100)}%` }}
                                        />
                                    </div>
                                    <span className="text-white font-mono">{alert.metadata.z_score.toFixed(2)}σ</span>
                                </div>
                                <p className="text-zinc-500 mt-1">
                                    {Math.abs(alert.metadata.z_score) > 3
                                        ? "Highly unusual (>3 standard deviations)"
                                        : "Moderately unusual (2-3 standard deviations)"}
                                </p>
                            </div>
                        )}

                        {alert.metadata?.failed_attempts && (
                            <div className="text-xs">
                                <span className="text-zinc-500">Failed Attempts:</span>
                                <span className="ml-2 text-red-400 font-bold">{alert.metadata.failed_attempts}</span>
                            </div>
                        )}

                        {alert.metadata?.request_count && (
                            <div className="text-xs">
                                <span className="text-zinc-500">Request Count:</span>
                                <span className="ml-2 text-orange-400 font-bold">{alert.metadata.request_count}</span>
                            </div>
                        )}

                        {alert.metadata?.error_count && (
                            <div className="text-xs">
                                <span className="text-zinc-500">Error Count:</span>
                                <span className="ml-2 text-yellow-400 font-bold">{alert.metadata.error_count}</span>
                            </div>
                        )}

                        {alert.metadata?.destination_count && (
                            <div className="text-xs">
                                <span className="text-zinc-500">Unique Destinations:</span>
                                <span className="ml-2 text-purple-400 font-bold">{alert.metadata.destination_count}</span>
                                <span className="ml-2 text-zinc-500">(possible port scan)</span>
                            </div>
                        )}

                        {alert.metadata?.top_ips && (
                            <div className="text-xs">
                                <span className="text-zinc-500">Top Source IPs:</span>
                                <div className="mt-1 space-y-1">
                                    {Object.entries(alert.metadata.top_ips).slice(0, 3).map(([ip, count]) => (
                                        <div key={ip} className="flex justify-between bg-zinc-900 rounded px-2 py-1">
                                            <span className="font-mono text-zinc-300">{ip}</span>
                                            <span className="text-red-400">{count as number} attempts</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {alert.metadata?.error_breakdown && (
                            <div className="text-xs">
                                <span className="text-zinc-500">Error Breakdown:</span>
                                <div className="mt-1 space-y-1">
                                    {Object.entries(alert.metadata.error_breakdown).map(([type, count]) => (
                                        <div key={type} className="flex justify-between bg-zinc-900 rounded px-2 py-1">
                                            <span className="text-zinc-300 capitalize">{type.replace(/_/g, ' ')}</span>
                                            <span className="text-yellow-400">{count as number}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {alert.metadata?.suspicious_commands && (
                            <div className="text-xs">
                                <span className="text-zinc-500">Suspicious Commands:</span>
                                <div className="mt-1 space-y-1">
                                    {alert.metadata.suspicious_commands.slice(0, 3).map((cmd: string, idx: number) => (
                                        <div key={idx} className="bg-zinc-900 rounded px-2 py-1 font-mono text-red-400 text-xs overflow-auto">
                                            {cmd}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        return null;
    };

    return (
        <div className="p-8 bg-zinc-950 min-h-screen">
            <div className="max-w-7xl mx-auto">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-3xl font-bold text-white">Security Alerts</h1>
                        <p className="text-zinc-400 mt-1">Multi-method threat detection results</p>
                    </div>
                    <button
                        onClick={fetchAlerts}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                    >
                        <RefreshCw className="w-4 h-4" />
                        Refresh
                    </button>
                </div>

                {/* Filters */}
                <div className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">
                                <Filter className="w-4 h-4 inline mr-2" />
                                Severity
                            </label>
                            <select
                                value={selectedSeverity}
                                onChange={(e) => setSelectedSeverity(e.target.value)}
                                className="w-full px-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                            >
                                <option value="">All Severities</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">
                                <Zap className="w-4 h-4 inline mr-2" />
                                Detection Method
                            </label>
                            <select
                                value={selectedMethod}
                                onChange={(e) => setSelectedMethod(e.target.value)}
                                className="w-full px-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                            >
                                <option value="">All Methods</option>
                                <option value="signature_detection">Signature Detection</option>
                                <option value="anomaly_detection">Anomaly Detection</option>
                                <option value="heuristic">Heuristic Analysis</option>
                                <option value="behavioral">Behavioral Analysis</option>
                            </select>
                        </div>

                        <div className="flex items-end">
                            <div className="text-sm text-zinc-400">
                                <div className="font-semibold text-white text-lg">{alerts.length}</div>
                                <div>alerts found</div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Alerts List */}
                <div className="space-y-4">
                    {loading ? (
                        <div className="text-center py-12 text-zinc-500">Loading alerts...</div>
                    ) : alerts.length === 0 ? (
                        <div className="text-center py-12">
                            <Shield className="w-16 h-16 text-zinc-700 mx-auto mb-4" />
                            <div className="text-zinc-500">No alerts found</div>
                            <div className="text-sm text-zinc-600 mt-2">All systems operating normally</div>
                        </div>
                    ) : (
                        alerts.map((alert) => {
                            const config = getSeverityConfig(alert.severity);
                            const Icon = config.icon;
                            const methodConfig = getDetectionMethodConfig(alert.detection_method);
                            const isExpanded = expandedAlerts.has(alert.id);

                            return (
                                <motion.div
                                    key={alert.id}
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    className={`rounded-xl border ${config.border} ${config.bg} overflow-hidden`}
                                >
                                    <div
                                        className="p-6 cursor-pointer hover:bg-white/5 transition-colors"
                                        onClick={() => toggleExpanded(alert.id)}
                                    >
                                        <div className="flex items-start justify-between">
                                            <div className="flex items-start gap-4 flex-1">
                                                <div className={`p-2 rounded-lg ${config.bg}`}>
                                                    <Icon className={`w-5 h-5 ${config.color}`} />
                                                </div>

                                                <div className="flex-1">
                                                    <div className="flex items-center gap-3 mb-2 flex-wrap">
                                                        <h3 className="text-lg font-semibold text-white">
                                                            {alert.description || alert.alert_type || "Unknown Alert"}
                                                        </h3>
                                                        <span className={`px-2 py-1 rounded text-xs font-medium ${config.bg} ${config.color}`}>
                                                            {alert.severity.toUpperCase()}
                                                        </span>
                                                        {methodConfig && (
                                                            <span className={`px-2 py-1 rounded text-xs bg-zinc-800 ${methodConfig.color} flex items-center gap-1`}>
                                                                <methodConfig.icon className="w-3 h-3" />
                                                                {methodConfig.label}
                                                            </span>
                                                        )}
                                                    </div>

                                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm mb-3">
                                                        {alert.host && (
                                                            <div>
                                                                <span className="text-zinc-500">Host:</span>
                                                                <span className="ml-2 text-zinc-300">{alert.host}</span>
                                                            </div>
                                                        )}
                                                        {alert.source_ip && (
                                                            <div>
                                                                <span className="text-zinc-500">Source IP:</span>
                                                                <span className="ml-2 text-zinc-300 font-mono">{alert.source_ip}</span>
                                                            </div>
                                                        )}
                                                        {alert.user && (
                                                            <div>
                                                                <span className="text-zinc-500">User:</span>
                                                                <span className="ml-2 text-zinc-300">{alert.user}</span>
                                                            </div>
                                                        )}
                                                        <div>
                                                            <span className="text-zinc-500">Priority:</span>
                                                            <span className="ml-2 text-zinc-300">{alert.priority_score.toFixed(1)}</span>
                                                        </div>
                                                    </div>

                                                    <div className="text-xs text-zinc-500">
                                                        {formatTimestamp(alert.created_at)}
                                                    </div>
                                                </div>
                                            </div>

                                            <button className="ml-4 p-2 hover:bg-zinc-800 rounded-lg transition-colors">
                                                {isExpanded ? (
                                                    <ChevronUp className="w-5 h-5 text-zinc-400" />
                                                ) : (
                                                    <ChevronDown className="w-5 h-5 text-zinc-400" />
                                                )}
                                            </button>
                                        </div>
                                    </div>

                                    {/* Expanded Details */}
                                    <AnimatePresence>
                                        {isExpanded && (
                                            <motion.div
                                                initial={{ opacity: 0, height: 0 }}
                                                animate={{ opacity: 1, height: "auto" }}
                                                exit={{ opacity: 0, height: 0 }}
                                                className="border-t border-zinc-800"
                                            >
                                                <div className="p-6 bg-zinc-900/30">
                                                    {renderExplanation(alert)}

                                                    {alert.metadata && Object.keys(alert.metadata).length > 0 && (
                                                        <div className="mt-4 pt-4 border-t border-zinc-800">
                                                            <h5 className="text-sm font-semibold text-zinc-400 mb-2">Raw Metadata</h5>
                                                            <div className="bg-zinc-950 rounded-lg p-3 text-xs font-mono text-zinc-300 overflow-auto max-h-48">
                                                                <pre>{JSON.stringify(alert.metadata, null, 2)}</pre>
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </motion.div>
                            );
                        })
                    )}
                </div>
            </div>
        </div>
    );
}
