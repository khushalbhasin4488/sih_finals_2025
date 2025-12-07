"use client";

import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { FileBarChart, TrendingUp, Activity, Calendar, Download, BarChart3, AlertTriangle } from "lucide-react";

interface AlertStats {
    total_alerts: number;
    alerts_24h: number;
    alerts_7d: number;
    detection_methods: Array<{ method: string; count: number }>;
    alert_types: Array<{ type: string; count: number }>;
    anomaly_detection?: {
        total_anomalies: number;
        anomalies_24h: number;
        anomalies_7d: number;
        percentage_of_total: number;
        anomaly_types: Array<{ type: string; count: number }>;
        severity_breakdown: Record<string, number>;
        trend_24h: Array<{ time: string; count: number }>;
    };
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export default function ReportsPage() {
    const [stats, setStats] = useState<AlertStats | null>(null);
    const [loading, setLoading] = useState(true);

    const fetchStats = useCallback(async () => {
        setLoading(true);
        try {
            const response = await fetch(`${API_BASE}/api/v1/alerts/stats`);
            const data = await response.json();
            setStats(data);
        } catch (err) {
            console.error("Error fetching alert stats:", err);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchStats();
    }, [fetchStats]);

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-zinc-950">
                <div className="text-zinc-400">Loading reports...</div>
            </div>
        );
    }

    if (!stats) return null;

    return (
        <div className="p-8 bg-zinc-950 min-h-screen">
            <div className="max-w-7xl mx-auto">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                            <FileBarChart className="w-8 h-8 text-blue-400" />
                            Security Reports
                        </h1>
                        <p className="text-zinc-400 mt-1">Analysis and statistics</p>
                    </div>
                    <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors">
                        <Download className="w-4 h-4" />
                        Export Report
                    </button>
                </div>

                {/* Time-based Stats */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                    >
                        <div className="flex items-center gap-3 mb-4">
                            <div className="p-2 rounded-lg bg-blue-500/10">
                                <Activity className="w-5 h-5 text-blue-400" />
                            </div>
                            <h3 className="text-lg font-semibold text-white">Total Alerts</h3>
                        </div>
                        <div className="text-3xl font-bold text-white mb-2">{stats.total_alerts.toLocaleString()}</div>
                        <div className="text-sm text-zinc-400">All time</div>
                    </motion.div>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.1 }}
                        className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                    >
                        <div className="flex items-center gap-3 mb-4">
                            <div className="p-2 rounded-lg bg-orange-500/10">
                                <Calendar className="w-5 h-5 text-orange-400" />
                            </div>
                            <h3 className="text-lg font-semibold text-white">Last 24 Hours</h3>
                        </div>
                        <div className="text-3xl font-bold text-white mb-2">{stats.alerts_24h.toLocaleString()}</div>
                        <div className="text-sm text-zinc-400">Recent activity</div>
                    </motion.div>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.2 }}
                        className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                    >
                        <div className="flex items-center gap-3 mb-4">
                            <div className="p-2 rounded-lg bg-purple-500/10">
                                <TrendingUp className="w-5 h-5 text-purple-400" />
                            </div>
                            <h3 className="text-lg font-semibold text-white">Last 7 Days</h3>
                        </div>
                        <div className="text-3xl font-bold text-white mb-2">{stats.alerts_7d.toLocaleString()}</div>
                        <div className="text-sm text-zinc-400">Weekly trend</div>
                    </motion.div>
                </div>

                {/* Detection Methods */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    className="mb-8 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <h2 className="text-xl font-semibold text-white mb-6">Detection Methods</h2>
                    <div className="space-y-4">
                        {stats.detection_methods.map((method, index) => {
                            const percentage = (method.count / stats.total_alerts) * 100;
                            return (
                                <div key={method.method}>
                                    <div className="flex justify-between text-sm mb-2">
                                        <span className="text-zinc-300 capitalize">{method.method.replace(/_/g, " ")}</span>
                                        <span className="text-zinc-400">
                                            {method.count} ({percentage.toFixed(1)}%)
                                        </span>
                                    </div>
                                    <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                                        <motion.div
                                            initial={{ width: 0 }}
                                            animate={{ width: `${percentage}%` }}
                                            transition={{ delay: 0.3 + index * 0.1, duration: 0.5 }}
                                            className="h-full bg-gradient-to-r from-blue-500 to-purple-500 rounded-full"
                                        />
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </motion.div>

                {/* Alert Types */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 }}
                    className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <h2 className="text-xl font-semibold text-white mb-6">Top Alert Types</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {stats.alert_types.map((alertType, index) => (
                            <motion.div
                                key={alertType.type}
                                initial={{ opacity: 0, x: -20 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: 0.4 + index * 0.05 }}
                                className="p-4 rounded-lg bg-white/5 border border-zinc-800 hover:border-zinc-700 transition-colors"
                            >
                                <div className="flex items-center justify-between mb-2">
                                    <span className="text-sm font-medium text-white capitalize">
                                        {alertType.type.replace(/_/g, " ")}
                                    </span>
                                    <span className="text-lg font-bold text-blue-400">{alertType.count}</span>
                                </div>
                                <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-blue-500 rounded-full"
                                        style={{
                                            width: `${(alertType.count / stats.alert_types[0].count) * 100}%`,
                                        }}
                                    />
                                </div>
                            </motion.div>
                        ))}
                    </div>
                </motion.div>

                {/* Anomaly Detection Section */}
                {stats.anomaly_detection && (
                    <>
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.5 }}
                            className="mb-8 p-6 rounded-xl border border-cyan-500/20 bg-cyan-500/5"
                        >
                            <div className="flex items-center gap-3 mb-6">
                                <div className="p-2 rounded-lg bg-cyan-500/10">
                                    <BarChart3 className="w-6 h-6 text-cyan-400" />
                                </div>
                                <div>
                                    <h2 className="text-2xl font-semibold text-white">Anomaly Detection Report</h2>
                                    <p className="text-sm text-zinc-400">Statistical analysis of unusual behavior patterns</p>
                                </div>
                            </div>

                            {/* Anomaly Statistics Cards */}
                            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                                <div className="p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
                                    <div className="text-sm text-zinc-400 mb-1">Total Anomalies</div>
                                    <div className="text-2xl font-bold text-cyan-400">{stats.anomaly_detection.total_anomalies.toLocaleString()}</div>
                                    <div className="text-xs text-zinc-500 mt-1">
                                        {stats.anomaly_detection.percentage_of_total.toFixed(1)}% of all alerts
                                    </div>
                                </div>
                                <div className="p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
                                    <div className="text-sm text-zinc-400 mb-1">Last 24 Hours</div>
                                    <div className="text-2xl font-bold text-orange-400">{stats.anomaly_detection.anomalies_24h.toLocaleString()}</div>
                                    <div className="text-xs text-zinc-500 mt-1">Recent anomalies</div>
                                </div>
                                <div className="p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
                                    <div className="text-sm text-zinc-400 mb-1">Last 7 Days</div>
                                    <div className="text-2xl font-bold text-purple-400">{stats.anomaly_detection.anomalies_7d.toLocaleString()}</div>
                                    <div className="text-xs text-zinc-500 mt-1">Weekly trend</div>
                                </div>
                                <div className="p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
                                    <div className="text-sm text-zinc-400 mb-1">Anomaly Types</div>
                                    <div className="text-2xl font-bold text-emerald-400">{stats.anomaly_detection.anomaly_types.length}</div>
                                    <div className="text-xs text-zinc-500 mt-1">Unique types detected</div>
                                </div>
                            </div>

                            {/* Anomaly Trend Chart */}
                            <div className="mb-6 p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
                                <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                    <TrendingUp className="w-5 h-5 text-cyan-400" />
                                    Anomaly Trend (24 Hours)
                                </h3>
                                {stats.anomaly_detection.trend_24h && stats.anomaly_detection.trend_24h.length > 0 ? (
                                    <div className="space-y-2">
                                        <div className="flex items-end justify-between gap-1 h-40">
                                            {stats.anomaly_detection.trend_24h.map((point, index) => {
                                                const maxCount = Math.max(...stats.anomaly_detection.trend_24h.map(p => p.count), 1);
                                                const height = (point.count / maxCount) * 100;
                                                const time = new Date(point.time);
                                                return (
                                                    <div key={index} className="flex-1 flex flex-col items-center group">
                                                        <div 
                                                            className="w-full bg-gradient-to-t from-cyan-600 to-cyan-400 rounded-t transition-all hover:from-cyan-500 hover:to-cyan-300 cursor-pointer"
                                                            style={{ height: `${Math.max(height, 5)}%` }}
                                                            title={`${time.toLocaleTimeString()}: ${point.count} anomalies`}
                                                        />
                                                        {index % 4 === 0 && (
                                                            <span className="text-xs text-zinc-500 mt-1 transform -rotate-45 origin-top-left whitespace-nowrap">
                                                                {time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                                            </span>
                                                        )}
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                ) : (
                                    <div className="h-40 flex items-center justify-center text-zinc-500 text-sm">
                                        No anomaly trend data available
                                    </div>
                                )}
                            </div>

                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                {/* Anomaly Types Breakdown */}
                                <div className="p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
                                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                        <BarChart3 className="w-5 h-5 text-cyan-400" />
                                        Top Anomaly Types
                                    </h3>
                                    {stats.anomaly_detection.anomaly_types.length > 0 ? (
                                        <div className="space-y-3">
                                            {stats.anomaly_detection.anomaly_types.slice(0, 8).map((anomalyType, index) => {
                                                const maxCount = Math.max(...stats.anomaly_detection.anomaly_types.map(t => t.count));
                                                const percentage = (anomalyType.count / maxCount) * 100;
                                                return (
                                                    <div key={anomalyType.type} className="space-y-1">
                                                        <div className="flex items-center justify-between text-sm">
                                                            <span className="text-zinc-300 capitalize">
                                                                {anomalyType.type.replace(/_/g, ' ').replace('anomaly', '').trim() || 'Unknown'}
                                                            </span>
                                                            <span className="text-cyan-400 font-medium">{anomalyType.count}</span>
                                                        </div>
                                                        <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                                                            <motion.div
                                                                initial={{ width: 0 }}
                                                                animate={{ width: `${percentage}%` }}
                                                                transition={{ delay: 0.6 + index * 0.05, duration: 0.5 }}
                                                                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"
                                                            />
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    ) : (
                                        <div className="text-zinc-500 text-sm">No anomaly types detected yet</div>
                                    )}
                                </div>

                                {/* Anomaly Severity Breakdown */}
                                <div className="p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
                                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                        <AlertTriangle className="w-5 h-5 text-cyan-400" />
                                        Anomaly Severity Distribution
                                    </h3>
                                    {Object.keys(stats.anomaly_detection.severity_breakdown).length > 0 ? (
                                        <div className="space-y-4">
                                            {Object.entries(stats.anomaly_detection.severity_breakdown).map(([severity, count], index) => {
                                                const total = stats.anomaly_detection.total_anomalies;
                                                const percentage = total > 0 ? (count / total) * 100 : 0;
                                                const severityColors = {
                                                    'critical': 'text-red-400 bg-red-500/10 border-red-500/20',
                                                    'high': 'text-orange-400 bg-orange-500/10 border-orange-500/20',
                                                    'medium': 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
                                                    'low': 'text-blue-400 bg-blue-500/10 border-blue-500/20',
                                                    'info': 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20'
                                                };
                                                const colorClass = severityColors[severity.toLowerCase() as keyof typeof severityColors] || severityColors.info;
                                                
                                                return (
                                                    <div key={severity}>
                                                        <div className="flex justify-between text-sm mb-2">
                                                            <span className={`capitalize px-2 py-1 rounded text-xs font-medium ${colorClass}`}>
                                                                {severity}
                                                            </span>
                                                            <span className="text-zinc-400">
                                                                {count} ({percentage.toFixed(1)}%)
                                                            </span>
                                                        </div>
                                                        <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                                                            <motion.div
                                                                initial={{ width: 0 }}
                                                                animate={{ width: `${percentage}%` }}
                                                                transition={{ delay: 0.7 + index * 0.1, duration: 0.5 }}
                                                                className={`h-full rounded-full ${
                                                                    severity === 'critical' ? 'bg-red-500' :
                                                                    severity === 'high' ? 'bg-orange-500' :
                                                                    severity === 'medium' ? 'bg-yellow-500' :
                                                                    severity === 'low' ? 'bg-blue-500' :
                                                                    'bg-zinc-500'
                                                                }`}
                                                            />
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    ) : (
                                        <div className="text-zinc-500 text-sm">No severity data available</div>
                                    )}
                                </div>
                            </div>
                        </motion.div>
                    </>
                )}

                {/* Summary */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.6 }}
                    className="mt-8 p-6 rounded-xl border border-blue-500/20 bg-blue-500/5"
                >
                    <h2 className="text-lg font-semibold text-white mb-3">Report Summary</h2>
                    <div className="text-sm text-zinc-300 space-y-2">
                        <p>
                            • Total of <span className="font-semibold text-white">{stats.total_alerts}</span> security alerts detected
                        </p>
                        <p>
                            • <span className="font-semibold text-white">{stats.alerts_24h}</span> alerts in the last 24 hours
                        </p>
                        <p>
                            • <span className="font-semibold text-white">{stats.detection_methods.length}</span> different detection methods active
                        </p>
                        {stats.anomaly_detection && (
                            <p>
                                • <span className="font-semibold text-white">{stats.anomaly_detection.total_anomalies}</span> anomalies detected 
                                ({stats.anomaly_detection.percentage_of_total.toFixed(1)}% of total alerts)
                            </p>
                        )}
                        <p>
                            • Most common alert type:{" "}
                            <span className="font-semibold text-white capitalize">
                                {stats.alert_types[0]?.type.replace(/_/g, " ")}
                            </span>{" "}
                            ({stats.alert_types[0]?.count} occurrences)
                        </p>
                        {stats.anomaly_detection && stats.anomaly_detection.anomaly_types.length > 0 && (
                            <p>
                                • Most common anomaly type:{" "}
                                <span className="font-semibold text-white capitalize">
                                    {stats.anomaly_detection.anomaly_types[0]?.type.replace(/_/g, " ").replace('anomaly', '').trim()}
                                </span>{" "}
                                ({stats.anomaly_detection.anomaly_types[0]?.count} occurrences)
                            </p>
                        )}
                    </div>
                </motion.div>
            </div>
        </div>
    );
}
