"use client";

import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { FileBarChart, TrendingUp, Activity, Calendar, Download } from "lucide-react";

interface AlertStats {
    total_alerts: number;
    alerts_24h: number;
    alerts_7d: number;
    detection_methods: Array<{ method: string; count: number }>;
    alert_types: Array<{ type: string; count: number }>;
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

                {/* Summary */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.5 }}
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
                        <p>
                            • Most common alert type:{" "}
                            <span className="font-semibold text-white capitalize">
                                {stats.alert_types[0]?.type.replace(/_/g, " ")}
                            </span>{" "}
                            ({stats.alert_types[0]?.count} occurrences)
                        </p>
                    </div>
                </motion.div>
            </div>
        </div>
    );
}
