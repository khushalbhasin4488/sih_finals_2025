"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
    Activity,
    Shield,
    AlertTriangle,
    Database,
    Server,
    TrendingUp,
    Clock
} from "lucide-react";

interface Stats {
    total_logs: number;
    total_alerts: number;
    critical_alerts: number;
    high_alerts: number;
    medium_alerts: number;
    low_alerts: number;
    logs_last_hour: number;
    alerts_last_hour: number;
    top_hosts: Array<{ host: string; count: number }>;
    top_alert_types: Array<{ type: string; count: number }>;
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export default function DashboardPage() {
    const [stats, setStats] = useState<Stats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        fetchStats();
        // Refresh every 10 seconds
        const interval = setInterval(fetchStats, 10000);
        return () => clearInterval(interval);
    }, []);

    const fetchStats = async () => {
        try {
            const response = await fetch(`${API_BASE}/api/v1/stats`);
            if (!response.ok) throw new Error("Failed to fetch stats");
            const data = await response.json();
            setStats(data);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Unknown error");
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-zinc-950">
                <div className="text-zinc-400">Loading...</div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-zinc-950">
                <div className="text-red-400">Error: {error}</div>
            </div>
        );
    }

    if (!stats) return null;

    const statCards = [
        {
            name: "Total Logs",
            value: stats.total_logs.toLocaleString(),
            change: `+${stats.logs_last_hour}`,
            trend: "up",
            icon: Database,
            color: "text-blue-400",
            bg: "bg-blue-400/10",
            border: "border-blue-400/20"
        },
        {
            name: "Active Alerts",
            value: stats.total_alerts.toLocaleString(),
            change: `+${stats.alerts_last_hour}`,
            trend: stats.alerts_last_hour > 0 ? "up" : "neutral",
            icon: AlertTriangle,
            color: "text-red-400",
            bg: "bg-red-400/10",
            border: "border-red-400/20"
        },
        {
            name: "Critical Alerts",
            value: stats.critical_alerts.toString(),
            change: "High Priority",
            trend: "neutral",
            icon: Shield,
            color: "text-purple-400",
            bg: "bg-purple-400/10",
            border: "border-purple-400/20"
        },
        {
            name: "Logs/Hour",
            value: stats.logs_last_hour.toString(),
            change: "Last Hour",
            trend: "neutral",
            icon: TrendingUp,
            color: "text-emerald-400",
            bg: "bg-emerald-400/10",
            border: "border-emerald-400/20"
        },
    ];

    return (
        <main className="min-h-screen p-8 bg-zinc-950 text-zinc-50 relative overflow-hidden">
            {/* Background Effects */}
            <div className="absolute top-0 left-0 w-full h-96 bg-blue-900/10 blur-[100px] pointer-events-none" />
            <div className="absolute bottom-0 right-0 w-full h-96 bg-purple-900/5 blur-[100px] pointer-events-none" />

            <div className="max-w-7xl mx-auto relative z-10">
                <header className="flex items-center justify-between mb-12">
                    <div>
                        <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-zinc-400">
                            Security Dashboard
                        </h1>
                        <p className="text-zinc-400 mt-1">Real-time monitoring and threat analysis</p>
                    </div>

                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm">
                            <span className="relative flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                            </span>
                            System Operational
                        </div>
                        <div className="text-sm text-zinc-500 flex items-center gap-2">
                            <Clock className="w-4 h-4" />
                            Auto-refresh: 10s
                        </div>
                    </div>
                </header>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    {statCards.map((stat, index) => (
                        <motion.div
                            key={stat.name}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: index * 0.1 }}
                            className={`p-6 rounded-xl border bg-zinc-900/50 backdrop-blur-sm hover:bg-zinc-900/80 transition-colors ${stat.border}`}
                        >
                            <div className="flex items-start justify-between mb-4">
                                <div className={`p-2 rounded-lg ${stat.bg}`}>
                                    <stat.icon className={`w-5 h-5 ${stat.color}`} />
                                </div>
                                <span className={`text-xs font-medium px-2 py-1 rounded-full ${stat.trend === 'up' ? 'bg-emerald-500/10 text-emerald-400' :
                                        'bg-zinc-500/10 text-zinc-400'
                                    }`}>
                                    {stat.change}
                                </span>
                            </div>
                            <h3 className="text-2xl font-bold text-white mb-1">{stat.value}</h3>
                            <p className="text-sm text-zinc-400">{stat.name}</p>
                        </motion.div>
                    ))}
                </div>

                {/* Severity Breakdown */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.4 }}
                        className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm"
                    >
                        <h2 className="text-lg font-semibold mb-6">Alert Severity Distribution</h2>
                        <div className="space-y-4">
                            <div>
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-zinc-400">Critical</span>
                                    <span className="text-red-400 font-medium">{stats.critical_alerts}</span>
                                </div>
                                <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-red-500 rounded-full transition-all"
                                        style={{ width: `${(stats.critical_alerts / (stats.total_alerts || 1)) * 100}%` }}
                                    />
                                </div>
                            </div>

                            <div>
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-zinc-400">High</span>
                                    <span className="text-orange-400 font-medium">{stats.high_alerts}</span>
                                </div>
                                <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-orange-500 rounded-full transition-all"
                                        style={{ width: `${(stats.high_alerts / (stats.total_alerts || 1)) * 100}%` }}
                                    />
                                </div>
                            </div>

                            <div>
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-zinc-400">Medium</span>
                                    <span className="text-yellow-400 font-medium">{stats.medium_alerts}</span>
                                </div>
                                <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-yellow-500 rounded-full transition-all"
                                        style={{ width: `${(stats.medium_alerts / (stats.total_alerts || 1)) * 100}%` }}
                                    />
                                </div>
                            </div>

                            <div>
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-zinc-400">Low</span>
                                    <span className="text-blue-400 font-medium">{stats.low_alerts}</span>
                                </div>
                                <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-blue-500 rounded-full transition-all"
                                        style={{ width: `${(stats.low_alerts / (stats.total_alerts || 1)) * 100}%` }}
                                    />
                                </div>
                            </div>
                        </div>
                    </motion.div>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.5 }}
                        className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm"
                    >
                        <h2 className="text-lg font-semibold mb-6">Top Hosts</h2>
                        <div className="space-y-3">
                            {stats.top_hosts.map((host, index) => (
                                <div key={host.host} className="flex items-center justify-between p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors">
                                    <div className="flex items-center gap-3">
                                        <Server className="w-4 h-4 text-zinc-400" />
                                        <span className="text-sm font-medium text-white">{host.host}</span>
                                    </div>
                                    <span className="text-sm text-zinc-400">{host.count} logs</span>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                </div>

                {/* Top Alert Types */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.6 }}
                    className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm"
                >
                    <h2 className="text-lg font-semibold mb-6">Top Alert Types</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {stats.top_alert_types.map((alertType) => (
                            <div key={alertType.type} className="p-4 rounded-lg bg-white/5 border border-zinc-800 hover:border-zinc-700 transition-colors">
                                <div className="flex items-center justify-between mb-2">
                                    <span className="text-sm font-medium text-white capitalize">{alertType.type.replace(/_/g, ' ')}</span>
                                    <span className="text-xs px-2 py-1 rounded-full bg-blue-500/10 text-blue-400">{alertType.count}</span>
                                </div>
                                <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                                    <div className="h-full bg-blue-500 rounded-full" style={{ width: '100%' }} />
                                </div>
                            </div>
                        ))}
                    </div>
                </motion.div>
            </div>
        </main>
    );
}
