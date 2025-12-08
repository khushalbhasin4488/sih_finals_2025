"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
    Activity,
    Shield,
    AlertTriangle,
    Database,
    TrendingUp,
    Clock,
    Users,
    Globe,
    Zap,
    ArrowUpRight,
    ArrowDownRight
} from "lucide-react";
import {
    SeverityPieChart,
    AlertTypesBarChart,
    HostActivityChart,
    LogsTimelineChart,
    DetectionMethodsChart
} from "@/components/charts/DashboardCharts";
import { useNetwork } from "@/lib/NetworkContext";

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

interface AlertStats {
    total_alerts: number;
    alerts_24h: number;
    alerts_7d: number;
    detection_methods: Array<{ method: string; count: number }>;
    alert_types: Array<{ type: string; count: number }>;
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export default function DashboardPage() {
    const [stats, setStats] = useState<Stats | null>(null);
    const [alertStats, setAlertStats] = useState<AlertStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [currentTime, setCurrentTime] = useState(new Date());
    const { selectedNetwork } = useNetwork();

    useEffect(() => {
        fetchAllData();
        const interval = setInterval(fetchAllData, 10000);
        const timeInterval = setInterval(() => setCurrentTime(new Date()), 1000);
        return () => {
            clearInterval(interval);
            clearInterval(timeInterval);
        };
    }, [selectedNetwork]); // Re-fetch when network changes

    const fetchAllData = async () => {
        try {
            const networkParam = selectedNetwork ? `?network=${encodeURIComponent(selectedNetwork)}` : '';
            const [statsRes, alertStatsRes] = await Promise.all([
                fetch(`${API_BASE}/api/v1/stats${networkParam}`),
                fetch(`${API_BASE}/api/v1/alerts/stats${networkParam}`)
            ]);

            if (statsRes.ok) {
                setStats(await statsRes.json());
            }
            if (alertStatsRes.ok) {
                setAlertStats(await alertStatsRes.json());
            }
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Connection error");
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-zinc-950">
                <div className="flex flex-col items-center gap-4">
                    <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
                    <p className="text-zinc-400">Loading dashboard...</p>
                </div>
            </div>
        );
    }

    if (error || !stats) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-zinc-950">
                <div className="text-center p-8 rounded-xl bg-zinc-900 border border-zinc-800">
                    <AlertTriangle className="w-12 h-12 text-yellow-500 mx-auto mb-4" />
                    <h2 className="text-xl font-semibold text-white mb-2">Connection Error</h2>
                    <p className="text-zinc-400 mb-4">{error || "Unable to load data"}</p>
                    <button
                        onClick={fetchAllData}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white transition-colors"
                    >
                        Retry
                    </button>
                </div>
            </div>
        );
    }

    const alertPercentChange = stats.total_alerts > 0
        ? ((stats.alerts_last_hour / stats.total_alerts) * 100).toFixed(1)
        : "0";

    return (
        <main className="min-h-screen p-4 md:p-6 lg:p-8 bg-zinc-950 text-zinc-50">
            {/* Header */}
            <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
                <div>
                    <h1 className="text-2xl md:text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-zinc-400">
                        Security Dashboard
                    </h1>
                    <p className="text-zinc-500 text-sm mt-1">Real-time monitoring and threat analysis</p>
                </div>
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20">
                        <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                        </span>
                        <span className="text-emerald-400 text-sm font-medium">Live</span>
                    </div>
                    <div className="hidden sm:flex items-center gap-2 text-zinc-500 text-sm">
                        <Clock className="w-4 h-4" />
                        {currentTime.toLocaleTimeString()}
                    </div>
                </div>
            </header>

            {/* Main Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                <StatCard
                    title="Total Logs"
                    value={stats.total_logs.toLocaleString()}
                    subtitle={`+${stats.logs_last_hour} this hour`}
                    icon={Database}
                    color="blue"
                    delay={0}
                />
                <StatCard
                    title="Active Alerts"
                    value={stats.total_alerts.toLocaleString()}
                    subtitle={`${stats.alerts_last_hour} new alerts`}
                    icon={AlertTriangle}
                    color="red"
                    trend={stats.alerts_last_hour > 0 ? "up" : "neutral"}
                    delay={0.1}
                />
                <StatCard
                    title="Critical"
                    value={stats.critical_alerts.toString()}
                    subtitle="High priority"
                    icon={Shield}
                    color="purple"
                    delay={0.2}
                />
                <StatCard
                    title="Throughput"
                    value={`${stats.logs_last_hour}/hr`}
                    subtitle="Log ingestion rate"
                    icon={Zap}
                    color="emerald"
                    delay={0.3}
                />
            </div>

            {/* Charts Row 1 */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                {/* Severity Distribution */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 }}
                    className="lg:col-span-1 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm relative overflow-hidden"
                >
                    <div className="absolute top-0 right-0 w-32 h-32 bg-purple-500/5 rounded-full blur-3xl" />
                    <h2 className="text-lg font-semibold mb-2 relative">Alert Severity</h2>
                    <p className="text-zinc-500 text-sm mb-4">Distribution by priority level</p>
                    <SeverityPieChart
                        data={{
                            critical: stats.critical_alerts,
                            high: stats.high_alerts,
                            medium: stats.medium_alerts,
                            low: stats.low_alerts
                        }}
                    />
                </motion.div>

                {/* Alert Types Bar Chart */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.5 }}
                    className="lg:col-span-2 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm relative overflow-hidden"
                >
                    <div className="absolute top-0 right-0 w-48 h-48 bg-blue-500/5 rounded-full blur-3xl" />
                    <h2 className="text-lg font-semibold mb-2 relative">Top Alert Categories</h2>
                    <p className="text-zinc-500 text-sm mb-4">Most frequent alert types detected</p>
                    <AlertTypesBarChart data={stats.top_alert_types} />
                </motion.div>
            </div>

            {/* Charts Row 2 */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                {/* Host Activity */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.6 }}
                    className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm relative overflow-hidden"
                >
                    <div className="absolute bottom-0 left-0 w-32 h-32 bg-emerald-500/5 rounded-full blur-3xl" />
                    <h2 className="text-lg font-semibold mb-2 relative">Host Activity</h2>
                    <p className="text-zinc-500 text-sm mb-4">Logs by source host</p>
                    <HostActivityChart data={stats.top_hosts} />
                </motion.div>

                {/* Detection Methods */}
                {alertStats && alertStats.detection_methods?.length > 0 && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.7 }}
                        className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm relative overflow-hidden"
                    >
                        <div className="absolute bottom-0 right-0 w-32 h-32 bg-cyan-500/5 rounded-full blur-3xl" />
                        <h2 className="text-lg font-semibold mb-2 relative">Detection Methods</h2>
                        <p className="text-zinc-500 text-sm mb-4">Alerts by detection engine</p>
                        <DetectionMethodsChart data={alertStats.detection_methods} />
                    </motion.div>
                )}
            </div>

            {/* Summary Cards Row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <SummaryCard
                    title="Alerts (24h)"
                    value={alertStats?.alerts_24h?.toLocaleString() || "0"}
                    icon={Activity}
                    color="blue"
                />
                <SummaryCard
                    title="Alerts (7d)"
                    value={alertStats?.alerts_7d?.toLocaleString() || "0"}
                    icon={TrendingUp}
                    color="purple"
                />
                <SummaryCard
                    title="Unique Hosts"
                    value={stats.top_hosts.length.toString()}
                    icon={Globe}
                    color="emerald"
                />
                <SummaryCard
                    title="Alert Types"
                    value={stats.top_alert_types.length.toString()}
                    icon={Users}
                    color="orange"
                />
            </div>

            {/* Quick Stats Footer */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.8 }}
                className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/30 backdrop-blur-sm"
            >
                <div className="flex flex-wrap justify-between gap-4 text-sm">
                    <div className="flex items-center gap-6">
                        <span className="text-zinc-500">Severity Breakdown:</span>
                        <span className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-red-500" />
                            <span className="text-zinc-400">Critical: {stats.critical_alerts}</span>
                        </span>
                        <span className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-orange-500" />
                            <span className="text-zinc-400">High: {stats.high_alerts}</span>
                        </span>
                        <span className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-yellow-500" />
                            <span className="text-zinc-400">Medium: {stats.medium_alerts}</span>
                        </span>
                        <span className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-blue-500" />
                            <span className="text-zinc-400">Low: {stats.low_alerts}</span>
                        </span>
                    </div>
                    <span className="text-zinc-500">
                        Last updated: {currentTime.toLocaleTimeString()}
                    </span>
                </div>
            </motion.div>
        </main>
    );
}

// Stat Card Component
function StatCard({
    title,
    value,
    subtitle,
    icon: Icon,
    color,
    trend,
    delay = 0
}: {
    title: string;
    value: string;
    subtitle: string;
    icon: any;
    color: "blue" | "red" | "purple" | "emerald" | "orange" | "cyan";
    trend?: "up" | "down" | "neutral";
    delay?: number;
}) {
    const colors = {
        blue: { bg: "bg-blue-500/10", border: "border-blue-500/20", text: "text-blue-400", icon: "text-blue-400" },
        red: { bg: "bg-red-500/10", border: "border-red-500/20", text: "text-red-400", icon: "text-red-400" },
        purple: { bg: "bg-purple-500/10", border: "border-purple-500/20", text: "text-purple-400", icon: "text-purple-400" },
        emerald: { bg: "bg-emerald-500/10", border: "border-emerald-500/20", text: "text-emerald-400", icon: "text-emerald-400" },
        orange: { bg: "bg-orange-500/10", border: "border-orange-500/20", text: "text-orange-400", icon: "text-orange-400" },
        cyan: { bg: "bg-cyan-500/10", border: "border-cyan-500/20", text: "text-cyan-400", icon: "text-cyan-400" },
    };

    const c = colors[color];

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay }}
            className={`p-4 md:p-6 rounded-xl border ${c.border} ${c.bg} backdrop-blur-sm hover:scale-[1.02] transition-transform cursor-default`}
        >
            <div className="flex items-start justify-between mb-3">
                <div className={`p-2 rounded-lg ${c.bg}`}>
                    <Icon className={`w-5 h-5 ${c.icon}`} />
                </div>
                {trend === "up" && <ArrowUpRight className="w-4 h-4 text-red-400" />}
                {trend === "down" && <ArrowDownRight className="w-4 h-4 text-emerald-400" />}
            </div>
            <h3 className="text-2xl md:text-3xl font-bold text-white mb-1">{value}</h3>
            <p className="text-sm text-zinc-400">{title}</p>
            <p className="text-xs text-zinc-500 mt-1">{subtitle}</p>
        </motion.div>
    );
}

// Summary Card Component
function SummaryCard({
    title,
    value,
    icon: Icon,
    color
}: {
    title: string;
    value: string;
    icon: any;
    color: "blue" | "purple" | "emerald" | "orange";
}) {
    const colors = {
        blue: "text-blue-400",
        purple: "text-purple-400",
        emerald: "text-emerald-400",
        orange: "text-orange-400"
    };

    return (
        <div className="flex items-center gap-4 p-4 rounded-xl border border-zinc-800 bg-zinc-900/30">
            <Icon className={`w-8 h-8 ${colors[color]}`} />
            <div>
                <p className="text-2xl font-bold text-white">{value}</p>
                <p className="text-sm text-zinc-500">{title}</p>
            </div>
        </div>
    );
}
