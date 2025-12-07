"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Settings as SettingsIcon, Database, Server, Activity, HardDrive } from "lucide-react";

interface SystemInfo {
    database: {
        path: string;
        size_mb: number;
        status: string;
    };
    api: {
        version: string;
        status: string;
    };
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export default function SettingsPage() {
    const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchSystemInfo();
    }, []);

    const fetchSystemInfo = async () => {
        setLoading(true);
        try {
            const response = await fetch(`${API_BASE}/api/v1/system/info`);
            const data = await response.json();
            setSystemInfo(data);
        } catch (err) {
            console.error("Error fetching system info:", err);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-zinc-950">
                <div className="text-zinc-400">Loading settings...</div>
            </div>
        );
    }

    if (!systemInfo) return null;

    return (
        <div className="p-8 bg-zinc-950 min-h-screen">
            <div className="max-w-5xl mx-auto">
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                        <SettingsIcon className="w-8 h-8 text-blue-400" />
                        System Settings
                    </h1>
                    <p className="text-zinc-400 mt-1">Configuration and system information</p>
                </div>

                {/* System Status */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
                        <Activity className="w-5 h-5 text-blue-400" />
                        System Status
                    </h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-sm text-zinc-400">API Status</span>
                                <span className="px-2 py-1 rounded text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    {systemInfo.api.status.toUpperCase()}
                                </span>
                            </div>
                            <div className="text-sm text-zinc-300">Version: {systemInfo.api.version}</div>
                        </div>

                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-sm text-zinc-400">Database Status</span>
                                <span className="px-2 py-1 rounded text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    {systemInfo.database.status.toUpperCase()}
                                </span>
                            </div>
                            <div className="text-sm text-zinc-300">Size: {systemInfo.database.size_mb} MB</div>
                        </div>
                    </div>
                </motion.div>

                {/* Database Configuration */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.1 }}
                    className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
                        <Database className="w-5 h-5 text-blue-400" />
                        Database Configuration
                    </h2>
                    <div className="space-y-4">
                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="text-sm text-zinc-400 mb-1">Database Path</div>
                            <div className="text-sm font-mono text-zinc-300 break-all">{systemInfo.database.path}</div>
                        </div>

                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="text-sm text-zinc-400 mb-1">Database Size</div>
                            <div className="flex items-center gap-2">
                                <HardDrive className="w-4 h-4 text-zinc-500" />
                                <div className="text-sm text-zinc-300">{systemInfo.database.size_mb} MB</div>
                            </div>
                        </div>

                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="text-sm text-zinc-400 mb-1">Connection Type</div>
                            <div className="text-sm text-zinc-300">DuckDB (Embedded)</div>
                        </div>
                    </div>
                </motion.div>

                {/* API Configuration */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                    className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
                        <Server className="w-5 h-5 text-blue-400" />
                        API Configuration
                    </h2>
                    <div className="space-y-4">
                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="text-sm text-zinc-400 mb-1">API Base URL</div>
                            <div className="text-sm font-mono text-zinc-300">{API_BASE}</div>
                        </div>

                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="text-sm text-zinc-400 mb-1">API Version</div>
                            <div className="text-sm text-zinc-300">{systemInfo.api.version}</div>
                        </div>

                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="text-sm text-zinc-400 mb-1">CORS Enabled</div>
                            <div className="text-sm text-zinc-300">Yes (localhost:3000, localhost:3001)</div>
                        </div>
                    </div>
                </motion.div>

                {/* Detection Configuration */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <h2 className="text-xl font-semibold text-white mb-6">Detection Configuration</h2>
                    <div className="space-y-4">
                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="flex items-center justify-between">
                                <div>
                                    <div className="text-sm font-medium text-white">Signature Detection</div>
                                    <div className="text-xs text-zinc-400 mt-1">Pattern-based threat detection</div>
                                </div>
                                <span className="px-3 py-1 rounded text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    ENABLED
                                </span>
                            </div>
                        </div>

                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="flex items-center justify-between">
                                <div>
                                    <div className="text-sm font-medium text-white">Real-time Analysis</div>
                                    <div className="text-xs text-zinc-400 mt-1">Continuous log monitoring</div>
                                </div>
                                <span className="px-3 py-1 rounded text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    ENABLED
                                </span>
                            </div>
                        </div>

                        <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                            <div className="flex items-center justify-between">
                                <div>
                                    <div className="text-sm font-medium text-white">Alert Deduplication</div>
                                    <div className="text-xs text-zinc-400 mt-1">Reduce duplicate alerts</div>
                                </div>
                                <span className="px-3 py-1 rounded text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    ENABLED
                                </span>
                            </div>
                        </div>
                    </div>
                </motion.div>

                {/* Info Note */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 }}
                    className="mt-6 p-4 rounded-xl border border-blue-500/20 bg-blue-500/5"
                >
                    <div className="text-sm text-zinc-300">
                        <p className="font-medium text-white mb-2">Configuration Note</p>
                        <p>
                            System settings are managed through configuration files and environment variables.
                            To modify settings, update the respective configuration files in the backend directory
                            and restart the API server.
                        </p>
                    </div>
                </motion.div>
            </div>
        </div>
    );
}
