"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
    Settings as SettingsIcon,
    Database,
    Server,
    Activity,
    HardDrive,
    Check,
    X,
    RefreshCw,
    Save,
    Layers
} from "lucide-react";

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

interface LogSource {
    name: string;
    enabled: boolean;
    logCount?: number;
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

// Local storage key for persisting settings
const SETTINGS_KEY = "log_analyzer_settings";

export default function SettingsPage() {
    const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [appnames, setAppnames] = useState<string[]>([]);
    const [hosts, setHosts] = useState<string[]>([]);
    const [selectedSources, setSelectedSources] = useState<Set<string>>(new Set());
    const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());
    const [saveMessage, setSaveMessage] = useState<string | null>(null);

    useEffect(() => {
        fetchAllData();
        loadSettings();
    }, []);

    const fetchAllData = async () => {
        setLoading(true);
        try {
            const [sysRes, appRes, hostRes] = await Promise.all([
                fetch(`${API_BASE}/api/v1/system/info`),
                fetch(`${API_BASE}/api/v1/appnames`),
                fetch(`${API_BASE}/api/v1/hosts`)
            ]);

            if (sysRes.ok) setSystemInfo(await sysRes.json());
            if (appRes.ok) {
                const data = await appRes.json();
                setAppnames(data.appnames || []);
            }
            if (hostRes.ok) {
                const data = await hostRes.json();
                setHosts(data.hosts || []);
            }
        } catch (err) {
            console.error("Error fetching data:", err);
        } finally {
            setLoading(false);
        }
    };

    const loadSettings = () => {
        try {
            const saved = localStorage.getItem(SETTINGS_KEY);
            if (saved) {
                const settings = JSON.parse(saved);
                if (settings.selectedSources) {
                    setSelectedSources(new Set(settings.selectedSources));
                }
                if (settings.selectedHosts) {
                    setSelectedHosts(new Set(settings.selectedHosts));
                }
            }
        } catch (err) {
            console.error("Error loading settings:", err);
        }
    };

    const saveSettings = async () => {
        setSaving(true);
        try {
            const settings = {
                selectedSources: Array.from(selectedSources),
                selectedHosts: Array.from(selectedHosts),
                updatedAt: new Date().toISOString()
            };
            localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
            setSaveMessage("Settings saved successfully!");
            setTimeout(() => setSaveMessage(null), 3000);
        } catch (err) {
            setSaveMessage("Failed to save settings");
        } finally {
            setSaving(false);
        }
    };

    const toggleSource = (source: string) => {
        setSelectedSources(prev => {
            const newSet = new Set(prev);
            if (newSet.has(source)) {
                newSet.delete(source);
            } else {
                newSet.add(source);
            }
            return newSet;
        });
    };

    const toggleHost = (host: string) => {
        setSelectedHosts(prev => {
            const newSet = new Set(prev);
            if (newSet.has(host)) {
                newSet.delete(host);
            } else {
                newSet.add(host);
            }
            return newSet;
        });
    };

    const selectAllSources = () => {
        setSelectedSources(new Set(appnames));
    };

    const clearAllSources = () => {
        setSelectedSources(new Set());
    };

    const selectAllHosts = () => {
        setSelectedHosts(new Set(hosts));
    };

    const clearAllHosts = () => {
        setSelectedHosts(new Set());
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-zinc-950">
                <div className="flex flex-col items-center gap-4">
                    <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
                    <p className="text-zinc-400">Loading settings...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="p-4 md:p-8 bg-zinc-950 min-h-screen">
            <div className="max-w-5xl mx-auto">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
                    <div>
                        <h1 className="text-2xl md:text-3xl font-bold text-white flex items-center gap-3">
                            <SettingsIcon className="w-8 h-8 text-blue-400" />
                            System Settings
                        </h1>
                        <p className="text-zinc-400 mt-1">Configure log sources and system preferences</p>
                    </div>
                    <button
                        onClick={saveSettings}
                        disabled={saving}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 rounded-lg text-white transition-colors"
                    >
                        {saving ? (
                            <RefreshCw className="w-4 h-4 animate-spin" />
                        ) : (
                            <Save className="w-4 h-4" />
                        )}
                        Save Settings
                    </button>
                </div>

                {/* Save Message */}
                {saveMessage && (
                    <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="mb-6 p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
                    >
                        {saveMessage}
                    </motion.div>
                )}

                {/* Log Sources Selection */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <div className="flex items-center justify-between mb-6">
                        <div>
                            <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                                <Layers className="w-5 h-5 text-blue-400" />
                                Log Sources (Services)
                            </h2>
                            <p className="text-sm text-zinc-500 mt-1">
                                Select which services to include in log analysis
                            </p>
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={selectAllSources}
                                className="px-3 py-1 text-xs rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors"
                            >
                                Select All
                            </button>
                            <button
                                onClick={clearAllSources}
                                className="px-3 py-1 text-xs rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors"
                            >
                                Clear All
                            </button>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                        {appnames.length > 0 ? (
                            appnames.map((source) => (
                                <button
                                    key={source}
                                    onClick={() => toggleSource(source)}
                                    className={`flex items-center justify-between p-4 rounded-lg border transition-all ${selectedSources.has(source)
                                            ? "bg-blue-500/10 border-blue-500/30 text-white"
                                            : "bg-zinc-800/50 border-zinc-700 text-zinc-400 hover:border-zinc-600"
                                        }`}
                                >
                                    <div className="flex items-center gap-3">
                                        <div className={`w-2 h-2 rounded-full ${selectedSources.has(source) ? "bg-blue-400" : "bg-zinc-600"
                                            }`} />
                                        <span className="font-medium capitalize">{source}</span>
                                    </div>
                                    {selectedSources.has(source) ? (
                                        <Check className="w-4 h-4 text-blue-400" />
                                    ) : (
                                        <X className="w-4 h-4 text-zinc-600" />
                                    )}
                                </button>
                            ))
                        ) : (
                            <div className="col-span-full text-center py-8 text-zinc-500">
                                No log sources found. Make sure the backend API is running.
                            </div>
                        )}
                    </div>

                    <div className="mt-4 pt-4 border-t border-zinc-800 flex items-center justify-between text-sm">
                        <span className="text-zinc-500">
                            {selectedSources.size} of {appnames.length} sources selected
                        </span>
                        <span className="text-zinc-400">
                            {selectedSources.size === 0 ? "All sources will be analyzed" : "Only selected sources will be analyzed"}
                        </span>
                    </div>
                </motion.div>

                {/* Hosts Selection */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.1 }}
                    className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <div className="flex items-center justify-between mb-6">
                        <div>
                            <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                                <Server className="w-5 h-5 text-purple-400" />
                                Hosts
                            </h2>
                            <p className="text-sm text-zinc-500 mt-1">
                                Filter logs by specific hosts
                            </p>
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={selectAllHosts}
                                className="px-3 py-1 text-xs rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors"
                            >
                                Select All
                            </button>
                            <button
                                onClick={clearAllHosts}
                                className="px-3 py-1 text-xs rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors"
                            >
                                Clear All
                            </button>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                        {hosts.length > 0 ? (
                            hosts.map((host) => (
                                <button
                                    key={host}
                                    onClick={() => toggleHost(host)}
                                    className={`flex items-center justify-between p-4 rounded-lg border transition-all ${selectedHosts.has(host)
                                            ? "bg-purple-500/10 border-purple-500/30 text-white"
                                            : "bg-zinc-800/50 border-zinc-700 text-zinc-400 hover:border-zinc-600"
                                        }`}
                                >
                                    <div className="flex items-center gap-3">
                                        <div className={`w-2 h-2 rounded-full ${selectedHosts.has(host) ? "bg-purple-400" : "bg-zinc-600"
                                            }`} />
                                        <span className="font-medium">{host}</span>
                                    </div>
                                    {selectedHosts.has(host) ? (
                                        <Check className="w-4 h-4 text-purple-400" />
                                    ) : (
                                        <X className="w-4 h-4 text-zinc-600" />
                                    )}
                                </button>
                            ))
                        ) : (
                            <div className="col-span-full text-center py-8 text-zinc-500">
                                No hosts found in the database.
                            </div>
                        )}
                    </div>

                    <div className="mt-4 pt-4 border-t border-zinc-800 flex items-center justify-between text-sm">
                        <span className="text-zinc-500">
                            {selectedHosts.size} of {hosts.length} hosts selected
                        </span>
                        <span className="text-zinc-400">
                            {selectedHosts.size === 0 ? "All hosts will be analyzed" : "Only selected hosts will be analyzed"}
                        </span>
                    </div>
                </motion.div>

                {/* System Status */}
                {systemInfo && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.2 }}
                        className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                    >
                        <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
                            <Activity className="w-5 h-5 text-emerald-400" />
                            System Status
                        </h2>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                                <div className="text-sm text-zinc-400 mb-1">API Status</div>
                                <div className="flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                                    <span className="text-white font-medium">{systemInfo.api.status.toUpperCase()}</span>
                                </div>
                            </div>
                            <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                                <div className="text-sm text-zinc-400 mb-1">API Version</div>
                                <div className="text-white font-medium">{systemInfo.api.version}</div>
                            </div>
                            <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                                <div className="text-sm text-zinc-400 mb-1">Database Status</div>
                                <div className="flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                                    <span className="text-white font-medium">{systemInfo.database.status.toUpperCase()}</span>
                                </div>
                            </div>
                            <div className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                                <div className="text-sm text-zinc-400 mb-1">Database Size</div>
                                <div className="flex items-center gap-2">
                                    <HardDrive className="w-4 h-4 text-zinc-500" />
                                    <span className="text-white font-medium">{systemInfo.database.size_mb} MB</span>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                )}

                {/* Detection Configuration */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
                        <Database className="w-5 h-5 text-cyan-400" />
                        Detection Engines
                    </h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {[
                            { name: "Signature Detection", desc: "Pattern-based threat detection", status: "ENABLED" },
                            { name: "Anomaly Detection", desc: "Statistical deviation analysis", status: "ENABLED" },
                            { name: "Heuristic Analysis", desc: "Behavior-based detection", status: "ENABLED" },
                            { name: "Behavioral Analysis", desc: "User behavior profiling", status: "ENABLED" },
                            { name: "Rule Engine", desc: "Custom detection rules", status: "ENABLED" },
                            { name: "Threat Intelligence", desc: "IOC matching", status: "ENABLED" },
                        ].map((engine, index) => (
                            <div key={engine.name} className="p-4 rounded-lg bg-white/5 border border-zinc-800">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <div className="text-sm font-medium text-white">{engine.name}</div>
                                        <div className="text-xs text-zinc-500 mt-1">{engine.desc}</div>
                                    </div>
                                    <span className="px-3 py-1 rounded text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                        {engine.status}
                                    </span>
                                </div>
                            </div>
                        ))}
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
                        <p className="font-medium text-white mb-2">How Log Source Selection Works</p>
                        <p>
                            When you select specific log sources or hosts, the dashboard and analysis tools will
                            filter data to show only logs from those sources. If no sources are selected,
                            all available logs will be included in the analysis.
                        </p>
                    </div>
                </motion.div>
            </div>
        </div>
    );
}
