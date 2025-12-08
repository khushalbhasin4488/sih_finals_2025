"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
    Globe,
    Shield,
    AlertTriangle,
    Target,
    Activity,
    Clock,
    TrendingUp,
    ExternalLink,
    Search,
    Filter,
    ChevronRight
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

// MITRE ATT&CK Techniques mapping
const MITRE_TECHNIQUES = [
    { id: "T1110", name: "Brute Force", tactic: "Credential Access", count: 0, color: "red" },
    { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", count: 0, color: "orange" },
    { id: "T1021", name: "Remote Services", tactic: "Lateral Movement", count: 0, color: "yellow" },
    { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion", count: 0, color: "purple" },
    { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", count: 0, color: "cyan" },
    { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", count: 0, color: "pink" },
    { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", count: 0, color: "blue" },
    { id: "T1569", name: "System Services", tactic: "Execution", count: 0, color: "emerald" },
];

interface AlertStats {
    total_alerts: number;
    alerts_24h: number;
    detection_methods: Array<{ method: string; count: number }>;
    alert_types: Array<{ type: string; count: number }>;
}

interface IOCMatch {
    id: string;
    indicator: string;
    type: "ip" | "domain" | "hash" | "url";
    threat_type: string;
    confidence: number;
    matched_at: string;
    source: string;
    severity: "critical" | "high" | "medium" | "low";
}

export default function ThreatIntelPage() {
    const [alertStats, setAlertStats] = useState<AlertStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<"overview" | "ioc" | "mitre">("overview");
    const [searchQuery, setSearchQuery] = useState("");

    // Sample IOC matches (in real app, fetch from API)
    const [iocMatches] = useState<IOCMatch[]>([
        { id: "1", indicator: "185.220.101.35", type: "ip", threat_type: "Tor Exit Node", confidence: 95, matched_at: new Date().toISOString(), source: "Threat Intel Feed", severity: "high" },
        { id: "2", indicator: "45.142.212.61", type: "ip", threat_type: "Known Scanner", confidence: 88, matched_at: new Date(Date.now() - 3600000).toISOString(), source: "Blocklist", severity: "medium" },
        { id: "3", indicator: "evil-domain.com", type: "domain", threat_type: "Phishing", confidence: 92, matched_at: new Date(Date.now() - 7200000).toISOString(), source: "Phishing DB", severity: "critical" },
        { id: "4", indicator: "ed01ebfbc9eb5bbea545af4d01bf5f10", type: "hash", threat_type: "Ransomware", confidence: 100, matched_at: new Date(Date.now() - 86400000).toISOString(), source: "VirusTotal", severity: "critical" },
        { id: "5", indicator: "89.248.165.75", type: "ip", threat_type: "Brute Force", confidence: 78, matched_at: new Date(Date.now() - 10800000).toISOString(), source: "AbuseIPDB", severity: "high" },
    ]);

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_BASE}/api/v1/alerts/stats`);
            if (res.ok) {
                const data = await res.json();
                setAlertStats(data);
                // Update MITRE counts based on alert types
                updateMitreCounts(data.alert_types || []);
            }
        } catch (err) {
            console.error("Error fetching data:", err);
        } finally {
            setLoading(false);
        }
    };

    const updateMitreCounts = (alertTypes: Array<{ type: string; count: number }>) => {
        // Map alert types to MITRE techniques
        const mapping: Record<string, string> = {
            "brute_force": "T1110",
            "authentication_attack": "T1110",
            "command_injection": "T1059",
            "lateral_movement": "T1021",
            "privilege_escalation": "T1078",
            "c2_communication": "T1071",
            "data_exfiltration": "T1048",
            "exploit": "T1190",
        };

        alertTypes.forEach(at => {
            const techniqueId = mapping[at.type.toLowerCase()];
            if (techniqueId) {
                const technique = MITRE_TECHNIQUES.find(t => t.id === techniqueId);
                if (technique) technique.count += at.count;
            }
        });
    };

    const filteredIOCs = iocMatches.filter(ioc =>
        ioc.indicator.toLowerCase().includes(searchQuery.toLowerCase()) ||
        ioc.threat_type.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const severityColor = (severity: string) => {
        const colors = {
            critical: "bg-red-500/10 text-red-400 border-red-500/20",
            high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
            medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
            low: "bg-blue-500/10 text-blue-400 border-blue-500/20"
        };
        return colors[severity as keyof typeof colors] || colors.medium;
    };

    const typeIcon = (type: string) => {
        const icons = { ip: "🌐", domain: "🔗", hash: "🔐", url: "📎" };
        return icons[type as keyof typeof icons] || "📍";
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-zinc-950">
                <div className="flex flex-col items-center gap-4">
                    <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
                    <p className="text-zinc-400">Loading threat intelligence...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="p-4 md:p-8 bg-zinc-950 min-h-screen">
            <div className="max-w-7xl mx-auto">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
                    <div>
                        <h1 className="text-2xl md:text-3xl font-bold text-white flex items-center gap-3">
                            <Globe className="w-8 h-8 text-blue-400" />
                            Threat Intelligence
                        </h1>
                        <p className="text-zinc-400 mt-1">Real-time threat detection and MITRE ATT&CK mapping</p>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-zinc-500">
                        <Clock className="w-4 h-4" />
                        Last updated: {new Date().toLocaleTimeString()}
                    </div>
                </div>

                {/* Tabs */}
                <div className="flex gap-2 mb-6 overflow-x-auto">
                    {[
                        { id: "overview", label: "Overview", icon: Activity },
                        { id: "ioc", label: "IOC Matches", icon: Target },
                        { id: "mitre", label: "MITRE ATT&CK", icon: Shield },
                    ].map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id as any)}
                            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors whitespace-nowrap ${activeTab === tab.id
                                ? "bg-blue-600 text-white"
                                : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700"
                                }`}
                        >
                            <tab.icon className="w-4 h-4" />
                            {tab.label}
                        </button>
                    ))}
                </div>

                {/* Overview Tab */}
                {activeTab === "overview" && (
                    <div className="space-y-6">
                        {/* Stats Cards */}
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                            <StatCard
                                title="IOC Matches"
                                value={iocMatches.length.toString()}
                                subtitle="Indicators found"
                                icon={Target}
                                color="red"
                            />
                            <StatCard
                                title="Active Threats"
                                value={iocMatches.filter(i => i.severity === "critical" || i.severity === "high").length.toString()}
                                subtitle="High priority"
                                icon={AlertTriangle}
                                color="orange"
                            />
                            <StatCard
                                title="Threat Sources"
                                value="6"
                                subtitle="Active feeds"
                                icon={Globe}
                                color="blue"
                            />
                            <StatCard
                                title="MITRE Coverage"
                                value={`${MITRE_TECHNIQUES.filter(t => t.count > 0).length}/${MITRE_TECHNIQUES.length}`}
                                subtitle="Techniques mapped"
                                icon={Shield}
                                color="purple"
                            />
                        </div>

                        {/* Recent Threats */}
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                        >
                            <div className="flex items-center justify-between mb-6">
                                <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                                    <TrendingUp className="w-5 h-5 text-red-400" />
                                    Recent Threat Matches
                                </h2>
                                <button
                                    onClick={() => setActiveTab("ioc")}
                                    className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
                                >
                                    View All <ChevronRight className="w-4 h-4" />
                                </button>
                            </div>
                            <div className="space-y-3">
                                {iocMatches.slice(0, 3).map((ioc) => (
                                    <div key={ioc.id} className="flex items-center justify-between p-4 rounded-lg bg-white/5 border border-zinc-800">
                                        <div className="flex items-center gap-4">
                                            <span className="text-2xl">{typeIcon(ioc.type)}</span>
                                            <div>
                                                <p className="font-mono text-sm text-white">{ioc.indicator}</p>
                                                <p className="text-xs text-zinc-500">{ioc.threat_type} • {ioc.source}</p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-3">
                                            <span className={`px-2 py-1 rounded text-xs border ${severityColor(ioc.severity)}`}>
                                                {ioc.severity.toUpperCase()}
                                            </span>
                                            <span className="text-xs text-zinc-500">
                                                {new Date(ioc.matched_at).toLocaleTimeString()}
                                            </span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </motion.div>

                        {/* Threat Types Distribution */}
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: 0.1 }}
                                className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                            >
                                <h2 className="text-lg font-semibold text-white mb-4">Threat Categories</h2>
                                <div className="space-y-3">
                                    {[
                                        { name: "Malicious IPs", count: 2, color: "bg-red-500" },
                                        { name: "Phishing Domains", count: 1, color: "bg-orange-500" },
                                        { name: "Malware Hashes", count: 1, color: "bg-purple-500" },
                                        { name: "C2 Servers", count: 1, color: "bg-cyan-500" },
                                    ].map((cat) => (
                                        <div key={cat.name} className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <div className={`w-3 h-3 rounded-full ${cat.color}`} />
                                                <span className="text-sm text-zinc-300">{cat.name}</span>
                                            </div>
                                            <span className="text-sm font-medium text-white">{cat.count}</span>
                                        </div>
                                    ))}
                                </div>
                            </motion.div>

                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: 0.2 }}
                                className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                            >
                                <h2 className="text-lg font-semibold text-white mb-4">Threat Sources</h2>
                                <div className="space-y-3">
                                    {[
                                        { name: "Internal Blocklist", count: 84, active: true },
                                        { name: "AbuseIPDB", count: 0, active: true },
                                        { name: "VirusTotal", count: 0, active: true },
                                        { name: "Phishing Database", count: 0, active: true },
                                        { name: "Tor Exit Nodes", count: 0, active: true },
                                        { name: "Custom Signatures", count: 73, active: true },
                                    ].map((source) => (
                                        <div key={source.name} className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <div className={`w-2 h-2 rounded-full ${source.active ? "bg-emerald-400" : "bg-zinc-600"}`} />
                                                <span className="text-sm text-zinc-300">{source.name}</span>
                                            </div>
                                            <span className="text-xs text-zinc-500">{source.count} indicators</span>
                                        </div>
                                    ))}
                                </div>
                            </motion.div>
                        </div>
                    </div>
                )}

                {/* IOC Matches Tab */}
                {activeTab === "ioc" && (
                    <div className="space-y-6">
                        {/* Search */}
                        <div className="flex gap-4">
                            <div className="flex-1 relative">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-zinc-500" />
                                <input
                                    type="text"
                                    placeholder="Search IOCs by indicator or threat type..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="w-full pl-10 pr-4 py-3 bg-zinc-900 border border-zinc-800 rounded-lg text-white placeholder-zinc-500 focus:outline-none focus:border-blue-500"
                                />
                            </div>
                            <button className="px-4 py-3 bg-zinc-800 rounded-lg text-zinc-400 hover:bg-zinc-700 flex items-center gap-2">
                                <Filter className="w-4 h-4" />
                                Filter
                            </button>
                        </div>

                        {/* IOC Table */}
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="rounded-xl border border-zinc-800 bg-zinc-900/50 overflow-hidden"
                        >
                            <div className="overflow-x-auto">
                                <table className="w-full">
                                    <thead>
                                        <tr className="border-b border-zinc-800">
                                            <th className="text-left p-4 text-sm font-medium text-zinc-400">Type</th>
                                            <th className="text-left p-4 text-sm font-medium text-zinc-400">Indicator</th>
                                            <th className="text-left p-4 text-sm font-medium text-zinc-400">Threat Type</th>
                                            <th className="text-left p-4 text-sm font-medium text-zinc-400">Confidence</th>
                                            <th className="text-left p-4 text-sm font-medium text-zinc-400">Severity</th>
                                            <th className="text-left p-4 text-sm font-medium text-zinc-400">Source</th>
                                            <th className="text-left p-4 text-sm font-medium text-zinc-400">Time</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filteredIOCs.map((ioc) => (
                                            <tr key={ioc.id} className="border-b border-zinc-800/50 hover:bg-white/5">
                                                <td className="p-4">
                                                    <span className="text-xl">{typeIcon(ioc.type)}</span>
                                                </td>
                                                <td className="p-4">
                                                    <span className="font-mono text-sm text-white">{ioc.indicator}</span>
                                                </td>
                                                <td className="p-4 text-sm text-zinc-300">{ioc.threat_type}</td>
                                                <td className="p-4">
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-16 h-2 bg-zinc-800 rounded-full overflow-hidden">
                                                            <div
                                                                className="h-full bg-blue-500 rounded-full"
                                                                style={{ width: `${ioc.confidence}%` }}
                                                            />
                                                        </div>
                                                        <span className="text-xs text-zinc-500">{ioc.confidence}%</span>
                                                    </div>
                                                </td>
                                                <td className="p-4">
                                                    <span className={`px-2 py-1 rounded text-xs border ${severityColor(ioc.severity)}`}>
                                                        {ioc.severity.toUpperCase()}
                                                    </span>
                                                </td>
                                                <td className="p-4 text-sm text-zinc-400">{ioc.source}</td>
                                                <td className="p-4 text-sm text-zinc-500">
                                                    {new Date(ioc.matched_at).toLocaleString()}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </motion.div>
                    </div>
                )}

                {/* MITRE ATT&CK Tab */}
                {activeTab === "mitre" && (
                    <div className="space-y-6">
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                        >
                            <div className="flex items-center justify-between mb-6">
                                <div>
                                    <h2 className="text-xl font-semibold text-white">MITRE ATT&CK Framework</h2>
                                    <p className="text-sm text-zinc-500 mt-1">Detected techniques mapped to MITRE ATT&CK</p>
                                </div>
                                <a
                                    href="https://attack.mitre.org/"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
                                >
                                    MITRE ATT&CK <ExternalLink className="w-4 h-4" />
                                </a>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                                {MITRE_TECHNIQUES.map((technique, index) => (
                                    <motion.div
                                        key={technique.id}
                                        initial={{ opacity: 0, scale: 0.95 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        transition={{ delay: index * 0.05 }}
                                        className={`p-4 rounded-lg border transition-all ${technique.count > 0
                                            ? "bg-red-500/10 border-red-500/30"
                                            : "bg-zinc-800/50 border-zinc-700"
                                            }`}
                                    >
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-xs font-mono text-zinc-500">{technique.id}</span>
                                            {technique.count > 0 && (
                                                <span className="px-2 py-0.5 rounded-full text-xs bg-red-500/20 text-red-400">
                                                    {technique.count} detected
                                                </span>
                                            )}
                                        </div>
                                        <p className="text-sm font-medium text-white mb-1">{technique.name}</p>
                                        <p className="text-xs text-zinc-500">{technique.tactic}</p>
                                    </motion.div>
                                ))}
                            </div>
                        </motion.div>

                        {/* Attack Chain Visualization */}
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.2 }}
                            className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                        >
                            <h2 className="text-lg font-semibold text-white mb-6">Attack Kill Chain</h2>
                            <div className="flex flex-wrap gap-2">
                                {["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command & Control", "Exfiltration", "Impact"].map((phase, index) => (
                                    <div
                                        key={phase}
                                        className={`px-3 py-2 rounded-lg text-sm ${index < 6
                                            ? "bg-red-500/10 border border-red-500/20 text-red-400"
                                            : "bg-zinc-800 border border-zinc-700 text-zinc-400"
                                            }`}
                                    >
                                        {phase}
                                    </div>
                                ))}
                            </div>
                        </motion.div>
                    </div>
                )}
            </div>
        </div>
    );
}

// Stat Card Component
function StatCard({ title, value, subtitle, icon: Icon, color }: {
    title: string;
    value: string;
    subtitle: string;
    icon: any;
    color: "red" | "orange" | "blue" | "purple";
}) {
    const colors = {
        red: "bg-red-500/10 border-red-500/20 text-red-400",
        orange: "bg-orange-500/10 border-orange-500/20 text-orange-400",
        blue: "bg-blue-500/10 border-blue-500/20 text-blue-400",
        purple: "bg-purple-500/10 border-purple-500/20 text-purple-400",
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className={`p-4 md:p-6 rounded-xl border ${colors[color]}`}
        >
            <div className="flex items-center gap-3 mb-3">
                <Icon className={`w-5 h-5 ${colors[color].split(" ")[2]}`} />
                <span className="text-sm text-zinc-400">{title}</span>
            </div>
            <p className="text-2xl md:text-3xl font-bold text-white">{value}</p>
            <p className="text-xs text-zinc-500 mt-1">{subtitle}</p>
        </motion.div>
    );
}
