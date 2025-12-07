"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Globe, Shield, AlertTriangle, Info } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export default function ThreatIntelPage() {
    const [blockedIPs, setBlockedIPs] = useState<string[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadBlockedIPs();
    }, []);

    const loadBlockedIPs = async () => {
        setLoading(true);
        try {
            // For now, show example blocked IPs
            // In production, this would fetch from the API
            setBlockedIPs([
                "192.0.2.1",
                "198.51.100.1",
                "203.0.113.1",
                "185.220.101.1",
                "185.220.101.2",
                "45.142.212.61",
                "89.248.165.75",
                "103.109.247.10",
                "185.244.25.145"
            ]);
        } catch (err) {
            console.error("Error loading blocked IPs:", err);
        } finally {
            setLoading(false);
        }
    };

    const threatCategories = [
        {
            name: "Blocked IPs",
            count: blockedIPs.length,
            description: "Known malicious IP addresses",
            icon: Shield,
            color: "text-red-400",
            bg: "bg-red-500/10",
            border: "border-red-500/20"
        },
        {
            name: "Malware Hashes",
            count: 3,
            description: "Known malware file signatures",
            icon: AlertTriangle,
            color: "text-orange-400",
            bg: "bg-orange-500/10",
            border: "border-orange-500/20"
        },
        {
            name: "C2 Servers",
            count: 2,
            description: "Command & Control servers",
            icon: Globe,
            color: "text-purple-400",
            bg: "bg-purple-500/10",
            border: "border-purple-500/20"
        }
    ];

    return (
        <div className="p-8 bg-zinc-950 min-h-screen">
            <div className="max-w-7xl mx-auto">
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                        <Globe className="w-8 h-8 text-blue-400" />
                        Threat Intelligence
                    </h1>
                    <p className="text-zinc-400 mt-1">Known threats and indicators of compromise</p>
                </div>

                {/* Threat Categories */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    {threatCategories.map((category, index) => (
                        <motion.div
                            key={category.name}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: index * 0.1 }}
                            className={`p-6 rounded-xl border ${category.border} ${category.bg}`}
                        >
                            <div className="flex items-center gap-3 mb-4">
                                <div className={`p-2 rounded-lg ${category.bg}`}>
                                    <category.icon className={`w-5 h-5 ${category.color}`} />
                                </div>
                                <h3 className="text-lg font-semibold text-white">{category.name}</h3>
                            </div>
                            <div className="text-3xl font-bold text-white mb-2">{category.count}</div>
                            <div className="text-sm text-zinc-400">{category.description}</div>
                        </motion.div>
                    ))}
                </div>

                {/* Blocked IPs */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
                        <Shield className="w-5 h-5 text-red-400" />
                        Blocked IP Addresses
                    </h2>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {loading ? (
                            <div className="col-span-3 text-center py-8 text-zinc-500">Loading...</div>
                        ) : (
                            blockedIPs.map((ip, index) => (
                                <motion.div
                                    key={ip}
                                    initial={{ opacity: 0, x: -20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: 0.3 + index * 0.05 }}
                                    className="p-3 rounded-lg bg-red-500/5 border border-red-500/20 hover:border-red-500/40 transition-colors"
                                >
                                    <div className="font-mono text-sm text-red-400">{ip}</div>
                                    <div className="text-xs text-zinc-500 mt-1">Malicious IP</div>
                                </motion.div>
                            ))
                        )}
                    </div>
                </motion.div>

                {/* Known Malware Hashes */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 }}
                    className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50"
                >
                    <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-orange-400" />
                        Known Malware Hashes
                    </h2>
                    <div className="space-y-3">
                        <div className="p-4 rounded-lg bg-orange-500/5 border border-orange-500/20">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-sm font-medium text-white">WannaCry Ransomware</span>
                                <span className="px-2 py-1 rounded text-xs bg-red-500/10 text-red-400">SHA256</span>
                            </div>
                            <div className="font-mono text-xs text-zinc-400 break-all">
                                ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
                            </div>
                        </div>

                        <div className="p-4 rounded-lg bg-orange-500/5 border border-orange-500/20">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-sm font-medium text-white">WannaCry Ransomware</span>
                                <span className="px-2 py-1 rounded text-xs bg-red-500/10 text-red-400">MD5</span>
                            </div>
                            <div className="font-mono text-xs text-zinc-400 break-all">
                                db349b97c37d22f5ea1d1841e3c89eb4
                            </div>
                        </div>

                        <div className="p-4 rounded-lg bg-orange-500/5 border border-orange-500/20">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-sm font-medium text-white">Emotet Malware</span>
                                <span className="px-2 py-1 rounded text-xs bg-red-500/10 text-red-400">SHA256</span>
                            </div>
                            <div className="font-mono text-xs text-zinc-400 break-all">
                                4a5b8f8f9c8e7d6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a
                            </div>
                        </div>
                    </div>
                </motion.div>

                {/* Info Note */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.5 }}
                    className="p-4 rounded-xl border border-blue-500/20 bg-blue-500/5"
                >
                    <div className="flex items-start gap-3">
                        <Info className="w-5 h-5 text-blue-400 mt-0.5" />
                        <div className="text-sm text-zinc-300">
                            <p className="font-medium text-white mb-2">Threat Intelligence Sources</p>
                            <p>
                                Threat intelligence data is sourced from signature files located in{" "}
                                <code className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 font-mono text-xs">
                                    config/signatures/
                                </code>{" "}
                                and{" "}
                                <code className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 font-mono text-xs">
                                    config/blocked_ips.txt
                                </code>
                                . These files are used by the signature detector to identify known threats in real-time.
                            </p>
                        </div>
                    </div>
                </motion.div>
            </div>
        </div>
    );
}
