"use client";

import { motion } from "framer-motion";
import {
    Activity,
    Shield,
    AlertTriangle,
    Search,
    Clock,
    ArrowUpRight,
    Database,
    Server
} from "lucide-react";

const stats = [
    {
        name: "Total Logs",
        value: "2.4M",
        change: "+12%",
        trend: "up",
        icon: Database,
        color: "text-blue-400",
        bg: "bg-blue-400/10",
        border: "border-blue-400/20"
    },
    {
        name: "Active Threats",
        value: "3",
        change: "-2",
        trend: "down",
        icon: AlertTriangle,
        color: "text-red-400",
        bg: "bg-red-400/10",
        border: "border-red-400/20"
    },
    {
        name: "System Health",
        value: "98%",
        change: "Stable",
        trend: "neutral",
        icon: Activity,
        color: "text-emerald-400",
        bg: "bg-emerald-400/10",
        border: "border-emerald-400/20"
    },
    {
        name: "Monitored Hosts",
        value: "142",
        change: "+5",
        trend: "up",
        icon: Server,
        color: "text-purple-400",
        bg: "bg-purple-400/10",
        border: "border-purple-400/20"
    },
];

const container = {
    hidden: { opacity: 0 },
    show: {
        opacity: 1,
        transition: {
            staggerChildren: 0.1
        }
    }
};

const item = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0 }
};

export default function HomePage() {
    return (
        <main className="min-h-screen p-8 bg-zinc-950 text-zinc-50 relative overflow-hidden">
            {/* Background Effects */}
            <div className="absolute top-0 left-0 w-full h-96 bg-blue-900/10 blur-[100px] pointer-events-none" />
            <div className="absolute bottom-0 right-0 w-full h-96 bg-purple-900/5 blur-[100px] pointer-events-none" />

            <div className="max-w-7xl mx-auto relative z-10">
                <header className="flex items-center justify-between mb-12">
                    <div>
                        <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-zinc-400">
                            Security Overview
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
                            Last updated: Just now
                        </div>
                    </div>
                </header>

                <motion.div
                    variants={container}
                    initial="hidden"
                    animate="show"
                    className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
                >
                    {stats.map((stat) => (
                        <motion.div
                            key={stat.name}
                            variants={item}
                            className={`p-6 rounded-xl border bg-zinc-900/50 backdrop-blur-sm hover:bg-zinc-900/80 transition-colors ${stat.border}`}
                        >
                            <div className="flex items-start justify-between mb-4">
                                <div className={`p-2 rounded-lg ${stat.bg}`}>
                                    <stat.icon className={`w-5 h-5 ${stat.color}`} />
                                </div>
                                <span className={`text-xs font-medium px-2 py-1 rounded-full ${stat.trend === 'up' ? 'bg-emerald-500/10 text-emerald-400' :
                                        stat.trend === 'down' ? 'bg-red-500/10 text-red-400' :
                                            'bg-zinc-500/10 text-zinc-400'
                                    }`}>
                                    {stat.change}
                                </span>
                            </div>
                            <h3 className="text-2xl font-bold text-white mb-1">{stat.value}</h3>
                            <p className="text-sm text-zinc-400">{stat.name}</p>
                        </motion.div>
                    ))}
                </motion.div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.4 }}
                        className="lg:col-span-2 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm"
                    >
                        <div className="flex items-center justify-between mb-6">
                            <h2 className="text-lg font-semibold">Recent Activity</h2>
                            <button className="text-sm text-blue-400 hover:text-blue-300 transition-colors">View All</button>
                        </div>
                        <div className="space-y-4">
                            {[1, 2, 3, 4, 5].map((i) => (
                                <div key={i} className="flex items-center justify-between p-3 rounded-lg hover:bg-white/5 transition-colors group cursor-pointer border border-transparent hover:border-zinc-800">
                                    <div className="flex items-center gap-4">
                                        <div className="w-2 h-2 rounded-full bg-blue-500" />
                                        <div>
                                            <p className="text-sm font-medium text-white group-hover:text-blue-400 transition-colors">SSH Login Attempt</p>
                                            <p className="text-xs text-zinc-500">192.168.1.{100 + i} • sshd</p>
                                        </div>
                                    </div>
                                    <span className="text-xs text-zinc-500 font-mono">10:4{i} AM</span>
                                </div>
                            ))}
                        </div>
                    </motion.div>

                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.5 }}
                        className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50 backdrop-blur-sm"
                    >
                        <h2 className="text-lg font-semibold mb-6">Quick Actions</h2>
                        <div className="space-y-3">
                            <button className="w-full flex items-center justify-between p-3 rounded-lg border border-zinc-800 hover:bg-white/5 hover:border-zinc-700 transition-all group">
                                <div className="flex items-center gap-3">
                                    <Search className="w-4 h-4 text-zinc-400 group-hover:text-white" />
                                    <span className="text-sm text-zinc-300 group-hover:text-white">Search Logs</span>
                                </div>
                                <ArrowUpRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-400" />
                            </button>

                            <button className="w-full flex items-center justify-between p-3 rounded-lg border border-zinc-800 hover:bg-white/5 hover:border-zinc-700 transition-all group">
                                <div className="flex items-center gap-3">
                                    <Shield className="w-4 h-4 text-zinc-400 group-hover:text-white" />
                                    <span className="text-sm text-zinc-300 group-hover:text-white">Update Rules</span>
                                </div>
                                <ArrowUpRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-400" />
                            </button>

                            <button className="w-full flex items-center justify-between p-3 rounded-lg border border-zinc-800 hover:bg-white/5 hover:border-zinc-700 transition-all group">
                                <div className="flex items-center gap-3">
                                    <AlertTriangle className="w-4 h-4 text-zinc-400 group-hover:text-white" />
                                    <span className="text-sm text-zinc-300 group-hover:text-white">View Alerts</span>
                                </div>
                                <ArrowUpRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-400" />
                            </button>
                        </div>

                        <div className="mt-8 p-4 rounded-lg bg-gradient-to-br from-blue-900/20 to-purple-900/20 border border-blue-500/10">
                            <h3 className="text-sm font-medium text-blue-200 mb-1">System Status</h3>
                            <p className="text-xs text-blue-300/70 mb-3">All systems running normally</p>
                            <div className="h-1.5 w-full bg-blue-900/30 rounded-full overflow-hidden">
                                <div className="h-full bg-blue-500 w-[98%] rounded-full" />
                            </div>
                        </div>
                    </motion.div>
                </div>
            </div>
        </main>
    );
}
