"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";
import {
    LayoutDashboard,
    FileText,
    AlertTriangle,
    Shield,
    Globe,
    FileBarChart,
    Settings,
    Activity
} from "lucide-react";
import { cn } from "@/src/lib/utils";

const navigation = [
    { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { name: "Logs", href: "/logs", icon: FileText },
    { name: "Alerts", href: "/alerts", icon: AlertTriangle },
    { name: "Rules", href: "/rules", icon: Shield },
    { name: "Threat Intel", href: "/threat-intel", icon: Globe },
    { name: "Reports", href: "/reports", icon: FileBarChart },
    { name: "Settings", href: "/settings", icon: Settings },
];

export default function Sidebar() {
    const pathname = usePathname();

    return (
        <div className="flex flex-col w-64 bg-zinc-950 border-r border-zinc-800 min-h-screen relative overflow-hidden">
            {/* Background Gradient */}
            <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-b from-blue-900/10 to-transparent pointer-events-none" />

            <div className="p-6 relative z-10">
                <div className="flex items-center gap-3 mb-8">
                    <div className="p-2 bg-blue-600/20 rounded-lg border border-blue-500/30">
                        <Activity className="w-6 h-6 text-blue-400" />
                    </div>
                    <div>
                        <h1 className="text-lg font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-zinc-400">
                            Log Analyzer
                        </h1>
                        <p className="text-xs text-zinc-500">Security Monitor</p>
                    </div>
                </div>
            </div>

            <nav className="flex-1 px-3 space-y-1 relative z-10">
                {navigation.map((item) => {
                    const isActive = pathname === item.href ||
                        (item.href !== "/" && pathname.startsWith(item.href));

                    return (
                        <Link
                            key={item.name}
                            href={item.href}
                            className={cn(
                                "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group relative",
                                isActive
                                    ? "text-white"
                                    : "text-zinc-400 hover:text-white hover:bg-white/5"
                            )}
                        >
                            {isActive && (
                                <motion.div
                                    layoutId="sidebar-active"
                                    className="absolute inset-0 bg-blue-600/10 border border-blue-500/20 rounded-lg"
                                    initial={false}
                                    transition={{ type: "spring", stiffness: 300, damping: 30 }}
                                />
                            )}

                            <item.icon className={cn(
                                "w-5 h-5 transition-colors",
                                isActive ? "text-blue-400" : "text-zinc-500 group-hover:text-zinc-300"
                            )} />

                            <span className="relative font-medium text-sm">{item.name}</span>

                            {isActive && (
                                <div className="absolute right-3 w-1.5 h-1.5 rounded-full bg-blue-400 shadow-[0_0_8px_rgba(96,165,250,0.6)]" />
                            )}
                        </Link>
                    );
                })}
            </nav>

            <div className="p-4 border-t border-zinc-800 relative z-10">
                <div className="flex items-center gap-3 p-2 rounded-lg hover:bg-white/5 transition-colors cursor-pointer">
                    <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-blue-500 to-purple-500 flex items-center justify-center border border-white/10">
                        <span className="text-xs font-bold text-white">A</span>
                    </div>
                    <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-white truncate">Admin User</p>
                        <p className="text-xs text-zinc-500 truncate">admin@secure.local</p>
                    </div>
                </div>
            </div>
        </div>
    );
}
