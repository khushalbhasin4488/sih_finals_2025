"use client";

import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
    Search,
    Filter,
    RefreshCw,
    FileText,
    Server,
    Clock,
    X,
    Download,
    ChevronLeft,
    ChevronRight
} from "lucide-react";

interface Log {
    id: string;
    timestamp: string;
    raw?: string;
    appname?: string;
    host?: string;
    message?: string;
    source_ip?: string;
    user?: string;
    normalized?: any;
    metadata?: any;
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export default function LogsPage() {
    const [logs, setLogs] = useState<Log[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState("");
    const [selectedAppname, setSelectedAppname] = useState("");
    const [selectedHost, setSelectedHost] = useState("");
    const [appnames, setAppnames] = useState<string[]>([]);
    const [hosts, setHosts] = useState<string[]>([]);
    const [selectedLog, setSelectedLog] = useState<Log | null>(null);
    const [currentPage, setCurrentPage] = useState(1);
    const [autoRefresh, setAutoRefresh] = useState(false);
    const logsPerPage = 50;

    const fetchFilters = useCallback(async () => {
        try {
            const [appnamesRes, hostsRes] = await Promise.all([
                fetch(`${API_BASE}/api/v1/appnames`),
                fetch(`${API_BASE}/api/v1/hosts`)
            ]);

            const appnamesData = await appnamesRes.json();
            const hostsData = await hostsRes.json();

            setAppnames(Array.isArray(appnamesData.appnames) ? appnamesData.appnames : []);
            setHosts(Array.isArray(hostsData.hosts) ? hostsData.hosts : []);
        } catch (err) {
            console.error("Error fetching filters:", err);
            setAppnames([]);
            setHosts([]);
        }
    }, []);

    const fetchLogs = useCallback(async () => {
        setLoading(true);
        try {
            const params = new URLSearchParams();
            params.append("limit", "200");
            if (selectedAppname) params.append("appname", selectedAppname);
            if (selectedHost) params.append("host", selectedHost);
            if (searchTerm) params.append("search", searchTerm);

            const response = await fetch(`${API_BASE}/api/v1/logs?${params}`);

            // Check if response is OK
            if (!response.ok) {
                console.error("API error:", response.status, response.statusText);
                setLogs([]);
                setCurrentPage(1);
                return;
            }

            const data = await response.json();

            // Ensure data is an array
            if (Array.isArray(data)) {
                setLogs(data);
            } else {
                console.error("API returned non-array data:", data);
                console.error("Response type:", typeof data);
                console.error("API URL:", `${API_BASE}/api/v1/logs?${params}`);
                setLogs([]);
            }

            setCurrentPage(1); // Reset to first page on new search
        } catch (err) {
            console.error("Error fetching logs:", err);
            console.error("API Base URL:", API_BASE);
            setLogs([]); // Set empty array on error
        } finally {
            setLoading(false);
        }
    }, [selectedAppname, selectedHost, searchTerm]);

    useEffect(() => {
        fetchFilters();
    }, [fetchFilters]);

    useEffect(() => {
        fetchLogs();
    }, [selectedAppname, selectedHost, fetchLogs]);

    useEffect(() => {
        if (autoRefresh) {
            const interval = setInterval(fetchLogs, 10000); // Refresh every 10 seconds
            return () => clearInterval(interval);
        }
    }, [autoRefresh, fetchLogs]);

    const handleSearch = () => {
        fetchLogs();
    };

    const handleExport = () => {
        const csv = [
            ["Timestamp", "Host", "Application", "Message", "Source IP", "User"].join(","),
            ...logs.map(log => [
                log.timestamp,
                log.host || "",
                log.appname || "",
                `"${(log.message || log.raw || "").replace(/"/g, '""')}"`,
                log.source_ip || "",
                log.user || ""
            ].join(","))
        ].join("\n");

        const blob = new Blob([csv], { type: "text/csv" });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `logs-${new Date().toISOString()}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    };

    const formatTimestamp = (timestamp: string) => {
        try {
            return new Date(timestamp).toLocaleString();
        } catch {
            return timestamp;
        }
    };

    // Pagination
    const indexOfLastLog = currentPage * logsPerPage;
    const indexOfFirstLog = indexOfLastLog - logsPerPage;
    const currentLogs = logs.slice(indexOfFirstLog, indexOfLastLog);
    const totalPages = Math.ceil(logs.length / logsPerPage);

    return (
        <div className="p-8 bg-zinc-950 min-h-screen">
            <div className="max-w-7xl mx-auto">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-3xl font-bold text-white">Log Viewer</h1>
                        <p className="text-zinc-400 mt-1">Search and analyze system logs</p>
                    </div>
                    <div className="flex items-center gap-3">
                        <button
                            onClick={() => setAutoRefresh(!autoRefresh)}
                            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${autoRefresh
                                ? "bg-emerald-600 hover:bg-emerald-700 text-white"
                                : "bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
                                }`}
                        >
                            <RefreshCw className={`w-4 h-4 ${autoRefresh ? "animate-spin" : ""}`} />
                            Auto-refresh
                        </button>
                        <button
                            onClick={handleExport}
                            className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-white rounded-lg transition-colors"
                        >
                            <Download className="w-4 h-4" />
                            Export CSV
                        </button>
                        <button
                            onClick={fetchLogs}
                            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                        >
                            <RefreshCw className="w-4 h-4" />
                            Refresh
                        </button>
                    </div>
                </div>

                {/* Filters */}
                <div className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">
                                <Search className="w-4 h-4 inline mr-2" />
                                Search
                            </label>
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                    onKeyPress={(e) => e.key === "Enter" && handleSearch()}
                                    placeholder="Search logs..."
                                    className="flex-1 px-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white placeholder-zinc-500 focus:outline-none focus:border-blue-500"
                                />
                                <button
                                    onClick={handleSearch}
                                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                                >
                                    Search
                                </button>
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">
                                <FileText className="w-4 h-4 inline mr-2" />
                                Application
                            </label>
                            <select
                                value={selectedAppname}
                                onChange={(e) => setSelectedAppname(e.target.value)}
                                className="w-full px-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                            >
                                <option value="">All Applications</option>
                                {appnames.map((app) => (
                                    <option key={app} value={app}>
                                        {app}
                                    </option>
                                ))}
                            </select>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">
                                <Server className="w-4 h-4 inline mr-2" />
                                Host
                            </label>
                            <select
                                value={selectedHost}
                                onChange={(e) => setSelectedHost(e.target.value)}
                                className="w-full px-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                            >
                                <option value="">All Hosts</option>
                                {hosts.map((host) => (
                                    <option key={host} value={host}>
                                        {host}
                                    </option>
                                ))}
                            </select>
                        </div>
                    </div>
                </div>

                {/* Logs Table */}
                <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead className="bg-zinc-800/50 border-b border-zinc-700">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                                        <Clock className="w-4 h-4 inline mr-2" />
                                        Timestamp
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                                        Host
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                                        App
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                                        Message
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-zinc-400 uppercase tracking-wider">
                                        Source IP
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-800">
                                {loading ? (
                                    <tr>
                                        <td colSpan={5} className="px-4 py-8 text-center text-zinc-500">
                                            Loading logs...
                                        </td>
                                    </tr>
                                ) : currentLogs.length === 0 ? (
                                    <tr>
                                        <td colSpan={5} className="px-4 py-8 text-center text-zinc-500">
                                            No logs found
                                        </td>
                                    </tr>
                                ) : (
                                    currentLogs.map((log) => (
                                        <motion.tr
                                            key={log.id}
                                            initial={{ opacity: 0 }}
                                            animate={{ opacity: 1 }}
                                            className="hover:bg-zinc-800/50 transition-colors cursor-pointer"
                                            onClick={() => setSelectedLog(log)}
                                        >
                                            <td className="px-4 py-3 text-sm text-zinc-300 font-mono">
                                                {formatTimestamp(log.timestamp)}
                                            </td>
                                            <td className="px-4 py-3 text-sm text-zinc-300">
                                                <span className="px-2 py-1 bg-blue-500/10 text-blue-400 rounded text-xs">
                                                    {log.host || "N/A"}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3 text-sm text-zinc-300">
                                                <span className="px-2 py-1 bg-purple-500/10 text-purple-400 rounded text-xs">
                                                    {log.appname || "N/A"}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3 text-sm text-zinc-300 max-w-md truncate">
                                                {log.message || log.raw || "No message"}
                                            </td>
                                            <td className="px-4 py-3 text-sm text-zinc-300 font-mono">
                                                {log.source_ip || "-"}
                                            </td>
                                        </motion.tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                    <div className="mt-4 flex items-center justify-between">
                        <div className="text-sm text-zinc-500">
                            Showing {indexOfFirstLog + 1} to {Math.min(indexOfLastLog, logs.length)} of {logs.length} logs
                        </div>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                                disabled={currentPage === 1}
                                className="px-3 py-2 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
                            >
                                <ChevronLeft className="w-4 h-4" />
                            </button>
                            <span className="text-sm text-zinc-400">
                                Page {currentPage} of {totalPages}
                            </span>
                            <button
                                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                                disabled={currentPage === totalPages}
                                className="px-3 py-2 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
                            >
                                <ChevronRight className="w-4 h-4" />
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {/* Log Detail Modal */}
            <AnimatePresence>
                {selectedLog && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
                        onClick={() => setSelectedLog(null)}
                    >
                        <motion.div
                            initial={{ scale: 0.95, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.95, opacity: 0 }}
                            className="bg-zinc-900 rounded-xl border border-zinc-800 max-w-4xl w-full max-h-[80vh] overflow-hidden"
                            onClick={(e) => e.stopPropagation()}
                        >
                            <div className="p-6 border-b border-zinc-800 flex items-center justify-between">
                                <h2 className="text-xl font-bold text-white">Log Details</h2>
                                <button
                                    onClick={() => setSelectedLog(null)}
                                    className="p-2 hover:bg-zinc-800 rounded-lg transition-colors"
                                >
                                    <X className="w-5 h-5 text-zinc-400" />
                                </button>
                            </div>
                            <div className="p-6 overflow-y-auto max-h-[calc(80vh-80px)]">
                                <div className="space-y-4">
                                    <div>
                                        <div className="text-sm text-zinc-500 mb-1">ID</div>
                                        <div className="text-sm font-mono text-zinc-300 bg-zinc-800 p-2 rounded">
                                            {selectedLog.id}
                                        </div>
                                    </div>
                                    <div>
                                        <div className="text-sm text-zinc-500 mb-1">Timestamp</div>
                                        <div className="text-sm text-zinc-300">{formatTimestamp(selectedLog.timestamp)}</div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <div className="text-sm text-zinc-500 mb-1">Host</div>
                                            <div className="text-sm text-zinc-300">{selectedLog.host || "N/A"}</div>
                                        </div>
                                        <div>
                                            <div className="text-sm text-zinc-500 mb-1">Application</div>
                                            <div className="text-sm text-zinc-300">{selectedLog.appname || "N/A"}</div>
                                        </div>
                                        <div>
                                            <div className="text-sm text-zinc-500 mb-1">Source IP</div>
                                            <div className="text-sm font-mono text-zinc-300">{selectedLog.source_ip || "N/A"}</div>
                                        </div>
                                        <div>
                                            <div className="text-sm text-zinc-500 mb-1">User</div>
                                            <div className="text-sm text-zinc-300">{selectedLog.user || "N/A"}</div>
                                        </div>
                                    </div>
                                    <div>
                                        <div className="text-sm text-zinc-500 mb-1">Message</div>
                                        <div className="text-sm text-zinc-300 bg-zinc-800 p-3 rounded whitespace-pre-wrap">
                                            {selectedLog.message || selectedLog.raw || "No message"}
                                        </div>
                                    </div>
                                    {selectedLog.normalized && (
                                        <div>
                                            <div className="text-sm text-zinc-500 mb-1">Normalized Data</div>
                                            <pre className="text-xs text-zinc-300 bg-zinc-800 p-3 rounded overflow-auto">
                                                {JSON.stringify(selectedLog.normalized, null, 2)}
                                            </pre>
                                        </div>
                                    )}
                                    {selectedLog.metadata && (
                                        <div>
                                            <div className="text-sm text-zinc-500 mb-1">Metadata</div>
                                            <pre className="text-xs text-zinc-300 bg-zinc-800 p-3 rounded overflow-auto">
                                                {JSON.stringify(selectedLog.metadata, null, 2)}
                                            </pre>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
