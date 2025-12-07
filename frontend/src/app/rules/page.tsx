"use client";

import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { Shield, Search, Filter, AlertTriangle } from "lucide-react";

interface Signature {
    id: string;
    name: string;
    severity: string;
    category: string;
    description: string;
    file: string;
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

const severityColors = {
    critical: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/20" },
    high: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/20" },
    medium: { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/20" },
    low: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/20" },
    info: { bg: "bg-zinc-500/10", text: "text-zinc-400", border: "border-zinc-500/20" },
};

export default function RulesPage() {
    const [signatures, setSignatures] = useState<Signature[]>([]);
    const [filteredSignatures, setFilteredSignatures] = useState<Signature[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState("");
    const [selectedCategory, setSelectedCategory] = useState("");
    const [selectedSeverity, setSelectedSeverity] = useState("");
    const [categories, setCategories] = useState<string[]>([]);

    const fetchSignatures = async () => {
        setLoading(true);
        try {
            const response = await fetch(`${API_BASE}/api/v1/signatures`);
            const data = await response.json();
            setSignatures(data.signatures || []);

            // Extract unique categories
            const cats = [...new Set(data.signatures.map((s: Signature) => s.category))].filter(Boolean);
            setCategories(cats as string[]);
        } catch (err) {
            console.error("Error fetching signatures:", err);
        } finally {
            setLoading(false);
        }
    };

    const filterSignatures = useCallback(() => {
        let filtered = signatures;

        if (searchTerm) {
            const search = searchTerm.toLowerCase();
            filtered = filtered.filter(
                (sig) =>
                    sig.name.toLowerCase().includes(search) ||
                    sig.description.toLowerCase().includes(search) ||
                    sig.id.toLowerCase().includes(search)
            );
        }

        if (selectedCategory) {
            filtered = filtered.filter((sig) => sig.category === selectedCategory);
        }

        if (selectedSeverity) {
            filtered = filtered.filter((sig) => sig.severity === selectedSeverity);
        }

        setFilteredSignatures(filtered);
    }, [searchTerm, selectedCategory, selectedSeverity, signatures]);

    useEffect(() => {
        fetchSignatures();
    }, []);

    useEffect(() => {
        filterSignatures();
    }, [filterSignatures]);

    const getSeverityColor = (severity: string) => {
        return severityColors[severity.toLowerCase() as keyof typeof severityColors] || severityColors.info;
    };

    const categoryStats = categories.map((cat) => ({
        category: cat,
        count: signatures.filter((s) => s.category === cat).length,
    }));

    return (
        <div className="p-8 bg-zinc-950 min-h-screen">
            <div className="max-w-7xl mx-auto">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                            <Shield className="w-8 h-8 text-blue-400" />
                            Detection Rules
                        </h1>
                        <p className="text-zinc-400 mt-1">Signature-based detection patterns</p>
                    </div>
                    <div className="text-sm text-zinc-500">
                        {filteredSignatures.length} of {signatures.length} rules
                    </div>
                </div>

                {/* Stats Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                    <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/50">
                        <div className="text-2xl font-bold text-white">{signatures.length}</div>
                        <div className="text-sm text-zinc-400">Total Rules</div>
                    </div>
                    <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/50">
                        <div className="text-2xl font-bold text-white">{categories.length}</div>
                        <div className="text-sm text-zinc-400">Categories</div>
                    </div>
                    <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/50">
                        <div className="text-2xl font-bold text-red-400">
                            {signatures.filter((s) => s.severity === "critical").length}
                        </div>
                        <div className="text-sm text-zinc-400">Critical</div>
                    </div>
                    <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/50">
                        <div className="text-2xl font-bold text-orange-400">
                            {signatures.filter((s) => s.severity === "high").length}
                        </div>
                        <div className="text-sm text-zinc-400">High Severity</div>
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
                            <input
                                type="text"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                placeholder="Search rules..."
                                className="w-full px-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white placeholder-zinc-500 focus:outline-none focus:border-blue-500"
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">
                                <Filter className="w-4 h-4 inline mr-2" />
                                Category
                            </label>
                            <select
                                value={selectedCategory}
                                onChange={(e) => setSelectedCategory(e.target.value)}
                                className="w-full px-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                            >
                                <option value="">All Categories</option>
                                {categories.map((cat) => (
                                    <option key={cat} value={cat}>
                                        {cat.replace(/_/g, " ")}
                                    </option>
                                ))}
                            </select>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">
                                <AlertTriangle className="w-4 h-4 inline mr-2" />
                                Severity
                            </label>
                            <select
                                value={selectedSeverity}
                                onChange={(e) => setSelectedSeverity(e.target.value)}
                                className="w-full px-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                            >
                                <option value="">All Severities</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                        </div>
                    </div>
                </div>

                {/* Category Breakdown */}
                <div className="mb-6 p-6 rounded-xl border border-zinc-800 bg-zinc-900/50">
                    <h2 className="text-lg font-semibold text-white mb-4">Rules by Category</h2>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {categoryStats.map((stat) => (
                            <div
                                key={stat.category}
                                className="p-3 rounded-lg bg-white/5 border border-zinc-800 hover:border-zinc-700 transition-colors cursor-pointer"
                                onClick={() => setSelectedCategory(stat.category)}
                            >
                                <div className="text-sm font-medium text-white capitalize">
                                    {stat.category.replace(/_/g, " ")}
                                </div>
                                <div className="text-xs text-zinc-400 mt-1">{stat.count} rules</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Rules List */}
                <div className="space-y-3">
                    {loading ? (
                        <div className="text-center py-12 text-zinc-500">Loading rules...</div>
                    ) : filteredSignatures.length === 0 ? (
                        <div className="text-center py-12 text-zinc-500">No rules found</div>
                    ) : (
                        filteredSignatures.map((sig) => {
                            const colors = getSeverityColor(sig.severity);
                            return (
                                <motion.div
                                    key={sig.id}
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    className={`p-5 rounded-xl border ${colors.border} bg-zinc-900/50 hover:bg-zinc-900/80 transition-all`}
                                >
                                    <div className="flex items-start justify-between">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-2">
                                                <h3 className="text-lg font-semibold text-white">{sig.name}</h3>
                                                <span className={`px-2 py-1 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
                                                    {sig.severity.toUpperCase()}
                                                </span>
                                                <span className="px-2 py-1 rounded text-xs bg-zinc-800 text-zinc-400 capitalize">
                                                    {sig.category.replace(/_/g, " ")}
                                                </span>
                                            </div>
                                            <p className="text-sm text-zinc-400 mb-3">{sig.description}</p>
                                            <div className="flex items-center gap-4 text-xs text-zinc-500">
                                                <span className="font-mono">{sig.id}</span>
                                                <span>•</span>
                                                <span>{sig.file}</span>
                                            </div>
                                        </div>
                                    </div>
                                </motion.div>
                            );
                        })
                    )}
                </div>
            </div>
        </div>
    );
}
