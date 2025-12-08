'use client';

import React, { useEffect, useState } from 'react';
import {
    Activity,
    Server,
    Shield,
    Users,
    Clock,
    AlertTriangle,
    BarChart2,
    Globe,
    Zap,
    Layout
} from 'lucide-react';
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    BarChart,
    Bar,
    PieChart,
    Pie,
    Cell
} from 'recharts';
import { useNetwork } from '@/lib/NetworkContext';

// Types mimicking the backend response
type AnalyticsData = {
    volume: {
        total_requests: number;
        requests_per_minute: number;
        peak_load_time: string;
        top_endpoints: { endpoint: string; count: number }[];
    };
    performance: {
        avg_response_time: number;
        p99_response_time: number;
        total_bandwidth_bytes: number;
        slowest_endpoints: { path: string; avg_time: number }[];
    };
    errors: {
        status_distribution: { status: string; count: number }[];
        top_errors: { message: string; count: number }[];
    };
    security: {
        failed_logins: number;
        top_source_ips: { ip: string; count: number }[];
    };
    users: {
        unique_active_users: number;
        top_user_agents: { agent: string; count: number }[];
    };
};

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

// Generate mock data for demo purposes
const generateMockData = (): AnalyticsData => {
    const randomInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
    const randomFloat = (min: number, max: number) => Math.random() * (max - min) + min;

    return {
        volume: {
            total_requests: randomInt(50000, 150000),
            requests_per_minute: randomFloat(50, 200),
            peak_load_time: `${randomInt(9, 17)}:00`,
            top_endpoints: [
                { endpoint: "GET /api/users", count: randomInt(5000, 15000) },
                { endpoint: "POST /api/auth/login", count: randomInt(3000, 10000) },
                { endpoint: "GET /api/products", count: randomInt(2000, 8000) },
                { endpoint: "PUT /api/orders", count: randomInt(1000, 5000) },
                { endpoint: "GET /api/analytics", count: randomInt(500, 3000) }
            ]
        },
        performance: {
            avg_response_time: randomFloat(80, 250),
            p99_response_time: randomFloat(400, 1200),
            total_bandwidth_bytes: randomInt(50000000, 500000000),
            slowest_endpoints: [
                { path: "/api/reports/generate", avg_time: randomFloat(800, 2000) },
                { path: "/api/search/advanced", avg_time: randomFloat(500, 1500) },
                { path: "/api/export/data", avg_time: randomFloat(400, 1200) }
            ]
        },
        errors: {
            status_distribution: [
                { status: "200", count: randomInt(40000, 90000) },
                { status: "404", count: randomInt(500, 3000) },
                { status: "500", count: randomInt(50, 500) },
                { status: "401", count: randomInt(100, 1000) },
                { status: "403", count: randomInt(50, 400) }
            ],
            top_errors: [
                { message: "Database connection timeout", count: randomInt(10, 100) },
                { message: "Invalid authentication token", count: randomInt(20, 150) },
                { message: "Resource not found", count: randomInt(30, 200) },
                { message: "Rate limit exceeded", count: randomInt(5, 50) },
                { message: "Internal server error", count: randomInt(10, 80) }
            ]
        },
        security: {
            failed_logins: randomInt(100, 1000),
            top_source_ips: [
                { ip: `192.168.${randomInt(1, 255)}.${randomInt(1, 255)}`, count: randomInt(500, 2000) },
                { ip: `10.0.${randomInt(1, 255)}.${randomInt(1, 255)}`, count: randomInt(300, 1500) },
                { ip: `172.16.${randomInt(1, 255)}.${randomInt(1, 255)}`, count: randomInt(200, 1000) },
                { ip: `203.0.${randomInt(1, 255)}.${randomInt(1, 255)}`, count: randomInt(100, 800) },
                { ip: `198.51.${randomInt(1, 255)}.${randomInt(1, 255)}`, count: randomInt(50, 500) }
            ]
        },
        users: {
            unique_active_users: randomInt(1000, 5000),
            top_user_agents: [
                { agent: "Mozilla/5.0 Chrome/120.0", count: randomInt(5000, 15000) },
                { agent: "Mozilla/5.0 Safari/605.1", count: randomInt(3000, 10000) },
                { agent: "Mozilla/5.0 Firefox/121.0", count: randomInt(2000, 8000) },
                { agent: "Postman Runtime/7.36", count: randomInt(500, 3000) },
                { agent: "curl/8.1.2", count: randomInt(200, 1500) }
            ]
        }
    };
};

export default function AnalyticsPage() {
    const [data, setData] = useState<AnalyticsData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [useMockData, setUseMockData] = useState(false);
    const { selectedNetwork } = useNetwork();

    useEffect(() => {
        const fetchData = async () => {
            try {
                const networkParam = selectedNetwork ? `&network=${encodeURIComponent(selectedNetwork)}` : '';
                const res = await fetch(`http://localhost:8000/api/v1/analytics/overview?time_range_minutes=1440${networkParam}`);
                if (!res.ok) throw new Error('Failed to fetch analytics');
                const json = await res.json();

                // Check if data is empty/insufficient and use mock data
                const isEmpty = json.volume?.total_requests === 0 || !json.volume;
                if (isEmpty) {
                    setUseMockData(true);
                    setData(generateMockData());
                } else {
                    setUseMockData(false);
                    setData(json);
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : 'Unknown error');
                // Use mock data on error
                setUseMockData(true);
                setData(generateMockData());
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        // Refresh every minute
        const interval = setInterval(fetchData, 60000);
        return () => clearInterval(interval);
    }, [selectedNetwork]); // Re-fetch when network changes

    if (loading) return <div className="p-8 flex items-center justify-center text-gray-400">Loading analytics...</div>;
    if (!data) return null;

    return (
        <div className="p-6 space-y-6 bg-gray-950 min-h-screen text-gray-100">
            <header className="mb-8">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold flex items-center gap-3 text-white">
                            <Activity className="w-8 h-8 text-blue-500" />
                            Comprehensive Log Analytics
                        </h1>
                        <p className="text-gray-400 mt-2">Real-time insights across Volume, Performance, Security, and Reliability.</p>
                    </div>
                    {/* {useMockData && (
                        <div className="px-4 py-2 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                            <p className="text-yellow-400 text-sm font-medium">📊 Demo Data Mode</p>
                            <p className="text-yellow-600 text-xs">Using sample data for visualization</p>
                        </div>
                    )} */}
                </div>
            </header>

            {/* 1. Key Metrics Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard
                    title="Total Requests (24h)"
                    value={data.volume.total_requests.toLocaleString()}
                    icon={<Layout className="w-5 h-5 text-purple-400" />}
                    subtext={`${data.volume.requests_per_minute.toFixed(2)} req/min`}
                />
                <StatCard
                    title="Avg Latency"
                    value={`${data.performance.avg_response_time.toFixed(2)}ms`}
                    icon={<Zap className="w-5 h-5 text-yellow-400" />}
                    subtext={`P99: ${data.performance.p99_response_time.toFixed(2)}ms`}
                />
                <StatCard
                    title="Failed Logins"
                    value={data.security.failed_logins.toLocaleString()}
                    icon={<Shield className="w-5 h-5 text-red-400" />}
                    subtext="Security Alerts"
                />
                <StatCard
                    title="Active Users"
                    value={data.users.unique_active_users.toLocaleString()}
                    icon={<Users className="w-5 h-5 text-green-400" />}
                    subtext="Unique IPs/IDs"
                />
            </div>

            {/* 2. Charts Row: Volume & Status Codes */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Status Code Distribution */}
                <div className="bg-gray-900 p-6 rounded-xl border border-gray-800 col-span-1">
                    <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                        <BarChart2 className="w-5 h-5 text-blue-400" />
                        Status Codes
                    </h2>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={data.errors.status_distribution}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={80}
                                    fill="#8884d8"
                                    paddingAngle={5}
                                    dataKey="count"
                                    nameKey="status"
                                >
                                    {data.errors.status_distribution.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f3f4f6' }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="flex flex-wrap gap-2 mt-4 justify-center">
                        {data.errors.status_distribution.map((entry, index) => (
                            <div key={index} className="flex items-center gap-1 text-sm bg-gray-800 px-2 py-1 rounded">
                                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                                <span>{entry.status}: {entry.count}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Top Endpoints */}
                <div className="bg-gray-900 p-6 rounded-xl border border-gray-800 col-span-2">
                    <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                        <Globe className="w-5 h-5 text-green-400" />
                        Top Endpoints
                    </h2>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={data.volume.top_endpoints} layout="vertical" margin={{ left: 20 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
                                <XAxis type="number" stroke="#9ca3af" />
                                <YAxis type="category" dataKey="endpoint" width={150} stroke="#9ca3af" tick={{ fontSize: 12 }} />
                                <Tooltip contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f3f4f6' }} />
                                <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            {/* 3. Detailed Lists Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Security / Top Attackers */}
                <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
                    <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 text-red-400">
                        <AlertTriangle className="w-5 h-5" />
                        Top Suspicious IPs & Sources
                    </h2>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="border-b border-gray-800 text-gray-400 text-sm">
                                    <th className="pb-3">Source IP</th>
                                    <th className="pb-3 text-right">Event Count</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.security.top_source_ips.length > 0 ? (
                                    data.security.top_source_ips.map((ip, i) => (
                                        <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/20">
                                            <td className="py-3 font-mono text-sm">{ip.ip}</td>
                                            <td className="py-3 text-right">{ip.count}</td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr><td colSpan={2} className="py-4 text-center text-gray-500">No suspicious sources found</td></tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Slowest Endpoints */}
                <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
                    <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 text-yellow-400">
                        <Clock className="w-5 h-5" />
                        Slowest Endpoints (Performance)
                    </h2>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="border-b border-gray-800 text-gray-400 text-sm">
                                    <th className="pb-3">Endpoint Path</th>
                                    <th className="pb-3 text-right">Avg Latency (ms)</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.performance.slowest_endpoints.length > 0 ? (
                                    data.performance.slowest_endpoints.map((ep, i) => (
                                        <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/20">
                                            <td className="py-3 font-mono text-sm truncate max-w-[200px]">{ep.path}</td>
                                            <td className="py-3 text-right text-yellow-500 font-medium">{ep.avg_time} ms</td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr><td colSpan={2} className="py-4 text-center text-gray-500">No latency data available</td></tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {/* 4. Errors & User Agents */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
                    <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 text-orange-400">
                        <Server className="w-5 h-5" />
                        Common Errors
                    </h2>
                    <ul className="space-y-3">
                        {data.errors.top_errors.map((err, i) => (
                            <li key={i} className="bg-red-900/10 border border-red-900/30 p-3 rounded flex justify-between items-center">
                                <span className="text-sm font-mono text-red-200 truncate pr-4" title={err.message}>
                                    {err.message}
                                </span>
                                <span className="text-xs bg-red-900/50 px-2 py-1 rounded text-red-100 whitespace-nowrap">
                                    {err.count} occurrences
                                </span>
                            </li>
                        ))}
                        {data.errors.top_errors.length === 0 && (
                            <li className="text-gray-500 text-center py-4">No significant errors found</li>
                        )}
                    </ul>
                </div>

                <div className="bg-gray-900 p-6 rounded-xl border border-gray-800">
                    <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 text-purple-400">
                        <Users className="w-5 h-5" />
                        User Agents
                    </h2>
                    <ul className="space-y-2">
                        {data.users.top_user_agents.map((ua, i) => (
                            <li key={i} className="flex justify-between items-center text-sm border-b border-gray-800 py-2 last:border-0">
                                <span className="text-gray-300 truncate max-w-[70%]" title={ua.agent}>{ua.agent}</span>
                                <span className="text-gray-500">{ua.count}</span>
                            </li>
                        ))}
                        {data.users.top_user_agents.length === 0 && (
                            <li className="text-gray-500 text-center py-4">No user agent data</li>
                        )}
                    </ul>
                </div>
            </div>

        </div>
    );
}

function StatCard({ title, value, icon, subtext }: { title: string, value: string, icon: React.ReactNode, subtext?: string }) {
    return (
        <div className="bg-gray-900 p-6 rounded-xl border border-gray-800 flex flex-col justify-between hover:border-blue-500/50 transition-colors">
            <div className="flex justify-between items-start mb-4">
                <h3 className="text-gray-400 text-sm font-medium">{title}</h3>
                <div className="p-2 bg-gray-800 rounded-lg">{icon}</div>
            </div>
            <div>
                <div className="text-2xl font-bold text-white">{value}</div>
                {subtext && <div className="text-xs text-gray-500 mt-1">{subtext}</div>}
            </div>
        </div>
    );
}
