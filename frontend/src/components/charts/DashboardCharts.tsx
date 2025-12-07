'use client';

import {
    PieChart, Pie, Cell, ResponsiveContainer,
    AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
    BarChart, Bar, LineChart, Line, Legend
} from 'recharts';

// Dark theme colors matching zinc design
const COLORS = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#22c55e'
};

const CHART_COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#10b981', '#f59e0b', '#06b6d4'];

// Custom tooltip style for dark theme
const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
        return (
            <div className="bg-zinc-800 border border-zinc-700 rounded-lg p-3 shadow-xl">
                <p className="text-zinc-300 text-sm">{label}</p>
                {payload.map((entry: any, index: number) => (
                    <p key={index} className="text-sm font-medium" style={{ color: entry.color }}>
                        {entry.name}: {entry.value}
                    </p>
                ))}
            </div>
        );
    }
    return null;
};

// ============ SEVERITY PIE CHART ============
interface SeverityData {
    critical: number;
    high: number;
    medium: number;
    low: number;
}

export function SeverityPieChart({ data }: { data: SeverityData }) {
    const chartData = [
        { name: 'Critical', value: data.critical, color: COLORS.critical },
        { name: 'High', value: data.high, color: COLORS.high },
        { name: 'Medium', value: data.medium, color: COLORS.medium },
        { name: 'Low', value: data.low, color: COLORS.low },
    ].filter(d => d.value > 0);

    const total = chartData.reduce((sum, d) => sum + d.value, 0);

    if (total === 0) {
        return (
            <div className="h-64 flex items-center justify-center text-zinc-500">
                No alerts to display
            </div>
        );
    }

    return (
        <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={chartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={90}
                        paddingAngle={2}
                        dataKey="value"
                    >
                        {chartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                    <Legend
                        verticalAlign="bottom"
                        formatter={(value) => <span className="text-zinc-400 text-sm">{value}</span>}
                    />
                </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="text-center">
                    <p className="text-2xl font-bold text-white">{total}</p>
                    <p className="text-xs text-zinc-500">Total</p>
                </div>
            </div>
        </div>
    );
}

// ============ LOGS TIMELINE AREA CHART ============
interface TimelinePoint {
    time: string;
    count: number;
}

export function LogsTimelineChart({ data }: { data: TimelinePoint[] }) {
    if (!data || data.length === 0) {
        return (
            <div className="h-64 flex items-center justify-center text-zinc-500">
                No timeline data available
            </div>
        );
    }

    const formattedData = data.map(point => ({
        ...point,
        time: new Date(point.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }));

    return (
        <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={formattedData}>
                    <defs>
                        <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                    <XAxis
                        dataKey="time"
                        stroke="#71717a"
                        tick={{ fill: '#71717a', fontSize: 12 }}
                        interval="preserveStartEnd"
                    />
                    <YAxis
                        stroke="#71717a"
                        tick={{ fill: '#71717a', fontSize: 12 }}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Area
                        type="monotone"
                        dataKey="count"
                        stroke="#3b82f6"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#colorCount)"
                        name="Logs"
                    />
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
}

// ============ ALERT TYPES BAR CHART ============
interface AlertType {
    type: string;
    count: number;
}

export function AlertTypesBarChart({ data }: { data: AlertType[] }) {
    if (!data || data.length === 0) {
        return (
            <div className="h-64 flex items-center justify-center text-zinc-500">
                No alert types to display
            </div>
        );
    }

    const formattedData = data.slice(0, 6).map(item => ({
        ...item,
        type: item.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    }));

    return (
        <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
                <BarChart data={formattedData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272a" horizontal={false} />
                    <XAxis type="number" stroke="#71717a" tick={{ fill: '#71717a', fontSize: 12 }} />
                    <YAxis
                        dataKey="type"
                        type="category"
                        stroke="#71717a"
                        tick={{ fill: '#a1a1aa', fontSize: 11 }}
                        width={120}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} name="Count" />
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}

// ============ ANOMALY TREND LINE CHART ============
export function AnomalyTrendChart({ data }: { data: TimelinePoint[] }) {
    if (!data || data.length === 0) {
        return (
            <div className="h-64 flex items-center justify-center text-zinc-500">
                No anomaly trend data
            </div>
        );
    }

    const formattedData = data.map(point => ({
        ...point,
        time: new Date(point.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }));

    return (
        <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
                <LineChart data={formattedData}>
                    <defs>
                        <linearGradient id="colorAnomaly" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2} />
                            <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                    <XAxis
                        dataKey="time"
                        stroke="#71717a"
                        tick={{ fill: '#71717a', fontSize: 12 }}
                        interval="preserveStartEnd"
                    />
                    <YAxis stroke="#71717a" tick={{ fill: '#71717a', fontSize: 12 }} />
                    <Tooltip content={<CustomTooltip />} />
                    <Line
                        type="monotone"
                        dataKey="count"
                        stroke="#06b6d4"
                        strokeWidth={2}
                        dot={{ fill: '#06b6d4', strokeWidth: 0, r: 3 }}
                        activeDot={{ r: 5, fill: '#06b6d4' }}
                        name="Anomalies"
                    />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}

// ============ HOST ACTIVITY BAR CHART ============
interface HostData {
    host: string;
    count: number;
}

export function HostActivityChart({ data }: { data: HostData[] }) {
    if (!data || data.length === 0) {
        return (
            <div className="h-64 flex items-center justify-center text-zinc-500">
                No host data available
            </div>
        );
    }

    return (
        <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.slice(0, 5)}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                    <XAxis
                        dataKey="host"
                        stroke="#71717a"
                        tick={{ fill: '#a1a1aa', fontSize: 11 }}
                        interval={0}
                    />
                    <YAxis stroke="#71717a" tick={{ fill: '#71717a', fontSize: 12 }} />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} name="Logs">
                        {data.slice(0, 5).map((_, index) => (
                            <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}

// ============ DETECTION METHODS PIE CHART ============
interface DetectionMethod {
    method: string;
    count: number;
}

export function DetectionMethodsChart({ data }: { data: DetectionMethod[] }) {
    if (!data || data.length === 0) {
        return (
            <div className="h-64 flex items-center justify-center text-zinc-500">
                No detection data
            </div>
        );
    }

    const chartData = data.map((item, index) => ({
        name: item.method.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        value: item.count,
        color: CHART_COLORS[index % CHART_COLORS.length]
    }));

    return (
        <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={chartData}
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}
                        labelLine={false}
                    >
                        {chartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
}
