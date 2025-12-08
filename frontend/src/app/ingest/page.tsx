"use client";

import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
    Upload,
    FileText,
    CheckCircle,
    AlertCircle,
    Loader2,
    HardDrive,
    Send,
    Scan,
    Zap
} from "lucide-react";
import { parse } from "path";

export default function IngestPage() {
    const [isDragging, setIsDragging] = useState(false);
    const [file, setFile] = useState<File | null>(null);
    const [uploading, setUploading] = useState(false);
    const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle');
    const [statusMessage, setStatusMessage] = useState("");
    const [stats, setStats] = useState<{ count?: number }>({});

    const fileInputRef = useRef<HTMLInputElement>(null);

    const handleDragOver = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(true);
    };

    const handleDragLeave = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
    };

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);

        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setFile(e.dataTransfer.files[0]);
            setStatus('idle');
        }
    };

    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0]);
            setStatus('idle');
        }
    };

    const handleUpload = async () => {
        if (!file) return;

        setUploading(true);
        setStatus('idle');

        const formData = new FormData();
        formData.append("file", file);

        try {
            // Simulate flight time for animation (at least 2s)
            const minWait = new Promise(resolve => setTimeout(resolve, 2000));

            const uploadPromise = fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/v1/ingest/upload`, {
                method: "POST",
                body: formData,
            });

            const [response, _] = await Promise.all([uploadPromise, minWait]);

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Upload failed");
            }

            setStatus('success');
            setStatusMessage(`Successfully ingested ${data.count} logs from ${data.filename}`);
            setStats({ count: data.count });
            setFile(null); // Clear file after success

            // Reset input
            if (fileInputRef.current) {
                fileInputRef.current.value = "";
            }

        } catch (error: any) {
            console.error("Upload error:", error);
            setStatus('error');
            setStatusMessage(error.message || "Failed to upload file");
        } finally {
            setUploading(false);
        }
    };

    return (
        <div className="p-6 max-w-7xl mx-auto space-y-8 min-h-screen relative overflow-hidden">

            {/* Background Ambience */}
            <div className="absolute inset-0 pointer-events-none opacity-20">
                <div className="absolute top-20 left-10 w-64 h-64 bg-blue-500/20 rounded-full blur-3xl animate-pulse" />
                <div className="absolute bottom-20 right-10 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl" />
            </div>

            {/* Header */}
            <div className="flex items-center justify-between relative z-10">
                <div>
                    <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-zinc-400 mb-2">
                        Log Ingestion
                    </h1>
                    <p className="text-zinc-400">Drag & Drop or use USB to ingest logs manually</p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative z-10">

                {/* Interactive Drop Zone Area */}
                <div className="md:col-span-2 space-y-6 relative">

                    <motion.div
                        layout
                        className={`
              relative border-2 border-dashed rounded-2xl p-16 transition-all duration-300 flex flex-col items-center justify-center text-center cursor-pointer overflow-hidden
              ${isDragging
                                ? "border-blue-400 bg-blue-500/10 shadow-[0_0_30px_rgba(59,130,246,0.2)]"
                                : "border-zinc-800 bg-zinc-900/50 hover:border-zinc-700 hover:bg-zinc-900"}
            `}
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onDrop={handleDrop}
                        onClick={() => !uploading && fileInputRef.current?.click()}
                    >
                        <input
                            type="file"
                            ref={fileInputRef}
                            className="hidden"
                            onChange={handleFileSelect}
                            accept=".json,.csv,.log,.txt"
                            disabled={uploading}
                        />

                        <AnimatePresence mode="wait">
                            {uploading ? (
                                // FLYING PLANE ANIMATION STATE
                                <motion.div
                                    key="flying"
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    exit={{ opacity: 0 }}
                                    className="flex flex-col items-center relative w-full h-40 justify-center"
                                >
                                    {/* The Plane */}
                                    <motion.div
                                        initial={{ x: -100, y: 50, scale: 0.8, rotate: -10 }}
                                        animate={{
                                            x: [-100, 0, 200, 400],
                                            y: [50, -20, -60, -100],
                                            scale: [0.8, 1.2, 0.8, 0.5],
                                            rotate: [-10, 10, 20, 45]
                                        }}
                                        transition={{
                                            duration: 2.5,
                                            ease: "easeInOut",
                                            repeat: Infinity,
                                            repeatDelay: 0.5
                                        }}
                                        className="absolute z-20"
                                    >
                                        <Send className="w-16 h-16 text-blue-400 fill-blue-500/20" />
                                        {/* Stream Trail behind plane */}
                                        <motion.div
                                            className="absolute top-1/2 right-full w-20 h-1 bg-gradient-to-l from-blue-400/50 to-transparent blur-sm"
                                            initial={{ scaleX: 0 }}
                                            animate={{ scaleX: 1 }}
                                        />
                                    </motion.div>

                                    {/* Scanning Grid Background */}
                                    <motion.div
                                        className="absolute inset-0 bg-[linear-gradient(rgba(59,130,246,0.1)_1px,transparent_1px),linear-gradient(90deg,rgba(59,130,246,0.1)_1px,transparent_1px)] bg-[size:20px_20px]"
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1, y: [0, 20] }}
                                        transition={{ repeat: Infinity, duration: 2, ease: "linear" }}
                                    />

                                    {/* Radar Scan Line */}
                                    <motion.div
                                        className="absolute top-0 left-0 w-full h-1 bg-blue-500/50 shadow-[0_0_15px_rgba(59,130,246,1)]"
                                        animate={{ top: ["0%", "100%"] }}
                                        transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                                    />

                                    <div className="mt-24 z-10 bg-zinc-950/80 px-4 py-2 rounded-full border border-blue-500/30 backdrop-blur-md">
                                        <p className="text-blue-400 font-mono text-sm animate-pulse">
                                            Deploying to Detection Engine...
                                        </p>
                                    </div>
                                </motion.div>
                            ) : (
                                // IDLE STATE
                                <motion.div
                                    key="idle"
                                    initial={{ opacity: 0, scale: 0.9 }}
                                    animate={{ opacity: 1, scale: 1 }}
                                    exit={{ opacity: 0, scale: 0.9 }}
                                    className="flex flex-col items-center"
                                >
                                    <div className={`w-20 h-20 rounded-2xl flex items-center justify-center mb-6 transition-colors ${file ? 'bg-blue-500/20' : 'bg-zinc-800'}`}>
                                        {file ? (
                                            <FileText className="w-10 h-10 text-blue-400" />
                                        ) : (
                                            <Upload className="w-10 h-10 text-zinc-400" />
                                        )}
                                    </div>

                                    <div className="space-y-3">
                                        <h3 className="text-xl font-medium text-white">
                                            {file ? file.name : "Drop logs to analyze"}
                                        </h3>
                                        <p className="text-sm text-zinc-500">
                                            {file
                                                ? `${(file.size / 1024).toFixed(2)} KB • Ready to fly`
                                                : "Supports JSON, CSV, LOG, TXT"}
                                        </p>
                                    </div>

                                    {file && (
                                        <motion.div
                                            initial={{ opacity: 0, y: 10 }}
                                            animate={{ opacity: 1, y: 0 }}
                                            className="mt-6"
                                        >
                                            <p className="text-xs text-blue-400 mb-2 font-mono">Ready for takeoff</p>
                                        </motion.div>
                                    )}
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </motion.div>

                    {/* Action Button */}
                    <div className="flex justify-end">
                        <button
                            onClick={handleUpload}
                            disabled={!file || uploading}
                            className={`
                px-8 py-3 rounded-xl font-semibold flex items-center gap-3 transition-all relative overflow-hidden group
                ${!file || uploading
                                    ? "bg-zinc-800 text-zinc-500 cursor-not-allowed"
                                    : "bg-blue-600 hover:bg-blue-500 text-white shadow-[0_0_20px_rgba(37,99,235,0.3)] hover:shadow-[0_0_30px_rgba(37,99,235,0.5)] active:scale-95"}
              `}
                        >
                            {/* Button shimmer effect */}
                            {!uploading && file && (
                                <div className="absolute inset-0 -translate-x-full group-hover:animate-[shimmer_2s_infinite] bg-gradient-to-r from-transparent via-white/20 to-transparent" />
                            )}

                            {uploading ? (
                                <>Processing...</>
                            ) : (
                                <>
                                    <Send className={`w-5 h-5 ${file ? 'group-hover:translate-x-1 group-hover:-translate-y-1 transition-transform' : ''}`} />
                                    Launch Analysis
                                </>
                            )}
                        </button>
                    </div>

                    {/* Status Message */}
                    <AnimatePresence>
                        {status !== 'idle' && (
                            <motion.div
                                initial={{ opacity: 0, y: 20, scale: 0.95 }}
                                animate={{ opacity: 1, y: 0, scale: 1 }}
                                exit={{ opacity: 0, y: -20 }}
                                className={`p-6 rounded-xl flex items-start gap-4 shadow-xl backdrop-blur-md ${status === 'success'
                                    ? 'bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/20 text-green-100'
                                    : 'bg-gradient-to-r from-red-500/10 to-orange-500/10 border border-red-500/20 text-red-100'
                                    }`}
                            >
                                <div className={`p-2 rounded-full ${status === 'success' ? 'bg-green-500/20' : 'bg-red-500/20'}`}>
                                    {status === 'success' ? <CheckCircle className="w-6 h-6 text-green-400" /> : <AlertCircle className="w-6 h-6 text-red-400" />}
                                </div>
                                <div>
                                    <h4 className="font-semibold text-lg">{status === 'success' ? 'Mission Successful' : 'Mission Failed'}</h4>
                                    <p className="text-sm opacity-80">{statusMessage}</p>
                                </div>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>

                {/* Instructions Panel - Glassmorphism */}
                <div className="bg-zinc-900/40 backdrop-blur-md border border-zinc-800/50 rounded-2xl p-6 h-fit relative group hover:border-zinc-700transition-colors">
                    <div className="absolute inset-0 bg-gradient-to-b from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-2xl pointer-events-none" />

                    <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                        <Scan className="w-5 h-5 text-blue-400" />
                        Supported Formats
                    </h3>
                    <ul className="space-y-6">
                        <li className="flex gap-4 items-start">
                            <div className="p-2.5 bg-blue-500/10 rounded-xl mt-1 border border-blue-500/20">
                                <FileText className="w-5 h-5 text-blue-400" />
                            </div>
                            <div>
                                <p className="text-sm font-semibold text-white">JSON Logs</p>
                                <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                                    Standard format for structured data. We auto-map `timestamp` and `source_ip`.
                                </p>
                            </div>
                        </li>
                        <li className="flex gap-4 items-start">
                            <div className="p-2.5 bg-purple-500/10 rounded-xl mt-1 border border-purple-500/20">
                                <FileText className="w-5 h-5 text-purple-400" />
                            </div>
                            <div>
                                <p className="text-sm font-semibold text-white">CSV Files</p>
                                <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                                    Bulk upload spreadsheets. Ensure header row is present for column mapping.
                                </p>
                            </div>
                        </li>
                        <li className="flex gap-4 items-start">
                            <div className="p-2.5 bg-emerald-500/10 rounded-xl mt-1 border border-emerald-500/20">
                                <HardDrive className="w-5 h-5 text-emerald-400" />
                            </div>
                            <div>
                                <p className="text-sm font-semibold text-white">USB Import</p>
                                <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                                    Connect any secure drive and select files directly via the picker.
                                </p>
                            </div>
                        </li>
                    </ul>

                    <div className="mt-8 pt-6 border-t border-zinc-800">
                        <div className="flex items-center gap-2 text-xs text-zinc-500">
                            <Zap className="w-3 h-3 text-yellow-500" />
                            <span>Powered by DuckDB & Async Analysis</span>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
}
