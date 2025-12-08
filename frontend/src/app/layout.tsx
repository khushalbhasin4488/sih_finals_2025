import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "../components/layout/Sidebar";
import { NetworkProvider } from "@/lib/NetworkContext";

export const metadata: Metadata = {
    title: "Log Analyzer - Security Monitoring",
    description: "Advanced log analysis and security monitoring system",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en" className="dark">
            <body className="flex min-h-screen bg-zinc-950 text-zinc-50 antialiased">
                <NetworkProvider>
                    <Sidebar />
                    <main className="flex-1 overflow-auto relative">
                        {children}
                    </main>
                </NetworkProvider>
            </body>
        </html>
    );
}
