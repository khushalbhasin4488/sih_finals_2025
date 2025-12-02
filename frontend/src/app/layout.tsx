import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "../components/layout/Sidebar";

export const metadata: Metadata = {
    title: "Log Analyzer Tool",
    description: "Portable log analysis tool for cyber security monitoring",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en" className="dark">
            <body className="flex min-h-screen bg-zinc-950 text-zinc-50 antialiased">
                <Sidebar />
                <main className="flex-1 overflow-auto relative">
                    {children}
                </main>
            </body>
        </html>
    );
}
