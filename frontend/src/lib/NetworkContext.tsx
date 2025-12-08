'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { usePathname, useSearchParams, useRouter } from 'next/navigation';

type NetworkContextType = {
    selectedNetwork: string | null;
    setSelectedNetwork: (network: string | null) => void;
    availableNetworks: string[];
    setAvailableNetworks: (networks: string[]) => void;
    isLoading: boolean;
};

const NetworkContext = createContext<NetworkContextType | undefined>(undefined);

export function NetworkProvider({ children }: { children: React.ReactNode }) {
    const [selectedNetwork, setSelectedNetworkState] = useState<string | null>(null);
    const [availableNetworks, setAvailableNetworks] = useState<string[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const router = useRouter();
    const pathname = usePathname();
    const searchParams = useSearchParams();

    // Load network from URL on mount
    useEffect(() => {
        const networkParam = searchParams?.get('network');
        if (networkParam) {
            setSelectedNetworkState(networkParam);
        }
        setIsLoading(false);
    }, [searchParams]);

    // Fetch available networks on mount
    useEffect(() => {
        const fetchNetworks = async () => {
            try {
                const res = await fetch('http://localhost:8000/api/v1/networks');
                if (res.ok) {
                    const networks = await res.json();
                    setAvailableNetworks(networks);
                }
            } catch (error) {
                console.error('Failed to fetch networks:', error);
            }
        };
        fetchNetworks();
    }, []);

    const setSelectedNetwork = (network: string | null) => {
        setSelectedNetworkState(network);

        // Update URL with network parameter
        const params = new URLSearchParams(searchParams?.toString() || '');
        if (network) {
            params.set('network', network);
        } else {
            params.delete('network');
        }

        const newUrl = pathname + (params.toString() ? `?${params.toString()}` : '');
        router.push(newUrl);
    };

    return (
        <NetworkContext.Provider
            value={{
                selectedNetwork,
                setSelectedNetwork,
                availableNetworks,
                setAvailableNetworks,
                isLoading,
            }}
        >
            {children}
        </NetworkContext.Provider>
    );
}

export function useNetwork() {
    const context = useContext(NetworkContext);
    if (context === undefined) {
        throw new Error('useNetwork must be used within a NetworkProvider');
    }
    return context;
}
