'use client';

import React from 'react';
import { Network, Globe } from 'lucide-react';
import { useNetwork } from '@/lib/NetworkContext';

export default function NetworkSwitcher() {
    const { selectedNetwork, setSelectedNetwork, availableNetworks, isLoading } = useNetwork();

    if (isLoading) {
        return (
            <div className="px-3 py-2 text-sm text-gray-500">
                Loading networks...
            </div>
        );
    }

    return (
        <div className="px-3 py-2">
            <label htmlFor="network-select" className="block text-xs font-medium text-gray-400 uppercase mb-2">
                <Globe className="w-3 h-3 inline mr-1" />
                Network Filter
            </label>
            <select
                id="network-select"
                value={selectedNetwork || ''}
                onChange={(e) => setSelectedNetwork(e.target.value || null)}
                className="w-full bg-gray-900 border border-gray-700 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent hover:border-gray-600 transition-colors"
            >
                <option value="">All Networks</option>
                {availableNetworks.map((network) => (
                    <option key={network} value={network}>
                        {network}
                    </option>
                ))}
            </select>

            {selectedNetwork && (
                <div className="mt-2 flex items-center gap-2 text-xs text-blue-400">
                    <Network className="w-3 h-3" />
                    <span>Filtering: {selectedNetwork}</span>
                </div>
            )}
        </div>
    );
}
