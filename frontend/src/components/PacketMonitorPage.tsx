import { useState, useEffect } from 'react';
import { PacketTable } from './organisms/PacketTable';
import { PacketDetailModal } from './molecules/PacketDetailModal';

interface Packet {
    id: string;
    timestamp: number;
    direction: string;
    sourceAddr: string;
    destAddr: string;
    messageType: string;
    payloadSize: number;
    transport: string;
    encrypted: boolean;
    rawData: string;
    decodedHeader: string;
    decodedPayload: string;
}

export function PacketMonitorPage() {
    const [packets, setPackets] = useState<Packet[]>([]);
    const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [autoRefresh, setAutoRefresh] = useState(true);

    const fetchPackets = async () => {
        try {
            const response = await fetch('http://localhost:8080/api/packets?limit=100');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            setPackets(data.packets || []);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to fetch packets');
            console.error('Error fetching packets:', err);
        } finally {
            setIsLoading(false);
        }
    };

    const clearPackets = async () => {
        try {
            const response = await fetch('http://localhost:8080/api/packets', {
                method: 'DELETE',
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            setPackets([]);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to clear packets');
            console.error('Error clearing packets:', err);
        }
    };

    useEffect(() => {
        fetchPackets();

        if (autoRefresh) {
            const interval = setInterval(fetchPackets, 2000); // Refresh every 2 seconds
            return () => clearInterval(interval);
        }
    }, [autoRefresh]);

    const formatDate = (timestamp: number) => {
        return new Date(timestamp).toLocaleString();
    };

    return (
        <div className="packet-monitor-page p-6 bg-gray-50 min-h-screen">
            <div className="max-w-7xl mx-auto">
                <div className="bg-white rounded-lg shadow-md p-6 mb-6">
                    <div className="flex justify-between items-center mb-4">
                        <div>
                            <h1 className="text-3xl font-bold text-gray-800">Packet Monitor</h1>
                            <p className="text-gray-600 mt-1">Live packet capture and inspection</p>
                        </div>
                        <div className="flex gap-3">
                            <button
                                onClick={() => setAutoRefresh(!autoRefresh)}
                                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                                    autoRefresh
                                        ? 'bg-green-500 hover:bg-green-600 text-white'
                                        : 'bg-gray-300 hover:bg-gray-400 text-gray-700'
                                }`}
                            >
                                {autoRefresh ? '⏸ Pause' : '▶ Resume'}
                            </button>
                            <button
                                onClick={fetchPackets}
                                disabled={isLoading}
                                className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-medium transition-colors disabled:opacity-50"
                            >
                                🔄 Refresh
                            </button>
                            <button
                                onClick={clearPackets}
                                className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg font-medium transition-colors"
                            >
                                🗑️ Clear All
                            </button>
                        </div>
                    </div>

                    <div className="flex items-center gap-4 text-sm text-gray-600">
                        <div className="flex items-center gap-2">
                            <span className="font-medium">Total Packets:</span>
                            <span className="bg-blue-100 text-blue-800 px-3 py-1 rounded-full font-semibold">
                                {packets.length}
                            </span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="font-medium">Auto-refresh:</span>
                            <span className={`px-3 py-1 rounded-full font-semibold ${
                                autoRefresh ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                            }`}>
                                {autoRefresh ? 'ON' : 'OFF'}
                            </span>
                        </div>
                    </div>
                </div>

                {error && (
                    <div className="bg-red-50 border border-red-300 text-red-800 px-4 py-3 rounded-lg mb-4">
                        <strong>Error:</strong> {error}
                    </div>
                )}

                {isLoading && packets.length === 0 ? (
                    <div className="bg-white rounded-lg shadow-md p-12 text-center">
                        <div className="text-gray-400 text-lg">Loading packets...</div>
                    </div>
                ) : packets.length === 0 ? (
                    <div className="bg-white rounded-lg shadow-md p-12 text-center">
                        <div className="text-gray-400 text-lg mb-2">No packets captured yet</div>
                        <div className="text-gray-500 text-sm">
                            Packets will appear here once network activity is detected
                        </div>
                    </div>
                ) : (
                    <PacketTable 
                        packets={packets} 
                        onPacketClick={setSelectedPacket}
                        formatDate={formatDate}
                    />
                )}

                {selectedPacket && (
                    <PacketDetailModal
                        packet={selectedPacket}
                        onClose={() => setSelectedPacket(null)}
                        formatDate={formatDate}
                    />
                )}
            </div>
        </div>
    );
}
