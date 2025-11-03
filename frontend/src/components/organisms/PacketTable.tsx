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

interface PacketTableProps {
    packets: Packet[];
    onPacketClick: (packet: Packet) => void;
    formatDate: (timestamp: number) => string;
}

export function PacketTable({ packets, onPacketClick, formatDate }: PacketTableProps) {
    const getDirectionColor = (direction: string) => {
        switch (direction) {
            case 'inbound':
                return 'bg-blue-100 text-blue-800';
            case 'outbound':
                return 'bg-green-100 text-green-800';
            case 'forwarded':
                return 'bg-purple-100 text-purple-800';
            default:
                return 'bg-gray-100 text-gray-800';
        }
    };

    const getTransportIcon = (transport: string) => {
        return transport === 'wifi' ? '📶' : '🔷';
    };

    const getMessageTypeColor = (type: string) => {
        const colors: Record<string, string> = {
            'HELLO': 'bg-yellow-100 text-yellow-800',
            'CHALLENGE': 'bg-orange-100 text-orange-800',
            'AUTH': 'bg-red-100 text-red-800',
            'AUTH_ACK': 'bg-green-100 text-green-800',
            'DATA': 'bg-blue-100 text-blue-800',
            'ACK': 'bg-teal-100 text-teal-800',
            'CONTROL': 'bg-purple-100 text-purple-800',
            'ERROR': 'bg-red-200 text-red-900',
        };
        return colors[type] || 'bg-gray-100 text-gray-800';
    };

    return (
        <div className="bg-white rounded-lg shadow-md overflow-hidden">
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Timestamp
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Direction
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Type
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Source → Dest
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Size
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Transport
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Flags
                            </th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {packets.map((packet) => (
                            <tr
                                key={packet.id}
                                onClick={() => onPacketClick(packet)}
                                className="hover:bg-gray-50 cursor-pointer transition-colors"
                            >
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {formatDate(packet.timestamp)}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${getDirectionColor(packet.direction)}`}>
                                        {packet.direction}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${getMessageTypeColor(packet.messageType)}`}>
                                        {packet.messageType}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-mono">
                                    {packet.sourceAddr} → {packet.destAddr}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {packet.payloadSize} bytes
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {getTransportIcon(packet.transport)} {packet.transport.toUpperCase()}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {packet.encrypted && (
                                        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                            🔒 Encrypted
                                        </span>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
