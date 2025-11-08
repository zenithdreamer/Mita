import { DeviceTable } from "../components/organisms/DeviceTable";

interface DeviceTablePageProps {
    data: {
        device_id: string;
        device_type: string;
        status: string;
        last_seen: string;
        rssi: number;
        battery_level: number;
        address?: string;
        transport?: string;
        connection_duration?: number;
    }[];
    onNavigateToPackets?: () => void;
}

export function DeviceTablePage({ data, onNavigateToPackets }: DeviceTablePageProps) {
    return (
        <div className="DeviceTablePage p-4">
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-2xl font-bold">Devices</h2>
                {onNavigateToPackets && (
                    <button
                        onClick={onNavigateToPackets}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                    >
                        📡 Packet Monitor
                    </button>
                )}
            </div>
            <DeviceTable data={data} />
        </div>
    );
}