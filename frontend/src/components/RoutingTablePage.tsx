import { RoutingTable } from "./organisms/RoutingTable";

interface RoutingTablePageProps {
    data: {
        id: string;
        name: string;
        type: string;
        status: string;
        lastseen: string;
    }[];
    onNavigateToPackets?: () => void;
}

export function RoutingTablePage({ data, onNavigateToPackets }: RoutingTablePageProps) {
    return (
        <div className="RoutingTablePage p-4">
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-2xl font-bold">Routing Table</h2>
                {onNavigateToPackets && (
                    <button
                        onClick={onNavigateToPackets}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                    >
                        📡 Packet Monitor
                    </button>
                )}
            </div>
            <RoutingTable data={data} />
        </div>
    );
}