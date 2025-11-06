import { RoutingTable } from "../components/organisms/RoutingTable";

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

export function RoutingTablePage({ data }: RoutingTablePageProps) {
    return (
        <div className="RoutingTablePage p-4">
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-2xl font-bold">Routing Table</h2>
            </div>
            <RoutingTable data={data} />
        </div>
    );
}