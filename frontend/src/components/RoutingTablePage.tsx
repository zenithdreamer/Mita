import { RoutingTable } from "./organisms/RoutingTable";

interface RoutingTablePageProps {
    data: {
        id: string;
        name: string;
        status: string;
    }[];
}

export function RoutingTablePage({ data }: RoutingTablePageProps) {
    return (
        <div className="RoutingTablePage">
            <h1>Routing Table</h1>
            <RoutingTable data={data} />
        </div>
    );
}