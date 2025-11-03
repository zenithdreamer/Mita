import { RoutingTable } from "./organisms/RoutingTable";

interface RoutingTablePageProps {
    data: {
        id: string;
        name: string;
        type: string;
        status: string;
        lastseen: string;
    }[];
}

export function RoutingTablePage({ data }: RoutingTablePageProps) {
    return (
        <div className="RoutingTablePage">
            <RoutingTable data={data} />
        </div>
    );
}