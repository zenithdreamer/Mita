import { RoutedDevice } from "../molecules/RoutedDevice";

interface RoutingTableProps {
    data: {
        id: string;
        name: string;
        status: string;
    }[];
}

export function RoutingTable({ data }: RoutingTableProps) {
    return (
        <div className="routing-table">
            {data.map((device) => (
                <RoutedDevice key={device.id} name={device.name} status={device.status} />
            ))}
        </div>
    );
}