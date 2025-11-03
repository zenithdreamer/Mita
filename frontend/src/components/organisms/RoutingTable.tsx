import { RoutedDevice } from "../molecules/RoutedDevice";

interface RoutingTableProps {
    data: {
        id: string;
        name: string;
        type: string;
        status: string;
        lastseen: string;
    }[];
}

export function RoutingTable({ data }: RoutingTableProps) {
    return (
        <div className="flex flex-col gap-4">
            <div className="flex flex-row gap-4">
                <div>ID</div>
                <div>Name</div>
                <div>Type</div>
                <div>Status</div>
                <div>Last seen</div>
            </div>

            {data.map((device) => (
                <RoutedDevice key={device.id} id={device.id} name={device.name} type={device.type} status={device.status} lastseen={device.lastseen} />
            ))}
        </div>
    );
}