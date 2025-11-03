import { StatusCard } from "../atoms/StatusCard";

interface RoutedDeviceProps {
    id: string;
    name: string;
    type: string;
    status: string;
    lastseen: string;
}   

export function RoutedDevice({ id, name, type, status, lastseen }: RoutedDeviceProps) {
    return (
        <div className="flex flex-row text-md gap-4">
            <h3>{id}</h3>
            <h3>{name}</h3>
            <h3>{type}</h3>
            <StatusCard status={status} />
            <h3>{lastseen}</h3>
        </div>
    );
}