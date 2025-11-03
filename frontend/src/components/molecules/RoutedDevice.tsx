import { StatusCard } from "../atoms/StatusCard";

interface RoutedDeviceProps {
    name: string;
    status: string;
}

export function RoutedDevice({ name, status }: RoutedDeviceProps) {
    return (
        <div className="routed-device">
            <StatusCard title={name} />
            <p>Status: {status}</p>
        </div>
    );
}