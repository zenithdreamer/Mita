import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "../ui/table";
import { StatusCard } from "../atoms/StatusCard";
import { Wifi, Radio } from 'lucide-react';

interface DeviceTableProps {
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
}

function formatDuration(seconds: number): string {
    if (seconds < 60) {
        return `${seconds}s`;
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${minutes}m ${secs}s`;
    } else if (seconds < 86400) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    } else {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        return `${days}d ${hours}h`;
    }
}

export function DeviceTable({ data }: DeviceTableProps) {
    const getTransportIcon = (transport?: string) => {
        if (transport?.toLowerCase() === 'wifi') {
            return <Wifi className="h-3 w-3" />;
        }
        return <Radio className="h-3 w-3" />;
    };

    return (
        <div className="rounded-md border bg-card shadow-sm">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead className="font-semibold">Device ID</TableHead>
                        <TableHead className="font-semibold">Address</TableHead>
                        <TableHead className="font-semibold">Transport</TableHead>
                        <TableHead className="font-semibold">Status</TableHead>
                        <TableHead className="font-semibold">Connected For</TableHead>
                        <TableHead className="font-semibold">Last Seen</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {data.length === 0 ? (
                        <TableRow>
                            <TableCell colSpan={6} className="h-24 text-center text-muted-foreground">
                                No devices found
                            </TableCell>
                        </TableRow>
                    ) : (
                        data.map((device) => (
                            <TableRow key={device.device_id} className="hover:bg-muted/50">
                                <TableCell className="font-mono text-sm">{device.device_id}</TableCell>
                                <TableCell className="font-mono text-sm">
                                    {device.address || 'N/A'}
                                </TableCell>
                                <TableCell>
                                    <div className="flex items-center gap-1">
                                        {getTransportIcon(device.transport)}
                                        <span className="text-xs uppercase">
                                            {device.transport || device.device_type}
                                        </span>
                                    </div>
                                </TableCell>
                                <TableCell>
                                    <StatusCard status={device.status} />
                                </TableCell>
                                <TableCell className="font-mono text-sm">
                                    {device.connection_duration !== undefined 
                                        ? formatDuration(device.connection_duration)
                                        : 'N/A'}
                                </TableCell>
                                <TableCell className="text-muted-foreground">{device.last_seen}</TableCell>
                            </TableRow>
                        ))
                    )}
                </TableBody>
            </Table>
        </div>
    );
}