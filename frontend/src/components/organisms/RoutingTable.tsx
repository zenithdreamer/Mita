import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "../ui/table";
import { Badge } from "../ui/badge";
import { StatusCard } from "../atoms/StatusCard";

interface RoutingTableProps {
    data: {
        device_id: string;
        device_type: string;
        status: string;
        assigned_address: string;
        last_seen: string;
    }[];
}

export function RoutingTable({ data }: RoutingTableProps) {
    return (
        <div className="rounded-md border bg-card shadow-sm">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead className="font-semibold">Device ID</TableHead>
                        <TableHead className="font-semibold">Type</TableHead>
                        <TableHead className="font-semibold">Status</TableHead>
                        <TableHead className="font-semibold">Assigned Address</TableHead>
                        <TableHead className="font-semibold">Last Seen</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {data.length === 0 ? (
                        <TableRow>
                            <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                                No devices found
                            </TableCell>
                        </TableRow>
                    ) : (
                        data.map((device) => (
                            <TableRow key={device.device_id} className="hover:bg-muted/50">
                                <TableCell className="font-mono text-sm">{device.device_id}</TableCell>
                                <TableCell>
                                    <Badge variant="outline" className="bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800">
                                        {device.device_type}
                                    </Badge>
                                </TableCell>
                                <TableCell>
                                    <StatusCard status={device.status} />
                                </TableCell>
                                <TableCell className="font-medium">{device.assigned_address}</TableCell>
                                <TableCell className="text-muted-foreground">{device.last_seen}</TableCell>
                            </TableRow>
                        ))
                    )}
                </TableBody>
            </Table>
        </div>
    );
}