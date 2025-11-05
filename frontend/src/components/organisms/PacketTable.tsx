import type { PacketInfoDto } from '@/api';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { Lock, Wifi, Radio } from 'lucide-react';

interface PacketTableProps {
    packets: PacketInfoDto[];
    onPacketClick: (packet: PacketInfoDto) => void;
    formatDate: (timestamp: number | undefined) => string;
}

export function PacketTable({ packets, onPacketClick, formatDate }: PacketTableProps) {
    const getDirectionVariant = (direction?: string) => {
        switch (direction) {
            case 'inbound':
                return 'default';
            case 'outbound':
                return 'secondary';
            case 'forwarded':
                return 'outline';
            default:
                return 'outline';
        }
    };

    const getTransportIcon = (transport?: string) => {
        if (transport?.toLowerCase() === 'wifi') {
            return <Wifi className="h-3 w-3" />;
        }
        return <Radio className="h-3 w-3" />;
    };

    return (
        <Card>
            <div className="overflow-x-auto">
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead>Timestamp</TableHead>
                            <TableHead>Direction</TableHead>
                            <TableHead>Type</TableHead>
                            <TableHead>Source → Dest</TableHead>
                            <TableHead className="text-right">Size</TableHead>
                            <TableHead>Transport</TableHead>
                            <TableHead>Flags</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {packets.length === 0 ? (
                            <TableRow>
                                <TableCell colSpan={7} className="text-center text-muted-foreground">
                                    No packets to display
                                </TableCell>
                            </TableRow>
                        ) : (
                            packets.map((packet) => (
                                <TableRow
                                    key={packet.id}
                                    onClick={() => onPacketClick(packet)}
                                    className="cursor-pointer"
                                >
                                    <TableCell className="font-mono text-xs">
                                        {formatDate(packet.timestamp)}
                                    </TableCell>
                                    <TableCell>
                                        <Badge variant={getDirectionVariant(packet.direction)}>
                                            {packet.direction || 'unknown'}
                                        </Badge>
                                    </TableCell>
                                    <TableCell>
                                        <Badge variant="outline">
                                            {packet.messageType || 'N/A'}
                                        </Badge>
                                    </TableCell>
                                    <TableCell className="font-mono text-xs">
                                        {packet.sourceAddr || 'N/A'} → {packet.destAddr || 'N/A'}
                                    </TableCell>
                                    <TableCell className="text-right">
                                        {packet.payloadSize || 0} bytes
                                    </TableCell>
                                    <TableCell>
                                        <div className="flex items-center gap-1">
                                            {getTransportIcon(packet.transport)}
                                            <span className="text-xs uppercase">
                                                {packet.transport || 'N/A'}
                                            </span>
                                        </div>
                                    </TableCell>
                                    <TableCell>
                                        <div className="flex gap-1 flex-wrap">
                                            {packet.encrypted && (
                                                <Badge variant="secondary" className="gap-1">
                                                    <Lock className="h-3 w-3" />
                                                    Encrypted
                                                </Badge>
                                            )}
                                            {packet.isValid === false && (
                                                <Badge variant="destructive" className="gap-1">
                                                    {packet.errorFlags || 'INVALID'}
                                                </Badge>
                                            )}
                                        </div>
                                    </TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
            </div>
        </Card>
    );
}
