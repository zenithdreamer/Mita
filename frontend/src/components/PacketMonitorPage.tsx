import { useState, useEffect } from 'react';
import { PacketTable } from './organisms/PacketTable';
import { getPackets, clearPackets as clearPacketsApi, getSettings, updateSettings } from '@/api';
import type { PacketInfoDto } from '@/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { RefreshCw, Pause, Play, Trash2, Loader2, ChevronLeft, ChevronRight, X, Unlock } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export function PacketMonitorPage() {
    const { toast } = useToast();
    const [packets, setPackets] = useState<PacketInfoDto[]>([]);
    const [selectedPacket, setSelectedPacket] = useState<PacketInfoDto | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [monitorEnabled, setMonitorEnabled] = useState(false);
    const [isMonitorLoading, setIsMonitorLoading] = useState(false);

    // Pagination state
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPackets, setTotalPackets] = useState(0);
    const [pageSize, setPageSize] = useState(50);

    const fetchPackets = async () => {
        try {
            const offset = (currentPage - 1) * pageSize;
            const response = await getPackets({
                query: {
                    limit: pageSize,
                    offset: offset
                }
            });

            if (response.data) {
                setPackets(response.data.packets || []);
                setTotalPackets(response.data.total || 0);
                setError(null);
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to fetch packets');
            console.error('Error fetching packets:', err);
        } finally {
            setIsLoading(false);
        }
    };

    const handleClearPackets = async () => {
        try {
            await clearPacketsApi();
            setPackets([]);
            setTotalPackets(0);
            setCurrentPage(1);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to clear packets');
            console.error('Error clearing packets:', err);
        }
    };

    const fetchMonitorSettings = async () => {
        try {
            const { data, error } = await getSettings();
            if (error) {
                console.error('Failed to fetch monitor settings:', error);
                return;
            }
            if (data) {
                setMonitorEnabled(data.monitorEnabled ?? false);
            }
        } catch (err) {
            console.error('Error fetching monitor settings:', err);
        }
    };

    const handleMonitorToggle = async (enabled: boolean) => {
        setIsMonitorLoading(true);
        try {
            const { data: currentSettings } = await getSettings();

            const { data, error } = await updateSettings({
                body: {
                    wifiEnabled: currentSettings?.wifiEnabled ?? false,
                    bleEnabled: currentSettings?.bleEnabled ?? false,
                    zigbeeEnabled: currentSettings?.zigbeeEnabled ?? false,
                    monitorEnabled: enabled,
                }
            });

            if (error) {
                throw new Error('Failed to update monitor setting');
            }

            if (data) {
                setMonitorEnabled(data.monitorEnabled ?? false);
                toast({
                    title: enabled ? "Monitor Enabled" : "Monitor Disabled",
                    description: enabled
                        ? "Packet monitoring is now active. Packets will be monitored and stored."
                        : "Packet monitoring has been stopped. No new packets will be monitored.",
                });
            }
        } catch (err) {
            console.error('Error toggling monitor:', err);
            toast({
                title: "Error",
                description: "Failed to update packet monitor setting",
                variant: "destructive",
            });
            // Revert to previous state
            fetchMonitorSettings();
        } finally {
            setIsMonitorLoading(false);
        }
    };

    useEffect(() => {
        fetchPackets();
        fetchMonitorSettings();

        if (autoRefresh) {
            const interval = setInterval(fetchPackets, 2000);
            return () => clearInterval(interval);
        }
    }, [autoRefresh, currentPage, pageSize]);

    const formatDate = (timestamp: number | undefined) => {
        if (!timestamp) return 'N/A';
        return new Date(timestamp).toLocaleString();
    };

    // Pagination calculations
    const totalPages = Math.ceil(totalPackets / pageSize);
    const startIndex = (currentPage - 1) * pageSize + 1;
    const endIndex = Math.min(currentPage * pageSize, totalPackets);

    const handlePreviousPage = () => {
        setCurrentPage(prev => Math.max(1, prev - 1));
    };

    const handleNextPage = () => {
        setCurrentPage(prev => Math.min(totalPages, prev + 1));
    };

    const handlePageSizeChange = (newSize: number) => {
        setPageSize(newSize);
        setCurrentPage(1);
    };

    return (
        <div className="h-full flex flex-col space-y-4">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Packet Monitor</h1>
                <p className="text-muted-foreground">Live packet monitoring and inspection</p>
            </div>

            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <div>
                            <CardTitle>Monitor Controls</CardTitle>
                            <CardDescription>Manage packet monitoring and recording</CardDescription>
                        </div>
                        <div className="flex gap-2">
                            <Button
                                variant={autoRefresh ? "default" : "outline"}
                                size="sm"
                                onClick={() => setAutoRefresh(!autoRefresh)}
                            >
                                {autoRefresh ? (
                                    <>
                                        <Pause className="h-4 w-4 mr-2" />
                                        Pause
                                    </>
                                ) : (
                                    <>
                                        <Play className="h-4 w-4 mr-2" />
                                        Resume
                                    </>
                                )}
                            </Button>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={fetchPackets}
                                disabled={isLoading}
                            >
                                <RefreshCw className="h-4 w-4 mr-2" />
                                Refresh
                            </Button>
                            <Button
                                variant="destructive"
                                size="sm"
                                onClick={handleClearPackets}
                            >
                                <Trash2 className="h-4 w-4 mr-2" />
                                Clear
                            </Button>

                        </div>
                    </div>
                </CardHeader>
                <CardContent>
                    <div className="flex items-center gap-6">
                        <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">Total Packets:</span>
                            <Badge variant="secondary">{totalPackets}</Badge>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">Showing:</span>
                            <Badge variant="outline">
                                {totalPackets === 0 ? '0' : `${startIndex}-${endIndex}`}
                            </Badge>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">Auto-refresh:</span>
                            <Badge variant={autoRefresh ? "default" : "outline"}>
                                {autoRefresh ? 'ON' : 'OFF'}
                            </Badge>
                        </div>
                        <div className="flex items-center gap-3 border-l pl-6">
                            <div className="flex items-center gap-2">
                                {isMonitorLoading ? (
                                    <Loader2 className="h-4 w-4 animate-spin" />
                                ) : (
                                    <Switch
                                        id="monitor-toggle"
                                        checked={monitorEnabled}
                                        onCheckedChange={handleMonitorToggle}
                                        disabled={isMonitorLoading}
                                    />
                                )}
                                <Label htmlFor="monitor-toggle" className="text-sm font-medium cursor-pointer">
                                    Packet Monitor
                                </Label>
                            </div>
                            <Badge variant={monitorEnabled ? "default" : "secondary"}>
                                {monitorEnabled ? 'MONITORING' : 'STOPPED'}
                            </Badge>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {error && (
                <Card className="border-destructive">
                    <CardContent className="pt-6">
                        <p className="text-sm text-destructive">
                            <strong>Error:</strong> {error}
                        </p>
                    </CardContent>
                </Card>
            )}

            {isLoading && packets.length === 0 ? (
                <Card>
                    <CardContent className="p-12 text-center">
                        <p className="text-muted-foreground">Loading packets...</p>
                    </CardContent>
                </Card>
            ) : packets.length === 0 ? (
                <Card>
                    <CardContent className="p-12 text-center">
                        <p className="text-lg text-muted-foreground mb-2">No packets monitored yet</p>
                        <p className="text-sm text-muted-foreground">
                            Packets will appear here once monitoring is enabled and network activity is detected
                        </p>
                    </CardContent>
                </Card>
            ) : (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 flex-1">
                    {/* Left side - Packet List */}
                    <div className="lg:col-span-2 space-y-4">
                        <PacketTable
                            packets={packets}
                            onPacketClick={setSelectedPacket}
                            formatDate={formatDate}
                        />

                        {/* Pagination Controls */}
                        <Card>
                            <CardContent className="pt-6">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <span className="text-sm text-muted-foreground">
                                            Page {currentPage} of {totalPages || 1}
                                        </span>
                                        <div className="flex items-center gap-2">
                                            <span className="text-sm text-muted-foreground">Items per page:</span>
                                            <div className="flex gap-1">
                                                {[25, 50, 100, 200].map(size => (
                                                    <Button
                                                        key={size}
                                                        variant={pageSize === size ? "default" : "outline"}
                                                        size="sm"
                                                        onClick={() => handlePageSizeChange(size)}
                                                    >
                                                        {size}
                                                    </Button>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={handlePreviousPage}
                                            disabled={currentPage === 1}
                                        >
                                            <ChevronLeft className="h-4 w-4 mr-1" />
                                            Previous
                                        </Button>
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={handleNextPage}
                                            disabled={currentPage >= totalPages}
                                        >
                                            Next
                                            <ChevronRight className="h-4 w-4 ml-1" />
                                        </Button>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    </div>

                    {/* Right side - Packet Details */}
                    <div className="lg:col-span-1">
                        {selectedPacket ? (
                            <Card className="sticky top-4 max-h-[calc(100vh-8rem)] overflow-hidden flex flex-col">
                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                    <CardTitle className="text-lg">Packet Details</CardTitle>
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => setSelectedPacket(null)}
                                    >
                                        <X className="h-4 w-4" />
                                    </Button>
                                </CardHeader>
                                <Separator />
                                <CardContent className="pt-4 overflow-y-auto">
                                    <Tabs defaultValue="info" className="w-full">
                                        <TabsList className="grid w-full grid-cols-3">
                                            <TabsTrigger value="info">Info</TabsTrigger>
                                            <TabsTrigger value="raw">Raw</TabsTrigger>
                                            <TabsTrigger value="decoded">Decoded</TabsTrigger>
                                        </TabsList>

                                        <TabsContent value="info" className="mt-4">
                                    <div className="space-y-4">
                                        {/* Basic Info */}
                                        <div>
                                            <h3 className="font-semibold mb-2">Basic Information</h3>
                                            <div className="space-y-2 text-sm">
                                                <div className="grid grid-cols-3 gap-2">
                                                    <span className="text-muted-foreground">ID:</span>
                                                    <span className="col-span-2 font-mono text-xs break-all">{selectedPacket.id}</span>
                                                </div>
                                                <div className="grid grid-cols-3 gap-2">
                                                    <span className="text-muted-foreground">Timestamp:</span>
                                                    <span className="col-span-2">{formatDate(selectedPacket.timestamp)}</span>
                                                </div>
                                                <div className="grid grid-cols-3 gap-2">
                                                    <span className="text-muted-foreground">Direction:</span>
                                                    <span className="col-span-2">
                                                        <Badge variant="outline">{selectedPacket.direction}</Badge>
                                                    </span>
                                                </div>
                                                <div className="grid grid-cols-3 gap-2">
                                                    <span className="text-muted-foreground">Transport:</span>
                                                    <span className="col-span-2">
                                                        <Badge variant="secondary">{selectedPacket.transport}</Badge>
                                                    </span>
                                                </div>
                                            </div>
                                        </div>

                                        <Separator />

                                        {/* Packet Info */}
                                        <div>
                                            <h3 className="font-semibold mb-2">Packet Header</h3>
                                            <div className="space-y-2 text-sm">
                                                <div className="grid grid-cols-3 gap-2">
                                                    <span className="text-muted-foreground">Source:</span>
                                                    <span className="col-span-2 font-mono text-xs">{selectedPacket.sourceAddr}</span>
                                                </div>
                                                <div className="grid grid-cols-3 gap-2">
                                                    <span className="text-muted-foreground">Destination:</span>
                                                    <span className="col-span-2 font-mono text-xs">{selectedPacket.destAddr}</span>
                                                </div>
                                                <div className="grid grid-cols-3 gap-2">
                                                    <span className="text-muted-foreground">Type:</span>
                                                    <span className="col-span-2">
                                                        <Badge>{selectedPacket.messageType}</Badge>
                                                    </span>
                                                </div>
                                                <div className="grid grid-cols-3 gap-2">
                                                    <span className="text-muted-foreground">Payload Size:</span>
                                                    <span className="col-span-2">{selectedPacket.payloadSize} bytes</span>
                                                </div>
                                                <div className="grid grid-cols-3 gap-2">
                                                    <span className="text-muted-foreground">Encrypted:</span>
                                                    <span className="col-span-2">
                                                        <Badge variant={selectedPacket.encrypted ? "default" : "secondary"}>
                                                            {selectedPacket.encrypted ? 'Yes' : 'No'}
                                                        </Badge>
                                                    </span>
                                                </div>
                                            </div>
                                        </div>

                                        <Separator />

                                        {/* Additional Header Fields */}
                                        <div>
                                            <h3 className="font-semibold mb-2">Header Details</h3>
                                            <div className="space-y-1 text-sm">
                                                <div className="bg-muted/50 p-2 rounded-md font-mono text-xs space-y-1">
                                                    {selectedPacket.decodedHeader && selectedPacket.decodedHeader.split('\n').map((line, idx) => (
                                                        <div key={idx} className="flex">
                                                            <span className="text-muted-foreground min-w-[140px]">{line.split(':')[0]}:</span>
                                                            <span className="flex-1">{line.split(':').slice(1).join(':')}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        </div>

                                        {selectedPacket.errorFlags && (
                                            <>
                                                <Separator />
                                                <div>
                                                    <h3 className="font-semibold mb-2 text-destructive">Error Information</h3>
                                                    <div className="bg-destructive/10 border border-destructive/20 p-3 rounded-md">
                                                        <p className="text-sm text-destructive font-mono">{selectedPacket.errorFlags}</p>
                                                    </div>
                                                </div>
                                            </>
                                        )}

                                    </div>
                                        </TabsContent>

                                        <TabsContent value="raw" className="mt-4">
                                            <div className="bg-muted p-3 rounded-md">
                                                <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                                                    {selectedPacket.rawData}
                                                </pre>
                                            </div>
                                        </TabsContent>

                                        <TabsContent value="decoded" className="mt-4 space-y-4">
                                            {/* Decoded Header */}
                                            <div>
                                                <h3 className="font-semibold mb-2">Header</h3>
                                                <div className="bg-muted p-3 rounded-md">
                                                    <pre className="text-xs font-mono whitespace-pre-wrap">
                                                        {selectedPacket.decodedHeader}
                                                    </pre>
                                                </div>
                                            </div>

                                            {/* Decoded Payload */}
                                            <div>
                                                <h3 className="font-semibold mb-2">Payload</h3>
                                                <div className="bg-muted p-3 rounded-md">
                                                    <pre className="text-xs font-mono whitespace-pre-wrap">
                                                        {selectedPacket.decodedPayload}
                                                    </pre>
                                                </div>
                                            </div>

                                            {/* Decrypted Payload - Show if decrypted by backend */}
                                            {selectedPacket.decryptedPayload && (
                                                <>
                                                    <Separator />
                                                    <div>
                                                        <h3 className="font-semibold mb-2 flex items-center gap-2">
                                                            <Unlock className="h-4 w-4" />
                                                            Decrypted Payload
                                                        </h3>
                                                        <div className="bg-muted p-3 rounded-md">
                                                            <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                                                                {selectedPacket.decryptedPayload}
                                                            </pre>
                                                        </div>
                                                    </div>
                                                </>
                                            )}
                                        </TabsContent>
                                    </Tabs>
                                </CardContent>
                            </Card>
                        ) : (
                            <Card className="sticky top-4">
                                <CardContent className="p-12 text-center">
                                    <p className="text-muted-foreground">
                                        Select a packet to view details
                                    </p>
                                </CardContent>
                            </Card>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
