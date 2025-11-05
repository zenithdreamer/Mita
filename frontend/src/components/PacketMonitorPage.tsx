import { useState, useEffect } from 'react';
import { PacketTable } from './organisms/PacketTable';
import { PacketDetailModal } from './molecules/PacketDetailModal';
import { getPackets, clearPackets as clearPacketsApi, getSettings, updateSettings } from '@/api';
import type { PacketInfoDto } from '@/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { RefreshCw, Pause, Play, Trash2, Loader2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export function PacketMonitorPage() {
    const { toast } = useToast();
    const [packets, setPackets] = useState<PacketInfoDto[]>([]);
    const [selectedPacket, setSelectedPacket] = useState<PacketInfoDto | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [monitorEnabled, setMonitorEnabled] = useState(false);
    const [isMonitorLoading, setIsMonitorLoading] = useState(false);

    const fetchPackets = async () => {
        try {
            const response = await getPackets({
                query: {
                    limit: 100,
                    offset: 0
                }
            });

            if (response.data) {
                setPackets(response.data.packets || []);
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
    }, [autoRefresh]);

    const formatDate = (timestamp: number | undefined) => {
        if (!timestamp) return 'N/A';
        return new Date(timestamp).toLocaleString();
    };

    return (
        <div className="space-y-6">
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
                            <Badge variant="secondary">{packets.length}</Badge>
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
                <PacketTable
                    packets={packets}
                    onPacketClick={setSelectedPacket}
                    formatDate={formatDate}
                />
            )}

            {selectedPacket && (
                <PacketDetailModal
                    packet={selectedPacket}
                    onClose={() => setSelectedPacket(null)}
                    formatDate={formatDate}
                />
            )}
        </div>
    );
}
