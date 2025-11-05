import { useState, useEffect } from 'react';
import { PacketTable } from './organisms/PacketTable';
import { getPackets, clearPackets as clearPacketsApi, getSettings, updateSettings } from '@/api';
import type { PacketInfoDto } from '@/api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { RefreshCw, Pause, Play, Trash2, Loader2, ChevronLeft, ChevronRight, X, Lock, Unlock, Settings, Key, Save } from 'lucide-react';
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

    // Decrypt state
    const [sessionKey, setSessionKey] = useState('');
    const [decryptedData, setDecryptedData] = useState<string | null>(null);
    const [decryptError, setDecryptError] = useState<string | null>(null);
    const [isDecrypting, setIsDecrypting] = useState(false);

    // Stored key for auto-decrypt
    const [storedKey, setStoredKey] = useState<string>(() => {
        return localStorage.getItem('mita_encryption_key') || '';
    });
    const [showKeySettings, setShowKeySettings] = useState(false);

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

    // Auto-decrypt when packet is selected and stored key exists
    useEffect(() => {
        if (selectedPacket && selectedPacket.encrypted && storedKey && storedKey.length === 32) {
            // Clear previous decrypt state first
            setDecryptError(null);
            setDecryptedData(null);
            // Trigger auto-decrypt
            decryptPayload(storedKey);
        } else {
            // Clear decrypt state if packet is not encrypted or no key
            setDecryptError(null);
            setDecryptedData(null);
        }
    }, [selectedPacket?.id, storedKey]);

    const formatDate = (timestamp: number | undefined) => {
        if (!timestamp) return 'N/A';
        return new Date(timestamp).toLocaleString();
    };

    // Decrypt functions
    const hexToBytes = (hex: string): Uint8Array => {
        const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
        const bytes = new Uint8Array(cleanHex.length / 2);
        for (let i = 0; i < cleanHex.length; i += 2) {
            bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
        }
        return bytes;
    };

    const saveStoredKey = (key: string) => {
        const cleanKey = key.replace(/[^0-9a-fA-F]/g, '');
        if (cleanKey.length === 32 || cleanKey.length === 0) {
            setStoredKey(cleanKey);
            localStorage.setItem('mita_encryption_key', cleanKey);
            toast({
                title: cleanKey ? "Key Saved" : "Key Cleared",
                description: cleanKey ? "Encryption key saved. Encrypted packets will auto-decrypt." : "Encryption key cleared.",
            });
        } else {
            toast({
                title: "Invalid Key",
                description: "Key must be 32 hex characters (16 bytes)",
                variant: "destructive",
            });
        }
    };

    const decryptPayload = async (keyToUse?: string) => {
        if (!selectedPacket) return;

        setIsDecrypting(true);
        setDecryptError(null);
        setDecryptedData(null);

        try {
            const key = keyToUse || sessionKey;
            // Ensure key is a string
            const keyStr = typeof key === 'string' ? key : String(key);
            const cleanKey = keyStr.replace(/[^0-9a-fA-F]/g, '');
            if (cleanKey.length !== 32) {
                throw new Error('Session key must be 32 hex characters (16 bytes)');
            }

            const rawBytes = hexToBytes(selectedPacket.rawData || '');

            if (rawBytes.length <= 16) {
                throw new Error('Packet too short - no payload to decrypt');
            }

            const payloadBytes = rawBytes.slice(16);

            if (payloadBytes.length < 16) {
                throw new Error('Encrypted payload too short - missing IV');
            }

            const iv = payloadBytes.slice(0, 16);
            const ciphertext = payloadBytes.slice(16);

            const keyBytes = hexToBytes(cleanKey);
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes as BufferSource,
                { name: 'AES-CBC' },
                false,
                ['decrypt']
            );

            const decryptedBytes = await crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: iv },
                cryptoKey,
                ciphertext
            );

            const decoder = new TextDecoder('utf-8');
            let result = decoder.decode(decryptedBytes);

            const printableChars = result.split('').filter(c => {
                const code = c.charCodeAt(0);
                return code >= 32 && code <= 126 || code === 10 || code === 13;
            }).length;

            if (printableChars / result.length < 0.7) {
                const hexString = Array.from(new Uint8Array(decryptedBytes))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(' ');
                result = `[Binary Data - Hex]\n${hexString}`;
            }

            setDecryptedData(result);
        } catch (err) {
            setDecryptError(err instanceof Error ? err.message : 'Decryption failed');
        } finally {
            setIsDecrypting(false);
        }
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
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setShowKeySettings(!showKeySettings)}
                            >
                                <Settings className="h-4 w-4 mr-2" />
                                Settings
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

            {/* Encryption Key Settings */}
            {showKeySettings && (
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Key className="h-5 w-5" />
                            Auto-Decrypt Settings
                        </CardTitle>
                        <CardDescription>
                            Save an encryption key to automatically decrypt encrypted packets
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-4">
                            <div className="space-y-2">
                                <Label htmlFor="stored-key">
                                    AES-128 Encryption Key (32 hex characters)
                                </Label>
                                <div className="flex gap-2">
                                    <Input
                                        id="stored-key"
                                        type="text"
                                        value={storedKey}
                                        onChange={(e) => setStoredKey(e.target.value)}
                                        placeholder="e.g., 0123456789abcdef0123456789abcdef"
                                        className="font-mono"
                                    />
                                    <Button
                                        onClick={() => saveStoredKey(storedKey)}
                                        size="sm"
                                    >
                                        <Save className="h-4 w-4 mr-2" />
                                        Save
                                    </Button>
                                    {storedKey && (
                                        <Button
                                            onClick={() => {
                                                setStoredKey('');
                                                saveStoredKey('');
                                            }}
                                            variant="outline"
                                            size="sm"
                                        >
                                            Clear
                                        </Button>
                                    )}
                                </div>
                                <p className="text-xs text-muted-foreground">
                                    When a key is saved, encrypted packets will automatically decrypt when selected.
                                    The key is stored locally in your browser.
                                </p>
                            </div>

                            {localStorage.getItem('mita_encryption_key') && (
                                <div className="bg-muted p-3 rounded-md">
                                    <div className="flex items-center gap-2 text-sm">
                                        <Lock className="h-4 w-4 text-green-500" />
                                        <span className="font-medium">Auto-decrypt enabled</span>
                                    </div>
                                    <p className="text-xs text-muted-foreground mt-1">
                                        Encrypted packets will automatically decrypt when selected
                                    </p>
                                </div>
                            )}
                        </div>
                    </CardContent>
                </Card>
            )}

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
                                        onClick={() => {
                                            setSelectedPacket(null);
                                            setDecryptedData(null);
                                            setDecryptError(null);
                                            setSessionKey('');
                                        }}
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
                                            <h3 className="font-semibold mb-2">Packet Information</h3>
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
                                                    <span className="text-muted-foreground">Size:</span>
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

                                            {/* Decrypt Section - Only show if encrypted */}
                                            {selectedPacket.encrypted && (
                                                <>
                                                    <Separator />
                                                    <div>
                                                        <h3 className="font-semibold mb-2 flex items-center gap-2">
                                                            <Unlock className="h-4 w-4" />
                                                            Decrypt Payload
                                                        </h3>
                                                        <div className="space-y-3">
                                                            <div className="space-y-2">
                                                                <Label htmlFor="session-key" className="text-xs">
                                                                    Session Key (32 hex chars)
                                                                </Label>
                                                                <Input
                                                                    id="session-key"
                                                                    type="text"
                                                                    value={sessionKey}
                                                                    onChange={(e) => setSessionKey(e.target.value)}
                                                                    placeholder="0123456789abcdef..."
                                                                    className="font-mono text-xs"
                                                                />
                                                            </div>

                                                            <Button
                                                                onClick={() => decryptPayload()}
                                                                disabled={isDecrypting || !sessionKey}
                                                                size="sm"
                                                                className="w-full"
                                                            >
                                                                <Unlock className="h-3 w-3 mr-2" />
                                                                {isDecrypting ? 'Decrypting...' : 'Decrypt'}
                                                            </Button>

                                                            {decryptError && (
                                                                <div className="bg-destructive/10 border border-destructive rounded-md p-2">
                                                                    <p className="text-xs text-destructive">
                                                                        {decryptError}
                                                                    </p>
                                                                </div>
                                                            )}

                                                            {decryptedData && (
                                                                <div>
                                                                    <h3 className="font-semibold mb-2">Decrypted Payload</h3>
                                                                    <div className="bg-muted p-3 rounded-md overflow-x-auto">
                                                                        <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                                                                            {decryptedData}
                                                                        </pre>
                                                                    </div>
                                                                </div>
                                                            )}

                                                            <div className="bg-muted/50 p-2 rounded-md">
                                                                <p className="text-xs text-muted-foreground">
                                                                    Format: [16-byte IV] + [AES-128-CBC Encrypted Data]
                                                                </p>
                                                            </div>
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
