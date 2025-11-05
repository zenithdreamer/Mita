import { useState } from 'react';
import type { PacketInfoDto } from '@/api';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Copy, Lock, Unlock } from 'lucide-react';

interface PacketDetailModalProps {
    packet: PacketInfoDto;
    onClose: () => void;
    formatDate: (timestamp: number | undefined) => string;
}

export function PacketDetailModal({ packet, onClose, formatDate }: PacketDetailModalProps) {
    const [sessionKey, setSessionKey] = useState('');
    const [decryptedData, setDecryptedData] = useState<string | null>(null);
    const [decryptError, setDecryptError] = useState<string | null>(null);
    const [isDecrypting, setIsDecrypting] = useState(false);

    const hexToBytes = (hex: string): Uint8Array => {
        const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
        const bytes = new Uint8Array(cleanHex.length / 2);
        for (let i = 0; i < cleanHex.length; i += 2) {
            bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
        }
        return bytes;
    };

    const decryptPayload = async () => {
        setIsDecrypting(true);
        setDecryptError(null);
        setDecryptedData(null);

        try {
            const cleanKey = sessionKey.replace(/[^0-9a-fA-F]/g, '');
            if (cleanKey.length !== 32) {
                throw new Error('Session key must be 32 hex characters (16 bytes)');
            }

            const rawBytes = hexToBytes(packet.rawData || '');

            if (rawBytes.length <= 16) {
                throw new Error('Packet too short - no payload to decrypt');
            }

            const payloadBytes = rawBytes.slice(16);

            if (payloadBytes.length < 16) {
                throw new Error('Encrypted payload too short - missing IV');
            }

            // AES-GCM format: IV (12 bytes) || Ciphertext || Tag (16 bytes)
            // Minimum: 12 (IV) + 16 (tag) = 28 bytes
            if (payloadBytes.length < 28) {
                throw new Error('Encrypted payload too short for GCM decryption');
            }
            
            const iv = payloadBytes.slice(0, 12);  // 12-byte IV for GCM
            const ciphertextWithTag = payloadBytes.slice(12);  // Ciphertext + tag (16 bytes at end)
            
            // Derive encryption key from session key using HMAC-SHA256
            // encryption_key = HMAC-SHA256(session_key, "ENC")
            const sessionKeyBytes = hexToBytes(cleanKey);
            
            const sessionCryptoKey = await crypto.subtle.importKey(
                'raw',
                sessionKeyBytes as BufferSource,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            
            const encInfo = new TextEncoder().encode('ENC');
            const encKeyFull = await crypto.subtle.sign('HMAC', sessionCryptoKey, encInfo);
            const encKeyBytes = new Uint8Array(encKeyFull).slice(0, 16); // First 16 bytes for AES-128
            
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                encKeyBytes as BufferSource,
                { name: 'AES-GCM', length: 128 },
                false,
                ['decrypt']
            );

            const decryptedBytes = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv, tagLength: 128 },  // 128-bit tag = 16 bytes
                cryptoKey,
                ciphertextWithTag
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

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    return (
        <Dialog open={true} onOpenChange={onClose}>
            <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                    <DialogTitle>Packet Details</DialogTitle>
                    <DialogDescription>
                        ID: {packet.id} • {formatDate(packet.timestamp)}
                    </DialogDescription>
                </DialogHeader>

                <Tabs defaultValue="summary" className="mt-4">
                    <TabsList className="grid w-full grid-cols-3">
                        <TabsTrigger value="summary">Summary</TabsTrigger>
                        <TabsTrigger value="data">Raw Data</TabsTrigger>
                        {packet.encrypted && <TabsTrigger value="decrypt">Decrypt</TabsTrigger>}
                    </TabsList>

                    <TabsContent value="summary" className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                            <Card>
                                <CardHeader className="pb-3">
                                    <CardTitle className="text-sm font-medium">Direction</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <Badge>{packet.direction || 'unknown'}</Badge>
                                </CardContent>
                            </Card>

                            <Card>
                                <CardHeader className="pb-3">
                                    <CardTitle className="text-sm font-medium">Message Type</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <Badge variant="outline">{packet.messageType || 'N/A'}</Badge>
                                </CardContent>
                            </Card>

                            <Card>
                                <CardHeader className="pb-3">
                                    <CardTitle className="text-sm font-medium">Transport</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-sm uppercase">{packet.transport || 'N/A'}</p>
                                </CardContent>
                            </Card>

                            <Card>
                                <CardHeader className="pb-3">
                                    <CardTitle className="text-sm font-medium">Payload Size</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-sm">{packet.payloadSize || 0} bytes</p>
                                </CardContent>
                            </Card>

                            <Card>
                                <CardHeader className="pb-3">
                                    <CardTitle className="text-sm font-medium">Source Address</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-sm font-mono">{packet.sourceAddr || 'N/A'}</p>
                                </CardContent>
                            </Card>

                            <Card>
                                <CardHeader className="pb-3">
                                    <CardTitle className="text-sm font-medium">Destination Address</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-sm font-mono">{packet.destAddr || 'N/A'}</p>
                                </CardContent>
                            </Card>
                        </div>

                        {packet.encrypted && (
                            <Card>
                                <CardContent className="pt-6 flex items-center gap-2">
                                    <Lock className="h-4 w-4" />
                                    <span className="text-sm font-medium">This packet is encrypted</span>
                                </CardContent>
                            </Card>
                        )}
                    </TabsContent>

                    <TabsContent value="data" className="space-y-4">
                        <Card>
                            <CardHeader>
                                <div className="flex items-center justify-between">
                                    <CardTitle>Raw Packet Data</CardTitle>
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => copyToClipboard(packet.rawData || '')}
                                    >
                                        <Copy className="h-3 w-3 mr-2" />
                                        Copy
                                    </Button>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <pre className="bg-muted p-4 rounded-lg overflow-x-auto font-mono text-xs">
                                    {packet.rawData || 'No data'}
                                </pre>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle>Decoded Header</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <pre className="bg-muted p-4 rounded-lg overflow-x-auto font-mono text-xs">
                                    {packet.decodedHeader || 'No header data'}
                                </pre>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle>Decoded Payload</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <pre className="bg-muted p-4 rounded-lg overflow-x-auto font-mono text-xs">
                                    {packet.decodedPayload || 'No payload data'}
                                </pre>
                            </CardContent>
                        </Card>
                    </TabsContent>

                    {packet.encrypted && (
                        <TabsContent value="decrypt" className="space-y-4">
                            <Card>
                                <CardHeader>
                                    <CardTitle className="flex items-center gap-2">
                                        <Unlock className="h-5 w-5" />
                                        Decrypt Payload
                                    </CardTitle>
                                    <CardDescription>
                                        Enter the AES-128 session key to decrypt this packet
                                    </CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="session-key">
                                            Session Key (32 hex characters / 16 bytes)
                                        </Label>
                                        <Input
                                            id="session-key"
                                            type="text"
                                            value={sessionKey}
                                            onChange={(e) => setSessionKey(e.target.value)}
                                            placeholder="e.g., 0123456789abcdef0123456789abcdef"
                                            className="font-mono"
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            Enter the 16-byte AES-128 session key in hexadecimal format
                                        </p>
                                    </div>

                                    <Button
                                        onClick={decryptPayload}
                                        disabled={isDecrypting || !sessionKey}
                                        className="w-full"
                                    >
                                        {isDecrypting ? 'Decrypting...' : 'Decrypt Payload'}
                                    </Button>

                                    {decryptError && (
                                        <Card className="border-destructive">
                                            <CardContent className="pt-6">
                                                <p className="text-sm text-destructive">
                                                    <strong>Error:</strong> {decryptError}
                                                </p>
                                            </CardContent>
                                        </Card>
                                    )}

                                    {decryptedData && (
                                        <Card>
                                            <CardHeader>
                                                <div className="flex items-center justify-between">
                                                    <CardTitle>Decrypted Data</CardTitle>
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        onClick={() => copyToClipboard(decryptedData)}
                                                    >
                                                        <Copy className="h-3 w-3 mr-2" />
                                                        Copy
                                                    </Button>
                                                </div>
                                            </CardHeader>
                                            <CardContent>
                                                <pre className="bg-muted p-4 rounded-lg overflow-x-auto font-mono text-xs max-h-64">
                                                    {decryptedData}
                                                </pre>
                                            </CardContent>
                                        </Card>
                                    )}

                                    <Card className="bg-muted/50">
                                        <CardContent className="pt-6">
                                            <p className="text-xs text-muted-foreground">
                                                <strong>Note:</strong> Decryption uses AES-128-CBC. The encrypted payload format is:
                                            </p>
                                            <code className="block mt-2 bg-background p-2 rounded text-xs font-mono">
                                                [16-byte IV] + [Encrypted Data]
                                            </code>
                                        </CardContent>
                                    </Card>
                                </CardContent>
                            </Card>
                        </TabsContent>
                    )}
                </Tabs>
            </DialogContent>
        </Dialog>
    );
}
