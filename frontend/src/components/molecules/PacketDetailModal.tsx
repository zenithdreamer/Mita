import { useState } from 'react';

interface Packet {
    id: string;
    timestamp: number;
    direction: string;
    sourceAddr: string;
    destAddr: string;
    messageType: string;
    payloadSize: number;
    transport: string;
    encrypted: boolean;
    rawData: string;
    decodedHeader: string;
    decodedPayload: string;
}

interface PacketDetailModalProps {
    packet: Packet;
    onClose: () => void;
    formatDate: (timestamp: number) => string;
}

export function PacketDetailModal({ packet, onClose, formatDate }: PacketDetailModalProps) {
    const [sessionKey, setSessionKey] = useState('');
    const [decryptedData, setDecryptedData] = useState<string | null>(null);
    const [decryptError, setDecryptError] = useState<string | null>(null);
    const [isDecrypting, setIsDecrypting] = useState(false);

    const handleBackdropClick = (e: React.MouseEvent) => {
        if (e.target === e.currentTarget) {
            onClose();
        }
    };

    // Convert hex string to Uint8Array
    const hexToBytes = (hex: string): Uint8Array => {
        const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
        const bytes = new Uint8Array(cleanHex.length / 2);
        for (let i = 0; i < cleanHex.length; i += 2) {
            bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
        }
        return bytes;
    };

    // AES-128-CBC decryption using Web Crypto API
    const decryptPayload = async () => {
        setIsDecrypting(true);
        setDecryptError(null);
        setDecryptedData(null);

        try {
            // Validate session key (should be 32 hex characters = 16 bytes)
            const cleanKey = sessionKey.replace(/[^0-9a-fA-F]/g, '');
            if (cleanKey.length !== 32) {
                throw new Error('Session key must be 32 hex characters (16 bytes)');
            }

            // Parse raw data
            const rawBytes = hexToBytes(packet.rawData);
            
            // Extract payload from packet (skip 16-byte header)
            if (rawBytes.length <= 16) {
                throw new Error('Packet too short - no payload to decrypt');
            }

            const payloadBytes = rawBytes.slice(16);
            
            // Extract IV (first 16 bytes of payload for AES-CBC)
            if (payloadBytes.length < 16) {
                throw new Error('Encrypted payload too short - missing IV');
            }

            const iv = payloadBytes.slice(0, 16);
            const ciphertext = payloadBytes.slice(16);

            // Import key
            const keyBytes = hexToBytes(cleanKey);
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes as BufferSource,
                { name: 'AES-CBC' },
                false,
                ['decrypt']
            );

            // Decrypt
            const decryptedBytes = await crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: iv },
                cryptoKey,
                ciphertext
            );

            // Convert to string (assuming UTF-8 text, or show hex if not)
            const decoder = new TextDecoder('utf-8');
            let result = decoder.decode(decryptedBytes);
            
            // If result contains mostly non-printable characters, show as hex
            const printableChars = result.split('').filter(c => {
                const code = c.charCodeAt(0);
                return code >= 32 && code <= 126 || code === 10 || code === 13;
            }).length;
            
            if (printableChars / result.length < 0.7) {
                // Mostly non-printable, show as hex
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
        <div
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
            onClick={handleBackdropClick}
        >
            <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
                {/* Header */}
                <div className="bg-gray-800 text-white px-6 py-4 flex justify-between items-center">
                    <div>
                        <h2 className="text-xl font-bold">Packet Details</h2>
                        <p className="text-sm text-gray-300 mt-1">ID: {packet.id}</p>
                    </div>
                    <button
                        onClick={onClose}
                        className="text-gray-300 hover:text-white text-2xl leading-none"
                    >
                        ×
                    </button>
                </div>

                {/* Content */}
                <div className="overflow-y-auto max-h-[calc(90vh-80px)]">
                    <div className="p-6 space-y-6">
                        {/* Summary */}
                        <div className="grid grid-cols-2 gap-4">
                            <div className="bg-gray-50 p-4 rounded-lg">
                                <h3 className="text-sm font-semibold text-gray-600 uppercase mb-2">
                                    Timestamp
                                </h3>
                                <p className="text-lg text-gray-900">{formatDate(packet.timestamp)}</p>
                            </div>
                            <div className="bg-gray-50 p-4 rounded-lg">
                                <h3 className="text-sm font-semibold text-gray-600 uppercase mb-2">
                                    Direction
                                </h3>
                                <p className="text-lg text-gray-900 capitalize">{packet.direction}</p>
                            </div>
                            <div className="bg-gray-50 p-4 rounded-lg">
                                <h3 className="text-sm font-semibold text-gray-600 uppercase mb-2">
                                    Message Type
                                </h3>
                                <p className="text-lg text-gray-900">{packet.messageType}</p>
                            </div>
                            <div className="bg-gray-50 p-4 rounded-lg">
                                <h3 className="text-sm font-semibold text-gray-600 uppercase mb-2">
                                    Transport
                                </h3>
                                <p className="text-lg text-gray-900 uppercase">{packet.transport}</p>
                            </div>
                            <div className="bg-gray-50 p-4 rounded-lg">
                                <h3 className="text-sm font-semibold text-gray-600 uppercase mb-2">
                                    Source Address
                                </h3>
                                <p className="text-lg text-gray-900 font-mono">{packet.sourceAddr}</p>
                            </div>
                            <div className="bg-gray-50 p-4 rounded-lg">
                                <h3 className="text-sm font-semibold text-gray-600 uppercase mb-2">
                                    Destination Address
                                </h3>
                                <p className="text-lg text-gray-900 font-mono">{packet.destAddr}</p>
                            </div>
                            <div className="bg-gray-50 p-4 rounded-lg">
                                <h3 className="text-sm font-semibold text-gray-600 uppercase mb-2">
                                    Payload Size
                                </h3>
                                <p className="text-lg text-gray-900">{packet.payloadSize} bytes</p>
                            </div>
                            <div className="bg-gray-50 p-4 rounded-lg">
                                <h3 className="text-sm font-semibold text-gray-600 uppercase mb-2">
                                    Encrypted
                                </h3>
                                <p className="text-lg text-gray-900">{packet.encrypted ? '🔒 Yes' : 'No'}</p>
                            </div>
                        </div>

                        {/* Raw Data */}
                        <div>
                            <h3 className="text-lg font-bold text-gray-800 mb-3">Raw Packet Data</h3>
                            <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                                <pre className="whitespace-pre-wrap break-all">{packet.rawData}</pre>
                            </div>
                        </div>

                        {/* Decoded Header */}
                        <div>
                            <h3 className="text-lg font-bold text-gray-800 mb-3">Decoded Header</h3>
                            <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg">
                                <pre className="whitespace-pre-wrap text-sm text-gray-800 font-mono">
                                    {packet.decodedHeader}
                                </pre>
                            </div>
                        </div>

                        {/* Decoded Payload */}
                        <div>
                            <h3 className="text-lg font-bold text-gray-800 mb-3">Decoded Payload</h3>
                            <div className="bg-purple-50 border border-purple-200 p-4 rounded-lg">
                                <pre className="whitespace-pre-wrap text-sm text-gray-800 font-mono">
                                    {packet.decodedPayload}
                                </pre>
                            </div>
                        </div>

                        {/* Decryption Section */}
                        {packet.encrypted && (
                            <div className="border-t pt-6">
                                <h3 className="text-lg font-bold text-gray-800 mb-3 flex items-center gap-2">
                                    🔓 Decrypt Payload
                                </h3>
                                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 space-y-4">
                                    <div>
                                        <label className="block text-sm font-semibold text-gray-700 mb-2">
                                            Session Key (32 hex characters / 16 bytes)
                                        </label>
                                        <input
                                            type="text"
                                            value={sessionKey}
                                            onChange={(e) => setSessionKey(e.target.value)}
                                            placeholder="e.g., 0123456789abcdef0123456789abcdef"
                                            className="w-full px-4 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                        />
                                        <p className="text-xs text-gray-600 mt-1">
                                            Enter the 16-byte AES-128 session key in hexadecimal format
                                        </p>
                                    </div>

                                    <button
                                        onClick={decryptPayload}
                                        disabled={isDecrypting || !sessionKey}
                                        className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
                                    >
                                        {isDecrypting ? (
                                            <>🔄 Decrypting...</>
                                        ) : (
                                            <>🔓 Decrypt Payload</>
                                        )}
                                    </button>

                                    {decryptError && (
                                        <div className="bg-red-50 border border-red-300 text-red-800 px-4 py-3 rounded-lg">
                                            <strong>Error:</strong> {decryptError}
                                        </div>
                                    )}

                                    {decryptedData && (
                                        <div>
                                            <div className="flex justify-between items-center mb-2">
                                                <h4 className="text-sm font-semibold text-gray-700">
                                                    Decrypted Data
                                                </h4>
                                                <button
                                                    onClick={() => copyToClipboard(decryptedData)}
                                                    className="text-xs px-3 py-1 bg-gray-200 hover:bg-gray-300 rounded text-gray-700 transition-colors"
                                                >
                                                    📋 Copy
                                                </button>
                                            </div>
                                            <div className="bg-green-50 border border-green-300 p-4 rounded-lg max-h-64 overflow-y-auto">
                                                <pre className="whitespace-pre-wrap text-sm text-gray-800 font-mono">
                                                    {decryptedData}
                                                </pre>
                                            </div>
                                        </div>
                                    )}

                                    <div className="bg-blue-50 border border-blue-200 p-3 rounded-lg text-xs text-gray-700">
                                        <strong>ℹ️ Note:</strong> Decryption uses AES-128-CBC. The encrypted payload format is:
                                        <code className="block mt-1 font-mono bg-white px-2 py-1 rounded">
                                            [16-byte IV] + [Encrypted Data]
                                        </code>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Footer */}
                <div className="bg-gray-50 px-6 py-4 border-t flex justify-end">
                    <button
                        onClick={onClose}
                        className="px-6 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg font-medium transition-colors"
                    >
                        Close
                    </button>
                </div>
            </div>
        </div>
    );
}
