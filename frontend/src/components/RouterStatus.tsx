import { useEffect, useState } from 'react';
import { getStatus } from '../api';
import type { StatusDto } from '../api';

const POLL_INTERVAL_MS = 5000; // Poll every 5 seconds

function formatUptime(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m ${secs}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  } else {
    return `${secs}s`;
  }
}

export function RouterStatus() {
  const [status, setStatus] = useState<StatusDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        // Fully type-safe API call using generated SDK!
        const startTime = performance.now();
        console.log('Fetching status...');

        const response = await getStatus();

        const endTime = performance.now();
        console.log(`Status fetch took ${(endTime - startTime).toFixed(2)}ms`);

        if (response.data) {
          setStatus(response.data);
          setError(null);
          setLastUpdate(new Date());
        } else if (response.error) {
          setError(`API Error: ${JSON.stringify(response.error)}`);
        }
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to connect to router';
        setError(errorMessage);
      }
    };

    // Initial fetch
    fetchStatus();

    // Set up polling interval
    const interval = setInterval(fetchStatus, POLL_INTERVAL_MS);

    // Cleanup on unmount
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold text-gray-800 text-center mb-8">
          Mita Router Dashboard
        </h1>

        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            {/* Status Card */}
            <div className="bg-gray-50 rounded-lg p-4">
              <div className="text-sm text-gray-600 mb-2">Status</div>
              <div>
                {error ? (
                  <span className="inline-block px-3 py-1 text-sm font-semibold text-white bg-red-500 rounded">
                    ERROR
                  </span>
                ) : status ? (
                  <span
                    className={`inline-block px-3 py-1 text-sm font-semibold text-white rounded ${
                      status.status === 'running' ? 'bg-green-500' : 'bg-red-500'
                    }`}
                  >
                    {status.status?.toUpperCase() ?? 'UNKNOWN'}
                  </span>
                ) : (
                  <span className="inline-block px-3 py-1 text-sm font-semibold text-white bg-gray-400 rounded">
                    LOADING...
                  </span>
                )}
              </div>
            </div>

            {/* Uptime Card */}
            <div className="bg-gray-50 rounded-lg p-4">
              <div className="text-sm text-gray-600 mb-2">Uptime</div>
              <div className="text-xl font-bold text-gray-800">
                {status?.uptime !== undefined ? formatUptime(status.uptime) : '--'}
              </div>
            </div>

            {/* Last Update Card */}
            <div className="bg-gray-50 rounded-lg p-4">
              <div className="text-sm text-gray-600 mb-2">Last Update</div>
              <div className="text-xl font-bold text-gray-800">
                {lastUpdate.toLocaleTimeString()}
              </div>
            </div>
          </div>

          {/* Message Card */}
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="text-sm text-gray-600 mb-2">Message</div>
            <div className="text-gray-800">
              {error ? error : status?.message ?? '--'}
            </div>
          </div>
        </div>

        {/* Auto-refresh indicator */}
        <div className="text-center text-sm text-gray-600">
          Auto-refreshing every {POLL_INTERVAL_MS / 1000} seconds
        </div>

      </div>
    </div>
  );
}
