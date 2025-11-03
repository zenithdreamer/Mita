import { useState } from 'react'
import { RouterStatus } from './components/RouterStatus'
import { RoutingTablePage } from './components/RoutingTablePage'
import { PacketMonitorPage } from './components/PacketMonitorPage'

const routingData = [
  { id: '1', name: 'Route A', type: 'wifi', status: 'active', lastseen: '12345' },
  { id: '2', name: 'Route B', type: 'wifi', status: 'inactive', lastseen: '2462235' },
  { id: '3', name: 'Route C', type: 'ble', status: 'active', lastseen: '7325321' },
];

type Page = 'routing' | 'packets';

function App() {
  const [currentPage, setCurrentPage] = useState<Page>('routing');

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 py-3">
          <div className="flex gap-4">
            <button
              onClick={() => setCurrentPage('routing')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                currentPage === 'routing'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              🌐 Routing Table
            </button>
            <button
              onClick={() => setCurrentPage('packets')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                currentPage === 'packets'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              📡 Packet Monitor
            </button>
          </div>
        </div>
      </nav>

      {/* Router Status - shown on all pages */}
      <RouterStatus />

      {/* Page Content */}
      {currentPage === 'routing' ? (
        <RoutingTablePage 
          data={routingData} 
          onNavigateToPackets={() => setCurrentPage('packets')}
        />
      ) : (
        <PacketMonitorPage />
      )}
    </div>
  );
}

export default App
