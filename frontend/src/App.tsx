import { RouterStatus } from './components/RouterStatus'
import { RoutingTablePage } from './components/RoutingTablePage'

const routingData = [
  { id: '1', name: 'Route A', type: 'wifi', status: 'active', lastseen: '12345' },
  { id: '2', name: 'Route B', type: 'wifi', status: 'inactive', lastseen: '2462235' },
  { id: '3', name: 'Route C', type: 'ble', status: 'active', lastseen: '7325321' },
];

function App() {
  return <>
          <RouterStatus />
          <RoutingTablePage data={routingData} />
        </>
}

export default App
