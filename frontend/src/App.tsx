import { RouterStatus } from './components/RouterStatus'
import { RoutingTablePage } from './components/RoutingTablePage'

const routingData = [
  { id: '1', name: 'Route A', status: 'active' },
  { id: '2', name: 'Route B', status: 'inactive' },
  { id: '3', name: 'Route C', status: 'active' },
];

function App() {
  return <>
          <RouterStatus />
          <RoutingTablePage data={routingData} />
        </>
}

export default App
