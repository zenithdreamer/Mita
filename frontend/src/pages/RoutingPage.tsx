import { RoutingTablePage } from "@/components/RoutingTablePage"

const mockRoutingData = [
  {
    id: "1",
    name: "Device-001",
    type: "WiFi",
    status: "active",
    lastseen: new Date().toISOString(),
  },
  {
    id: "2",
    name: "BLE-Sensor-01",
    type: "BLE",
    status: "active",
    lastseen: new Date().toISOString(),
  },
  {
    id: "3",
    name: "Zigbee-Light-05",
    type: "Zigbee",
    status: "inactive",
    lastseen: new Date(Date.now() - 3600000).toISOString(),
  },
]

export function RoutingPage() {
  return <RoutingTablePage data={mockRoutingData} />
}
