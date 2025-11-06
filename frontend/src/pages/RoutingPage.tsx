import { RoutingTablePage } from "@/pages/RoutingTablePage"

const mockRoutingData = [
  {
    device_id: "1",
    device_type: "WiFi",
    status: "active",
    assigned_address: "192.168.1.1",
    last_seen: new Date().toISOString(),
  },
  {
    device_id: "2",
    device_type: "BLE",
    status: "active",
    assigned_address: "192.168.1.2",
    last_seen: new Date().toISOString(),
  },
  {
    device_id: "3",
    device_type: "Zigbee",
    status: "inactive",
    assigned_address: "192.168.1.3",
    last_seen: new Date(Date.now() - 3600000).toISOString(),
  },
]

export function RoutingPage() {
  return <RoutingTablePage data={mockRoutingData} />
}
