import { DeviceTablePage } from "@/pages/DeviceTablePage"

const mockDeviceData = [
  {
    device_id: "1",
    device_type: "WiFi",
    status: "active",
    last_seen: new Date().toISOString(),
    rssi: 1,
    battery_level: 50,
  },
  {
    device_id: "2",
    device_type: "BLE",
    status: "active",
    last_seen: new Date().toISOString(),
    rssi: 4,
    battery_level: 44,
  },
  {
    device_id: "3",
    device_type: "Zigbee",
    status: "inactive",
    last_seen: new Date(Date.now() - 3600000).toISOString(),
    rssi: 2,
    battery_level: 30,
  },
]

export function DevicePage() {
  return <DeviceTablePage data={mockDeviceData} />
}
