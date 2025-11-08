import { DeviceTablePage } from "@/pages/DeviceTablePage"
import { useEffect, useState } from "react"
import { getWifiDevices, getBleDevices } from "@/api"
import type { DeviceDto } from "@/api/types.gen"

function formatLastSeen(timestamp: number | undefined): string {
  if (!timestamp) return "Never";
  
  const now = Math.floor(Date.now() / 1000);
  const secondsAgo = now - timestamp;
  
  if (secondsAgo < 5) return "Just now";
  if (secondsAgo < 60) return `${secondsAgo}s ago`;
  if (secondsAgo < 3600) {
    const minutes = Math.floor(secondsAgo / 60);
    return `${minutes}m ago`;
  }
  if (secondsAgo < 86400) {
    const hours = Math.floor(secondsAgo / 3600);
    return `${hours}h ago`;
  }
  const days = Math.floor(secondsAgo / 86400);
  return `${days}d ago`;
}

export function DevicePage() {
  const [devices, setDevices] = useState<DeviceDto[]>([])

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        const [wifiResponse, bleResponse] = await Promise.all([
          getWifiDevices(),
          getBleDevices()
        ])

        const allDevices = [
          ...(wifiResponse.data?.devices || []),
          ...(bleResponse.data?.devices || [])
        ]

        setDevices(allDevices)
      } catch (err) {
        console.error("Error fetching devices:", err)
      }
    }

    fetchDevices()
    
    const interval = setInterval(fetchDevices, 5000)
    return () => clearInterval(interval)
  }, [])

  const transformedData = devices.map(device => ({
    device_id: device.device_id || "unknown",
    device_type: device.device_type || "unknown",
    status: device.status || "unknown",
    last_seen: formatLastSeen(device.last_seen),
    rssi: device.rssi || 0,
    battery_level: device.battery_level || 0,
    address: device.address,
    transport: device.transport,
    connection_duration: device.connection_duration,
  }))

  return <DeviceTablePage data={transformedData} />
}
