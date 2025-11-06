import { DeviceTablePage } from "@/pages/DeviceTablePage"
import { useEffect, useState } from "react"
import { getWifiDevices, getBleDevices } from "@/api"
import type { DeviceDto } from "@/api/types.gen"

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
    last_seen: device.last_seen 
      ? new Date(device.last_seen * 1000).toISOString() 
      : "Never",
    rssi: device.rssi || 0,
    battery_level: device.battery_level || 0,
  }))

  return <DeviceTablePage data={transformedData} />
}
