import { useEffect, useState } from "react"
import {
  Activity,
  Network,
  TrendingUp,
  Cpu,
  HardDrive,
  Clock,
} from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { getStatus, getDeviceStatus, getSystemStatus, getNetworkStatus, getProtocols } from "@/api"
import type { StatusDto, DashboardStatsDto, SystemResourcesDto, NetworkStatsDto, ProtocolListDto } from "@/api"

interface StatCardProps {
  title: string
  value: string
  description: string
  icon: React.ReactNode
  trend?: string
}

function StatCard({ title, value, description, icon, trend }: StatCardProps) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        <p className="text-xs text-muted-foreground">{description}</p>
        {trend && (
          <div className="flex items-center mt-2 text-xs text-green-600 dark:text-green-400">
            <TrendingUp className="h-3 w-3 mr-1" />
            {trend}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

interface ProtocolCardProps {
  name: string
  status: "active" | "inactive" | "error"
  devices: number
  description: string
}

function ProtocolCard({ name, status, devices, description }: ProtocolCardProps) {
  const statusColors = {
    active: "bg-green-500",
    inactive: "bg-gray-500",
    error: "bg-red-500",
  }

  const statusLabels = {
    active: "Active",
    inactive: "Inactive",
    error: "Error",
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">{name}</CardTitle>
          <Badge
            variant={status === "active" ? "default" : "secondary"}
            className={status === "active" ? "" : ""}
          >
            <div className={`w-2 h-2 rounded-full ${statusColors[status]} mr-2`} />
            {statusLabels[status]}
          </Badge>
        </div>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Connected Devices</span>
          <span className="text-2xl font-bold">{devices}</span>
        </div>
      </CardContent>
    </Card>
  )
}

export function DashboardPage() {
  const [status, setStatus] = useState<StatusDto | null>(null)
  const [deviceStatus, setDeviceStatus] = useState<DashboardStatsDto | null>(null)
  const [systemStatus, setSystemStatus] = useState<SystemResourcesDto | null>(null)
  const [networkStatus, setNetworkStatus] = useState<NetworkStatsDto | null>(null)
  const [protocols, setProtocols] = useState<ProtocolListDto['protocols']>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await getStatus()
        if (response.data) {
          setStatus(response.data)
        }
      } catch (error) {
        console.error("Failed to fetch router status:", error)
      } finally {
        setLoading(false)
      }
    }

    const fetchDeviceStatus = async () => {
      try {
        const { data } = await getDeviceStatus()
        setDeviceStatus(data || null)
      } catch (error) {
        console.error("Failed to fetch device status:", error)
      }
    }

    const fetchSystemStatus = async () => {
      try {
        const { data } = await getSystemStatus()
        setSystemStatus(data || null)
      } catch (error) {
        console.error("Failed to fetch system status:", error)
      }
    }

    const fetchNetworkStatus = async () => {
      try {
        const { data } = await getNetworkStatus()
        setNetworkStatus(data || null)
      } catch (error) {
        console.error("Failed to fetch network status:", error)
      }
    }

    const fetchProtocols = async () => {
      try {
        const { data } = await getProtocols()
        setProtocols(data?.protocols || [])
      } catch (error) {
        console.error("Failed to fetch protocols:", error)
      }
    }

    fetchStatus()
    fetchDeviceStatus()
    fetchSystemStatus()
    fetchNetworkStatus()
    fetchProtocols()
    const interval = setInterval(() => {
      fetchStatus()
      fetchDeviceStatus()
      fetchSystemStatus()
      fetchNetworkStatus()
      fetchProtocols()
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)

    if (days > 0) return `${days}d ${hours}h ${minutes}m`
    if (hours > 0) return `${hours}h ${minutes}m`
    return `${minutes}m`
  }

  const formatSpeed = (speedMBps: number) => {
    // Convert MB/s to bytes/s for accurate calculation
    const bytesPerSec = speedMBps * 1024 * 1024

    if (bytesPerSec >= 1073741824) {
      // >= 1 GB/s
      return `${(bytesPerSec / 1073741824).toFixed(2)} GB/s`
    } else if (bytesPerSec >= 1048576) {
      // >= 1 MB/s
      return `${(bytesPerSec / 1048576).toFixed(2)} MB/s`
    } else if (bytesPerSec >= 1024) {
      // >= 1 KB/s
      return `${(bytesPerSec / 1024).toFixed(2)} KB/s`
    } else {
      // < 1 KB/s
      return `${bytesPerSec.toFixed(0)} B/s`
    }
  }

  const formatBytes = (bytes: number) => {
    if (bytes >= 1099511627776) {
      // >= 1 TB
      return `${(bytes / 1099511627776).toFixed(2)} TB`
    } else if (bytes >= 1073741824) {
      // >= 1 GB
      return `${(bytes / 1073741824).toFixed(2)} GB`
    } else if (bytes >= 1048576) {
      // >= 1 MB
      return `${(bytes / 1048576).toFixed(2)} MB`
    } else if (bytes >= 1024) {
      // >= 1 KB
      return `${(bytes / 1024).toFixed(2)} KB`
    } else {
      return `${bytes} B`
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">Loading dashboard...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your IoT multi-protocol router
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Router Status"
          value={status?.status === "running" ? "Online" : "Offline"}
          description={status?.message ? status.message : "No status message"}
          icon={<Activity className="h-4 w-4 text-muted-foreground" />}
        />
        <StatCard
          title="Uptime"
          value={status?.uptime ? formatUptime(status.uptime) : "0m"}
          description="Since last restart"
          icon={<Clock className="h-4 w-4 text-muted-foreground" />}
        />
        <StatCard
          title="Active Connections"
          value={deviceStatus?.connectedDevices !== undefined ? deviceStatus.connectedDevices.toString() : "..."}
          description="Connected devices"
          icon={<Network className="h-4 w-4 text-muted-foreground" />}
        />
        <StatCard
          title="Data Throughput"
          value={networkStatus?.uploadSpeed !== undefined && networkStatus?.downloadSpeed !== undefined
            ? formatSpeed(networkStatus.uploadSpeed + networkStatus.downloadSpeed)
            : "..."}
          description="Current transfer rate"
          icon={<TrendingUp className="h-4 w-4 text-muted-foreground" />}
        />
      </div>

      {/* System Resources */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <Cpu className="mr-2 h-5 w-5" />
              System Resources
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">CPU Usage</span>
                <span className="text-sm text-muted-foreground">
                  {systemStatus?.cpuUsage !== undefined ? `${systemStatus.cpuUsage.toFixed(1)}%` : "..."}
                </span>
              </div>
              <div className="w-full bg-secondary rounded-full h-2">
                <div 
                  className="bg-primary h-2 rounded-full" 
                  style={{ width: systemStatus?.cpuUsage !== undefined ? `${systemStatus.cpuUsage.toFixed(0)}%` : '0%' }} 
                />
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Memory Usage</span>
                <span className="text-sm text-muted-foreground">
                  {systemStatus?.memoryUsed !== undefined && systemStatus?.memoryTotal !== undefined
                    ? `${formatBytes(systemStatus.memoryUsed)} / ${formatBytes(systemStatus.memoryTotal)}`
                    : "..."}
                </span>
              </div>
              <div className="w-full bg-secondary rounded-full h-2">
                <div 
                  className="bg-primary h-2 rounded-full" 
                  style={{ 
                    width: systemStatus?.memoryUsed !== undefined && systemStatus?.memoryTotal !== undefined
                      ? `${((systemStatus.memoryUsed / systemStatus.memoryTotal) * 100).toFixed(0)}%`
                      : "0%"
                  }} 
                />
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Storage</span>
                <span className="text-sm text-muted-foreground">
                  {systemStatus?.storageUsed !== undefined && systemStatus?.storageTotal !== undefined
                    ? `${formatBytes(systemStatus.storageUsed)} / ${formatBytes(systemStatus.storageTotal)}`
                    : "..."}
                </span>
              </div>
              <div className="w-full bg-secondary rounded-full h-2">
                <div 
                  className="bg-primary h-2 rounded-full" 
                  style={{ 
                    width: systemStatus?.storageUsed !== undefined && systemStatus?.storageTotal !== undefined
                      ? `${((systemStatus.storageUsed / systemStatus.storageTotal) * 100).toFixed(0)}%`
                      : "0%"
                  }} 
                />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <HardDrive className="mr-2 h-5 w-5" />
              Network Statistics
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">Total Packets</span>
              <span className="text-lg font-semibold">
                {networkStatus?.totalPackets !== undefined ? networkStatus.totalPackets.toLocaleString() : "..."}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">Packets/sec</span>
              <span className="text-lg font-semibold">
                {networkStatus?.packetsPerSecond !== undefined ? networkStatus.packetsPerSecond.toLocaleString() : "..."}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">Upload</span>
              <span className="text-lg font-semibold">
                {networkStatus?.uploadSpeed !== undefined ? formatSpeed(networkStatus.uploadSpeed) : "..."}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">Download</span>
              <span className="text-lg font-semibold">
                {networkStatus?.downloadSpeed !== undefined ? formatSpeed(networkStatus.downloadSpeed) : "..."}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Protocol Support Cards */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight mb-4">Protocol Status</h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {protocols && protocols.length > 0 ? (
            protocols.map((protocol, index) => (
              <ProtocolCard
                key={index}
                name={protocol.name || ''}
                status={protocol.status as "active" | "inactive" | "error" || 'inactive'}
                devices={protocol.connectedDevices || 0}
                description={protocol.description || ''}
              />
            ))
          ) : (
            <>
              <ProtocolCard
                name="WiFi (802.11ax)"
                status="active"
                devices={12}
                description="2.4GHz & 5GHz dual-band wireless"
              />
              <ProtocolCard
                name="Bluetooth LE"
                status="active"
                devices={8}
                description="Low energy Bluetooth 5.3"
              />
              <ProtocolCard
                name="Zigbee 3.0"
                status="active"
                devices={3}
                description="Low-power mesh networking"
              />
            </>
          )}
        </div>
      </div>
    </div>
  )
}
