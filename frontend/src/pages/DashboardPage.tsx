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
import { getStatus } from "@/api"
import type { StatusDto } from "@/api"

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

    fetchStatus()
    const interval = setInterval(fetchStatus, 5000)
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
          value={status?.running ? "Online" : "Offline"}
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
          value="24"
          description="Connected devices"
          icon={<Network className="h-4 w-4 text-muted-foreground" />}
          trend="+12% from last hour"
        />
        <StatCard
          title="Data Throughput"
          value="45.2 MB/s"
          description="Current transfer rate"
          icon={<TrendingUp className="h-4 w-4 text-muted-foreground" />}
          trend="+8% from average"
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
                <span className="text-sm text-muted-foreground">34%</span>
              </div>
              <div className="w-full bg-secondary rounded-full h-2">
                <div className="bg-primary h-2 rounded-full" style={{ width: "34%" }} />
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Memory Usage</span>
                <span className="text-sm text-muted-foreground">2.4 GB / 4 GB</span>
              </div>
              <div className="w-full bg-secondary rounded-full h-2">
                <div className="bg-primary h-2 rounded-full" style={{ width: "60%" }} />
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Storage</span>
                <span className="text-sm text-muted-foreground">12.8 GB / 32 GB</span>
              </div>
              <div className="w-full bg-secondary rounded-full h-2">
                <div className="bg-primary h-2 rounded-full" style={{ width: "40%" }} />
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
              <span className="text-lg font-semibold">1,234,567</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">Packets/sec</span>
              <span className="text-lg font-semibold">8,945</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">Upload</span>
              <span className="text-lg font-semibold">12.4 MB/s</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">Download</span>
              <span className="text-lg font-semibold">32.8 MB/s</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Protocol Support Cards */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight mb-4">Protocol Status</h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
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
        </div>
      </div>
    </div>
  )
}
