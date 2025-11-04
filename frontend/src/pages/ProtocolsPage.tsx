import { Wifi, Bluetooth, Radio, Network, Settings2 } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

interface ProtocolConfigProps {
  name: string
  icon: React.ReactNode
  status: boolean
  description: string
  channel?: string
  frequency?: string
  power?: string
}

function ProtocolConfig({ name, icon, status, description, channel, frequency, power }: ProtocolConfigProps) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="bg-primary/10 p-2 rounded-lg">
              {icon}
            </div>
            <div>
              <CardTitle className="text-lg">{name}</CardTitle>
              <CardDescription>{description}</CardDescription>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Badge variant={status ? "default" : "secondary"}>
              {status ? "Enabled" : "Disabled"}
            </Badge>
            <Switch checked={status} />
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-3 gap-4 text-sm">
          {channel && (
            <div>
              <Label className="text-muted-foreground">Channel</Label>
              <p className="font-medium mt-1">{channel}</p>
            </div>
          )}
          {frequency && (
            <div>
              <Label className="text-muted-foreground">Frequency</Label>
              <p className="font-medium mt-1">{frequency}</p>
            </div>
          )}
          {power && (
            <div>
              <Label className="text-muted-foreground">TX Power</Label>
              <p className="font-medium mt-1">{power}</p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export function ProtocolsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Protocol Management</h1>
        <p className="text-muted-foreground">
          Configure and manage IoT communication protocols
        </p>
      </div>

      <Tabs defaultValue="wireless" className="space-y-4">
        <TabsList>
          <TabsTrigger value="wireless">Wireless</TabsTrigger>
          <TabsTrigger value="others">Others</TabsTrigger>
        </TabsList>

        <TabsContent value="wireless" className="space-y-4">
          <ProtocolConfig
            name="WiFi 6 (802.11ax)"
            icon={<Wifi className="h-5 w-5 text-primary" />}
            status={true}
            description="High-speed wireless networking"
            channel="Auto (1-11)"
            frequency="2.4GHz / 5GHz"
            power="20 dBm"
          />
          <ProtocolConfig
            name="Bluetooth Low Energy"
            icon={<Bluetooth className="h-5 w-5 text-primary" />}
            status={true}
            description="Low power wireless communication"
            channel="37-39"
            frequency="2.4GHz"
            power="4 dBm"
          />
        </TabsContent>

        <TabsContent value="others" className="space-y-4">
          <ProtocolConfig
            name="Zigbee 3.0"
            icon={<Radio className="h-5 w-5 text-primary" />}
            status={true}
            description="Low-power mesh networking"
            channel="15"
            frequency="2.4GHz"
            power="8 dBm"
          />
        </TabsContent>
      </Tabs>

      <Card>
        <CardHeader>
          <CardTitle>Protocol Statistics</CardTitle>
          <CardDescription>Overall protocol performance metrics</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 bg-secondary rounded-lg">
              <div className="text-2xl font-bold">98.5%</div>
              <div className="text-xs text-muted-foreground mt-1">WiFi Uptime</div>
            </div>
            <div className="text-center p-4 bg-secondary rounded-lg">
              <div className="text-2xl font-bold">45ms</div>
              <div className="text-xs text-muted-foreground mt-1">Avg Latency</div>
            </div>
            <div className="text-center p-4 bg-secondary rounded-lg">
              <div className="text-2xl font-bold">12</div>
              <div className="text-xs text-muted-foreground mt-1">Active Protocols</div>
            </div>
            <div className="text-center p-4 bg-secondary rounded-lg">
              <div className="text-2xl font-bold">99.2%</div>
              <div className="text-xs text-muted-foreground mt-1">Packet Success</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
