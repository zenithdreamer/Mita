import { useState, useEffect, useRef } from "react"
import { Wifi, Bluetooth, Radio, Loader2 } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/hooks/use-toast"
import { getSettings, updateSettings } from "@/api/sdk.gen"
import type { SettingsDto } from "@/api/types.gen"

interface ProtocolConfigProps {
  name: string
  icon: React.ReactNode
  enabled: boolean
  description: string
  channel?: string
  frequency?: string
  power?: string
  onToggle: (enabled: boolean) => void
  isLoading?: boolean
}

function ProtocolConfig({ name, icon, enabled, description, channel, frequency, power, onToggle, isLoading }: ProtocolConfigProps) {
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
            {isLoading ? (
              <Badge variant="outline" className="gap-1">
                <Loader2 className="h-3 w-3 animate-spin" />
                {enabled ? "Disabling..." : "Enabling..."}
              </Badge>
            ) : (
              <Badge variant={enabled ? "default" : "secondary"}>
                {enabled ? "Enabled" : "Disabled"}
              </Badge>
            )}
            <Switch
              checked={enabled}
              onCheckedChange={onToggle}
              disabled={isLoading}
            />
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

interface Settings {
  wifiEnabled: boolean
  bleEnabled: boolean
  zigbeeEnabled: boolean
}

interface LoadingStates {
  wifi: boolean
  ble: boolean
  zigbee: boolean
}

export function ProtocolsPage() {
  const { toast } = useToast()
  const [settings, setSettings] = useState<Settings>({
    wifiEnabled: false,
    bleEnabled: false,
    zigbeeEnabled: false,
  })
  const [loadingStates, setLoadingStates] = useState<LoadingStates>({
    wifi: false,
    ble: false,
    zigbee: false,
  })
  // Store current capture setting to preserve it when updating transports
  const currentCaptureEnabled = useRef(false)

  // Fetch settings on mount
  useEffect(() => {
    fetchSettings()
  }, [])

  const fetchSettings = async () => {
    try {
      const { data, error } = await getSettings()
      if (error) {
        throw new Error("Failed to fetch settings")
      }
      if (data) {
        setSettings({
          wifiEnabled: data.wifiEnabled ?? false,
          bleEnabled: data.bleEnabled ?? false,
          zigbeeEnabled: data.zigbeeEnabled ?? false,
        })
        // Store monitor setting to preserve it when updating transports
        currentCaptureEnabled.current = data.monitorEnabled ?? false
      }
    } catch (error) {
      console.error("Failed to fetch settings:", error)
      toast({
        title: "Error",
        description: "Failed to load transport settings",
        variant: "destructive",
      })
    }
  }

  const updateTransportSettings = async (newSettings: Settings, transportType: keyof LoadingStates) => {
    setLoadingStates(prev => ({ ...prev, [transportType]: true }))
    try {
      const requestBody: SettingsDto = {
        wifiEnabled: newSettings.wifiEnabled,
        bleEnabled: newSettings.bleEnabled,
        zigbeeEnabled: newSettings.zigbeeEnabled,
        monitorEnabled: currentCaptureEnabled.current, // Preserve monitor setting
      }

      const { data, error } = await updateSettings({
        body: requestBody,
      })

      if (error) {
        throw new Error("Failed to update settings")
      }

      if (data) {
        setSettings({
          wifiEnabled: data.wifiEnabled ?? false,
          bleEnabled: data.bleEnabled ?? false,
          zigbeeEnabled: data.zigbeeEnabled ?? false,
        })
        toast({
          title: "Settings Updated",
          description: "Transport settings have been applied successfully and are now active.",
        })
      }
    } catch (error) {
      console.error("Failed to update settings:", error)
      toast({
        title: "Error",
        description: "Failed to update transport settings",
        variant: "destructive",
      })
      // Revert to previous settings
      fetchSettings()
    } finally {
      setLoadingStates(prev => ({ ...prev, [transportType]: false }))
    }
  }

  const handleWifiToggle = (enabled: boolean) => {
    updateTransportSettings({ ...settings, wifiEnabled: enabled }, "wifi")
  }

  const handleBleToggle = (enabled: boolean) => {
    updateTransportSettings({ ...settings, bleEnabled: enabled }, "ble")
  }

  const handleZigbeeToggle = (enabled: boolean) => {
    updateTransportSettings({ ...settings, zigbeeEnabled: enabled }, "zigbee")
  }

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
            enabled={settings.wifiEnabled}
            description="High-speed wireless networking"
            channel="Auto (1-11)"
            frequency="2.4GHz / 5GHz"
            power="20 dBm"
            onToggle={handleWifiToggle}
            isLoading={loadingStates.wifi}
          />
          <ProtocolConfig
            name="Bluetooth Low Energy"
            icon={<Bluetooth className="h-5 w-5 text-primary" />}
            enabled={settings.bleEnabled}
            description="Low power wireless communication"
            channel="37-39"
            frequency="2.4GHz"
            power="4 dBm"
            onToggle={handleBleToggle}
            isLoading={loadingStates.ble}
          />
        </TabsContent>

        <TabsContent value="others" className="space-y-4">
          <ProtocolConfig
            name="Zigbee 3.0"
            icon={<Radio className="h-5 w-5 text-primary" />}
            enabled={settings.zigbeeEnabled}
            description="Low-power mesh networking"
            channel="15"
            frequency="2.4GHz"
            power="8 dBm"
            onToggle={handleZigbeeToggle}
            isLoading={loadingStates.zigbee}
          />
        </TabsContent>
      </Tabs>
    </div>
  )
}
