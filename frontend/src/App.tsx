import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import { ThemeProvider } from "@/components/ThemeProvider"
import { AuthProvider } from "@/contexts/AuthContext"
import { ProtectedRoute } from "@/components/ProtectedRoute"
import { DashboardLayout } from "@/components/DashboardLayout"
import { LoginPage } from "@/pages/LoginPage"
import { DashboardPage } from "@/pages/DashboardPage"
import { RoutingPage } from "@/pages/RoutingPage"
import { PacketsPage } from "@/pages/PacketsPage"
import { ProtocolsPage } from "@/pages/ProtocolsPage"
import { SettingsPage } from "@/pages/SettingsPage"

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="mita-router-theme">
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <DashboardLayout />
                </ProtectedRoute>
              }
            >
              <Route index element={<DashboardPage />} />
              <Route path="routing" element={<RoutingPage />} />
              <Route path="packets" element={<PacketsPage />} />
              <Route path="protocols" element={<ProtocolsPage />} />
              <Route path="settings" element={<SettingsPage />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  )
}

export default App
