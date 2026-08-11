import { createBrowserRouter, Navigate } from "react-router-dom"
import { ProtectedRoute } from "@/routes/ProtectedRoute"
import { PublicRoute } from "@/routes/PublicRoute"
import { AppLayout } from "@/layouts/AppLayout"
import { LoginPage } from "@/pages/LoginPage"
import { SetupPage } from "@/pages/SetupPage"
import { DashboardPage } from "@/pages/DashboardPage"
import { UsersPage } from "@/pages/UsersPage"
import { RolesPage } from "@/pages/RolesPage"
import { SecretsPage } from "@/pages/SecretsPage"

export const router = createBrowserRouter([
  { path: "/", element: <Navigate to="/dashboard" replace /> },
  {
    element: <PublicRoute />,
    children: [
      { path: "/login", element: <LoginPage /> },
      { path: "/setup", element: <SetupPage /> },
    ],
  },
  {
    element: <ProtectedRoute />,
    children: [
      {
        element: <AppLayout />,
        children: [
          { path: "/dashboard", element: <DashboardPage /> },
          { path: "/users", element: <UsersPage /> },
          { path: "/roles", element: <RolesPage /> },
          { path: "/secrets", element: <SecretsPage /> },
        ],
      },
    ],
  },
  // No dedicated 404 for this MVP's two-route surface — an unknown path
  // resolves the same way "/" does.
  { path: "*", element: <Navigate to="/dashboard" replace /> },
])
