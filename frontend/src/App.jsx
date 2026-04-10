import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import Layout from "./components/Layout/Layout";
import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";
import PhishingModule from "./pages/PhishingModule";
import RansomwareModule from "./pages/RansomwareModule";
import Logs from "./pages/Logs";
import Login from "./pages/Login";
import Reports from "./pages/Reports";
import AutomatedTesting from "./pages/AutomatedTesting";
import Docs from "./pages/Docs";
import Pricing from "./pages/Pricing";
import Blog from "./pages/Blog";
import ConnectionTest from "./components/ConnectionTest";
import { DashboardProvider } from "./context/DashboardContext";
import { AuthProvider, useAuth } from "./context/AuthContext";
import ProtectedRoute from "./components/Auth/ProtectedRoute";

const ProtectedLayout = () => {
  return (
    <ProtectedRoute>
      <Layout />
    </ProtectedRoute>
  );
};

function AppRoutes() {
  const { isAuthenticated } = useAuth();

  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/" element={<Landing />} />
      <Route
        path="/login"
        element={
          isAuthenticated ? <Navigate to="/dashboard" replace /> : <Login />
        }
      />
      <Route path="/docs" element={<Docs />} />
      <Route path="/pricing" element={<Pricing />} />
      <Route path="/blog" element={<Blog />} />

      {/* Test Routes */}
      <Route path="/test" element={<ConnectionTest />} />
      <Route path="/testing" element={<AutomatedTesting />} />

      {/* Protected Routes */}
      <Route path="/dashboard" element={<ProtectedLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="phishing" element={<PhishingModule />} />
        <Route path="ransomware" element={<RansomwareModule />} />
        <Route path="logs" element={<Logs />} />
        <Route path="reports" element={<Reports />} />
      </Route>

      {/* Catch all */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function App() {
  return (
    <AuthProvider>
      <DashboardProvider>
        <Router>
          <AppRoutes />
        </Router>
      </DashboardProvider>
    </AuthProvider>
  );
}

export default App;
