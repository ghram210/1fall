import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "@/contexts/AuthContext";
import ProtectedRoute from "@/components/ProtectedRoute";
import Login from "./pages/Login.tsx";
import AcceptInvite from "./pages/AcceptInvite.tsx";
import Index from "./pages/Index.tsx";
import Vulnerabilities from "./pages/Vulnerabilities.tsx";
import ScanResults from "./pages/ScanResults.tsx";
import NewScan from "./pages/NewScan.tsx";
import VulnDashboard from "./pages/VulnDashboard.tsx";
import Settings from "./pages/Settings.tsx";
import AdminPanel from "./pages/AdminPanel.tsx";
import NotFound from "./pages/NotFound.tsx";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/invite/:token" element={<AcceptInvite />} />
            <Route path="/" element={<ProtectedRoute><Index /></ProtectedRoute>} />
            <Route path="/vulnerabilities" element={<ProtectedRoute><Vulnerabilities /></ProtectedRoute>} />
            <Route path="/vuln-dashboard" element={<ProtectedRoute><VulnDashboard /></ProtectedRoute>} />
            <Route path="/new-scan" element={<ProtectedRoute adminOnly><NewScan /></ProtectedRoute>} />
            <Route path="/scan-results" element={<ProtectedRoute><ScanResults /></ProtectedRoute>} />
            <Route path="/settings" element={<ProtectedRoute adminOnly><Settings /></ProtectedRoute>} />
            <Route path="/admin" element={<ProtectedRoute adminOnly><AdminPanel /></ProtectedRoute>} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
