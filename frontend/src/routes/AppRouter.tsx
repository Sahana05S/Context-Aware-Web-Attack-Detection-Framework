import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Layout } from "../components/layout/Layout";
import { Dashboard } from "../pages/Dashboard";
import { Alerts } from "../pages/Alerts";
import { IPDetailPage } from "../pages/IPDetail";
import { Upload } from "../pages/Upload";
import { Live } from "../pages/Live";
import { Landing } from "../pages/Landing";
import { Login } from "../pages/Login";
import { Signup } from "../pages/Signup";
import { AIAnalysis } from "../pages/AIAnalysis";
import { AuthGuard } from "../components/AuthGuard";

export function AppRouter() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Signup />} />
        
        <Route element={<AuthGuard />}>
          <Route element={<Layout />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/ips/:ip" element={<IPDetailPage />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/live" element={<Live />} />
            <Route path="/ai" element={<AIAnalysis />} />
          </Route>
        </Route>
        
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
