import React from "react";
import { Toaster } from "@/components/ui/toaster";
import { QueryClientProvider } from "@tanstack/react-query";
import { queryClientInstance } from "@/lib/query-client";
import { BrowserRouter as Router, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/AuthContext";
import UserNotRegisteredError from "@/components/UserNotRegisteredError";
import ScrollToTop from "@/components/ScrollToTop";
import ProtectedRoute from "@/components/ProtectedRoute";
import SiteLayout from "@/components/site/SiteLayout";
import { FullScreenLoading } from "@/components/site/bits";
import Home from "@/pages/site/Home";
import {
  BlogArticle,
  BlogIndex,
  GuideArticle,
  GuidesIndex,
  PathDetail,
  PathsIndex,
  ResourcesIndex,
  WikiArticle,
  WikiIndex,
} from "@/pages/site/ContentPages";
import Privacy from "@/pages/site/Privacy";
import Security from "@/pages/site/Security";
import ReportSecurityIssue from "@/pages/site/ReportSecurityIssue";
import NotFound from "@/pages/site/NotFound";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import ForgotPassword from "@/pages/ForgotPassword";
import ResetPassword from "@/pages/ResetPassword";
import AppRoot from "@/pages/app/AppRoot";
import Messages from "@/pages/app/Messages";
import Settings from "@/pages/app/Settings";
import Admin from "@/pages/app/Admin";

function RedirectToLogin() {
  const location = useLocation();
  return <Navigate to={`/login?returnTo=${encodeURIComponent(location.pathname + location.search)}`} replace />;
}

function AppRoutes() {
  const { isLoadingAuth, isLoadingPublicSettings, authError } = useAuth();
  if (isLoadingPublicSettings || isLoadingAuth) return <FullScreenLoading />;
  if (authError?.type === "user_not_registered") return <UserNotRegisteredError />;

  return (
    <Routes>
      <Route element={<SiteLayout />}>
        <Route index element={<Home />} />
        <Route path="blog" element={<BlogIndex />} />
        <Route path="blog/:slug" element={<BlogArticle />} />
        <Route path="guides" element={<GuidesIndex />} />
        <Route path="guides/:slug" element={<GuideArticle />} />
        <Route path="paths" element={<PathsIndex />} />
        <Route path="paths/:slug" element={<PathDetail />} />
        <Route path="resources" element={<ResourcesIndex />} />
        <Route path="wiki" element={<WikiIndex />} />
        <Route path="wiki/:slug" element={<WikiArticle />} />
        <Route path="privacy" element={<Privacy />} />
        <Route path="security" element={<Security />} />
        <Route path="security/report" element={<ReportSecurityIssue />} />
        <Route path="*" element={<NotFound />} />
      </Route>
      <Route path="login" element={<Login />} />
      <Route path="register" element={<Register />} />
      <Route path="forgot-password" element={<ForgotPassword />} />
      <Route path="reset-password" element={<ResetPassword />} />
      <Route element={<ProtectedRoute unauthenticatedElement={<RedirectToLogin />} />}>
        <Route path="app" element={<AppRoot />}>
          <Route index element={<Messages />} />
          <Route path="c/:conversationId" element={<Messages />} />
          <Route path="settings" element={<Settings />} />
        </Route>
        <Route path="admin" element={<Admin />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <QueryClientProvider client={queryClientInstance}>
        <Router>
          <ScrollToTop />
          <AppRoutes />
        </Router>
        <Toaster />
      </QueryClientProvider>
    </AuthProvider>
  );
}
