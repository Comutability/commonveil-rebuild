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
import ResourcesIndex from "@/pages/site/Resources";
import Releases from "@/pages/site/Releases";
import Privacy from "@/pages/site/Privacy";
import Security from "@/pages/site/Security";
import ReportSecurityIssue from "@/pages/site/ReportSecurityIssue";
import Search from "@/pages/site/Search";
import { HelpArticle, HelpGuide, HelpIndex } from "@/pages/site/Help";
import NotFound from "@/pages/site/NotFound";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import ForgotPassword from "@/pages/ForgotPassword";
import ResetPassword from "@/pages/ResetPassword";
import InviteLanding from "@/pages/site/InviteLanding";
import PublicProfile from "@/pages/site/PublicProfile";
import AppRoot from "@/pages/app/AppRoot";
import AppHome from "@/pages/app/Home";
import ServerView from "@/pages/app/ServerView";
import ServerSettings from "@/pages/app/ServerSettings";
import Discover from "@/pages/app/Discover";
import JoinInvite from "@/pages/app/JoinInvite";
import UserSettings from "@/pages/app/UserSettings";
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
        <Route path="resources" element={<ResourcesIndex />} />
        <Route path="releases" element={<Releases />} />
        {/* Guides, learning paths, the wiki and the blog were removed in 0.15.0. */}
        {["blog", "blog/:slug", "guides", "guides/:slug", "paths", "paths/:slug", "wiki", "wiki/:slug", "saved"].map((p) => (
          <Route key={p} path={p} element={<Navigate to="/help" replace />} />
        ))}
        <Route path="help" element={<HelpIndex />} />
        <Route path="help/guide" element={<HelpGuide />} />
        <Route path="help/:slug" element={<HelpArticle />} />
        <Route path="privacy" element={<Privacy />} />
        <Route path="security" element={<Security />} />
        <Route path="security/report" element={<ReportSecurityIssue />} />
        <Route path="search" element={<Search />} />
        <Route path="invite/:code" element={<InviteLanding />} />
        <Route path="u/:username" element={<PublicProfile />} />
        <Route path="*" element={<NotFound />} />
      </Route>
      <Route path="login" element={<Login />} />
      <Route path="register" element={<Register />} />
      <Route path="forgot-password" element={<ForgotPassword />} />
      <Route path="reset-password" element={<ResetPassword />} />
      <Route element={<ProtectedRoute unauthenticatedElement={<RedirectToLogin />} />}>
        <Route path="app" element={<AppRoot />}>
          <Route index element={<AppHome />} />
          <Route path="c/:conversationId" element={<AppHome />} />
          <Route path="s/:serverId" element={<ServerView />} />
          <Route path="s/:serverId/settings" element={<ServerSettings />} />
          <Route path="s/:serverId/settings/channel/:channelId" element={<ServerSettings />} />
          <Route path="s/:serverId/settings/:section" element={<ServerSettings />} />
          <Route path="s/:serverId/:channelId" element={<ServerView />} />
          <Route path="s/:serverId/:channelId/:threadId" element={<ServerView />} />
          <Route path="discover" element={<Discover />} />
          <Route path="join/:code" element={<JoinInvite />} />
          <Route path="settings" element={<UserSettings />} />
          <Route path="settings/:section" element={<UserSettings />} />
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
