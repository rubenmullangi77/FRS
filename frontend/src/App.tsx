import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './layouts/Sidebar';
import { Header } from './layouts/Header';
import { DashboardPage } from './pages/DashboardPage';
import { EvidencePage } from './pages/EvidencePage';
import { RecoveryPage } from './pages/RecoveryPage';
import { CarvingPage } from './pages/CarvingPage';
import { FileEraserPage } from './pages/FileEraserPage';
import { DriveSanitizationPage } from './pages/DriveSanitizationPage';
import { ReportsPage } from './pages/ReportsPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { DiagnosticsPage } from './pages/DiagnosticsPage';
import { SettingsPage } from './pages/SettingsPage';
import { LoginPage } from './pages/LoginPage';
import { api } from './services/api';
import { authService, AuthSession } from './services/auth';
import { themeService } from './services/theme';
import { BackendStatus, CaseMetadata, NavigationTab } from './types';

export const App: React.FC = () => {
  const [session, setSession] = useState<AuthSession>(authService.getSession());
  const [activeTab, setActiveTab] = useState<NavigationTab>('dashboard');
  const [backendStatus, setBackendStatus] = useState<BackendStatus | null>(null);
  const [activeCase, setActiveCase] = useState<CaseMetadata | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [, setTheme] = useState(themeService.getTheme());

  // Subscribe to central auth and theme changes
  useEffect(() => {
    const unsubAuth = authService.subscribe((sess) => {
      setSession(sess);
      if (!sess.isAuthenticated) {
        setActiveTab('dashboard');
      }
    });
    const unsubTheme = themeService.subscribe((t) => setTheme(t));
    return () => {
      unsubAuth();
      unsubTheme();
    };
  }, []);

  const fetchBackendStatus = useCallback(async () => {
    setIsLoading(true);
    try {
      const status = await api.getStatus();
      setBackendStatus(status);
    } catch {
      setBackendStatus(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchBackendStatus();
    const interval = setInterval(fetchBackendStatus, 10000);
    return () => clearInterval(interval);
  }, [fetchBackendStatus]);

  // Do not auto-select sample cases; activeCase stays null until the examiner selects or creates one
  useEffect(() => {
    // If activeCase is set, we can validate it against listCases
    if (session.isAuthenticated && activeCase) {
      api.listCases()
        .then((res) => {
          const exists = res.cases?.some(c => c.case_id === activeCase.case_id);
          if (!exists) {
            setActiveCase(null);
          }
        })
        .catch(() => {});
    }
  }, [session.isAuthenticated, activeCase]);

  const getPageTitle = (tab: NavigationTab): string => {
    switch (tab) {
      case 'dashboard':
        return 'Dashboard';
      case 'evidence':
        return 'Evidence Files';
      case 'recovery':
        return 'Recover Deleted Files';
      case 'carving':
        return 'File Recovery from Raw Data';
      case 'file_eraser':
        return 'Secure File Deletion';
      case 'drive_sanitization':
        return 'Secure Drive Eraser';
      case 'reports':
        return 'Forensic Reports';
      case 'audit_logs':
        return 'Activity & Audit Log';
      case 'diagnostics':
        return 'System Status';
      case 'settings':
        return 'System Settings';
      default:
        return 'Forensic Workstation';
    }
  };

  // If user is not authenticated, strictly render the Login Page
  if (!session.isAuthenticated) {
    return <LoginPage onLoginSuccess={() => setActiveTab('dashboard')} />;
  }

  const renderActivePage = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <DashboardPage
            backendStatus={backendStatus}
            activeCase={activeCase}
            onNavigate={setActiveTab}
          />
        );
      case 'evidence':
        return (
          <EvidencePage
            activeCase={activeCase}
            onSelectCase={setActiveCase}
          />
        );
      case 'recovery':
        return <RecoveryPage activeCase={activeCase} />;
      case 'carving':
        return <CarvingPage activeCase={activeCase} />;
      case 'file_eraser':
        return <FileEraserPage />;
      case 'drive_sanitization':
        return <DriveSanitizationPage />;
      case 'reports':
        return <ReportsPage activeCase={activeCase} onSelectCase={setActiveCase} />;
      case 'audit_logs':
        return <AuditLogsPage activeCase={activeCase} />;
      case 'diagnostics':
        return (
          <DiagnosticsPage
            backendStatus={backendStatus}
            onRefresh={fetchBackendStatus}
            isLoading={isLoading}
          />
        );
      case 'settings':
        return (
          <SettingsPage
            backendStatus={backendStatus}
            onRefresh={fetchBackendStatus}
            isLoading={isLoading}
          />
        );
      default:
        return (
          <DashboardPage
            backendStatus={backendStatus}
            activeCase={activeCase}
            onNavigate={setActiveTab}
          />
        );
    }
  };

  return (
    <div className="flex h-screen w-full max-w-full bg-[var(--bg-main)] text-[var(--text-primary)] overflow-hidden font-sans antialiased box-border">
      {/* Navigation Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        engineVersion={backendStatus?.engine_version || '1.0.0'}
        isBackendOnline={backendStatus !== null}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden bg-[var(--bg-main)]">
        {/* Top Header */}
        <Header
          activeTabTitle={getPageTitle(activeTab)}
          backendStatus={backendStatus}
          activeCase={activeCase}
          onRefresh={fetchBackendStatus}
          isLoading={isLoading}
          onNavigate={setActiveTab}
          onLogout={() => setActiveTab('dashboard')}
        />

        {/* Scrollable View Container */}
        <main className="flex-1 overflow-y-auto min-w-0 bg-[var(--bg-main)] box-border">
          {renderActivePage()}
        </main>
      </div>
    </div>
  );
};

export default App;
