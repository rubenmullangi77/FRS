import React, { useState, useEffect } from 'react';
import {
  User,
  FolderOpen,
  CheckCircle2,
  Sliders,
  Bell,
  Save,
  Moon,
  Sun,
  Shield,
  Check,
  RotateCcw,
  Sparkles,
  Lock,
  RefreshCw
} from 'lucide-react';
import { BackendStatus } from '../types';
import { settingsService, UserSettings } from '../services/settings';
import { themeService, ThemeMode } from '../services/theme';

interface SettingsPageProps {
  backendStatus: BackendStatus | null;
  onRefresh: () => void;
  isLoading: boolean;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({
  backendStatus: _backendStatus,
  onRefresh,
  isLoading: _isLoading
}) => {
  const [settings, setSettings] = useState<UserSettings>(settingsService.getSettings());
  const [currentThemeMode, setCurrentThemeMode] = useState<ThemeMode>(themeService.getTheme());
  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);

  const handleRefreshSettings = async () => {
    setIsRefreshing(true);
    setRefreshError(null);
    try {
      setSettings(settingsService.getSettings());
      setCurrentThemeMode(themeService.getTheme());
      if (onRefresh) await onRefresh();
    } catch {
      setRefreshError('Unable to refresh data.');
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    const unsubTheme = themeService.subscribe((t) => {
      setCurrentThemeMode(t);
    });
    const unsubSettings = settingsService.subscribe((s) => {
      setSettings(s);
    });
    return () => {
      unsubTheme();
      unsubSettings();
    };
  }, []);

  const handleSelectTheme = (mode: ThemeMode) => {
    themeService.setTheme(mode);
    setCurrentThemeMode(mode);
    setSettings((prev) => ({
      ...prev,
      theme: mode
    }));
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    settingsService.saveSettings(settings);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 4000);
  };

  const handleResetDefaults = () => {
    const defaultSettings: UserSettings = {
      examinerName: 'Ruben Mullangi',
      agencyName: 'National Cyber Crime Forensics Lab',
      defaultCaseName: 'SIH Demo Case',
      defaultEvidenceFolder: 'test_data',
      theme: 'dark',
      notificationsEnabled: true
    };
    setSettings(defaultSettings);
    settingsService.saveSettings(defaultSettings);
    themeService.setTheme('dark');
    setCurrentThemeMode('dark');
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 4000);
  };

  return (
    <div className="p-8 lg:p-14 space-y-10 max-w-5xl mx-auto min-h-full pb-28">
      {/* 1. PAGE HEADER */}
      <div className="pb-6 border-b border-[var(--border-subtle)]">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-[28px] lg:text-[32px] font-bold text-[var(--text-primary)] tracking-tight">
                System Settings
              </h1>
              <span className="px-3 py-1 rounded-full text-[11.5px] font-mono font-semibold bg-[var(--surface-secondary)] text-[var(--primary-orange)] border border-[var(--border)]">
                Workstation v1.0.0
              </span>
            </div>
            <p className="text-[14.5px] text-[var(--text-secondary)] mt-2 leading-relaxed max-w-2xl">
              Configure investigator credentials, visual theme styles, evidence directories, and audit logging parameters.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleRefreshSettings}
              disabled={isRefreshing}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[12.5px] font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all cursor-pointer shadow-xs"
              title="Refresh settings and status"
            >
              <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
            <span className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] text-[12.5px] font-medium text-[var(--text-secondary)]">
              <span className="w-2.5 h-2.5 rounded-full bg-[#2E7D32]"></span>
              IPC Sync Active
            </span>
          </div>
        </div>
      </div>

      {refreshError && (
        <div className="p-4 rounded-xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px]">
          {refreshError}
        </div>
      )}

      {/* SUCCESS BANNER */}
      {savedSuccess && (
        <div className="p-5 rounded-2xl bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-[14px] flex items-center justify-between gap-3 shadow-xs animate-fade-in">
          <div className="flex items-center gap-3">
            <CheckCircle2 size={20} className="flex-shrink-0" aria-hidden="true" focusable="false" />
            <span className="font-semibold">
              Settings and visual preferences successfully updated and synchronized.
            </span>
          </div>
          <span className="text-[12px] font-mono opacity-80">SAVED</span>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-10">
        {/* ============================================================ */}
        {/* SECTION 1: WORKSTATION THEME & APPEARANCE                    */}
        {/* ============================================================ */}
        <div className="workstation-card p-8 lg:p-10 space-y-7">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-2 border-b border-[var(--border-subtle)]">
            <div className="space-y-1">
              <h2 className="text-[19px] font-bold text-[var(--text-primary)] flex items-center gap-2.5">
                <Sliders size={20} className="text-[var(--primary-orange)]" aria-hidden="true" focusable="false" />
                <span>Workstation Visual Theme</span>
              </h2>
              <p className="text-[13.5px] text-[var(--text-secondary)]">
                Select your preferred appearance mode. Changes apply immediately in real-time across all views.
              </p>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-[12px] font-mono text-[var(--text-secondary)]">
              <span>Current:</span>
              <strong className="text-[var(--primary-orange)] uppercase">
                {currentThemeMode === 'dark' ? 'Dark Obsidian' : 'Warm Cream'}
              </strong>
            </div>
          </div>

          {/* Interactive Visual Theme Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-1">
            {/* Card 1: Dark Mode */}
            <div
              id="theme-btn-dark"
              onClick={() => handleSelectTheme('dark')}
              className={`p-6 rounded-2xl border-2 transition-all cursor-pointer flex flex-col justify-between space-y-5 bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] ${
                currentThemeMode === 'dark'
                  ? 'border-[var(--primary-orange)] shadow-lg ring-2 ring-[var(--primary-orange)]/25'
                  : 'border-[var(--border)] opacity-85 hover:opacity-100'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3.5">
                  <div className="w-11 h-11 rounded-xl bg-[#1C1917] border border-[#3A342E] flex items-center justify-center text-[#FBBF24] shadow-xs">
                    <Moon size={22} />
                  </div>
                  <div>
                    <div className="font-bold text-[16px] text-[var(--text-primary)] flex items-center gap-2">
                      <span>Dark Mode</span>
                      <span className="text-[11px] font-normal px-2 py-0.5 rounded-full bg-[#EA7325]/15 text-[#EA7325] border border-[#EA7325]/30">
                        Default
                      </span>
                    </div>
                    <div className="text-[12.5px] text-[var(--text-secondary)] mt-0.5">
                      High-Contrast Obsidian Lab Workspace
                    </div>
                  </div>
                </div>

                {currentThemeMode === 'dark' ? (
                  <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-[var(--primary-orange)] text-white text-[12px] font-bold shadow-xs">
                    <Check size={14} />
                    <span>Active</span>
                  </div>
                ) : (
                  <span className="text-[12px] text-[var(--text-muted)] hover:text-[var(--text-primary)] font-medium">
                    Click to switch
                  </span>
                )}
              </div>

              {/* Realistic Desktop Mockup Preview (Dark) */}
              <div className="rounded-xl overflow-hidden border border-[#3A342E] bg-[#121110] p-3 shadow-inner space-y-2">
                <div className="flex items-center gap-1.5 pb-2 border-b border-[#2D2823]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]/80"></span>
                  <span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]/80"></span>
                  <span className="w-2.5 h-2.5 rounded-full bg-[#10B981]/80"></span>
                  <span className="ml-2 text-[10.5px] font-mono text-[#A89D93]">ForensiVault Dark UI</span>
                </div>
                <div className="flex gap-2">
                  <div className="w-1/4 h-14 rounded-md bg-[#1C1917] border border-[#3A342E] p-1.5 space-y-1">
                    <div className="w-3/4 h-1.5 rounded bg-[#EA7325]"></div>
                    <div className="w-1/2 h-1.5 rounded bg-[#3A342E]"></div>
                    <div className="w-2/3 h-1.5 rounded bg-[#3A342E]"></div>
                  </div>
                  <div className="flex-1 h-14 rounded-md bg-[#1C1917] border border-[#3A342E] p-2 flex flex-col justify-between">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-[#F7F2E8] font-bold">Deleted Files</span>
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-[#34D399]/20 text-[#34D399]">Recovered</span>
                    </div>
                    <div className="flex gap-1">
                      <div className="w-5 h-2 rounded bg-[#2E2924]"></div>
                      <div className="w-8 h-2 rounded bg-[#2E2924]"></div>
                      <div className="w-4 h-2 rounded bg-[#2E2924]"></div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Color Swatch Dots */}
              <div className="flex items-center gap-2 pt-2 border-t border-[var(--border-subtle)] text-[12px] text-[var(--text-secondary)]">
                <span>Palette:</span>
                <span className="w-4 h-4 rounded-full bg-[#121110] border border-[#3A342E]" title="Obsidian #121110" />
                <span className="w-4 h-4 rounded-full bg-[#1C1917] border border-[#3A342E]" title="Surface #1C1917" />
                <span className="w-4 h-4 rounded-full bg-[#EA7325]" title="Accent #EA7325" />
                <span className="w-4 h-4 rounded-full bg-[#34D399]" title="Success #34D399" />
                <span className="ml-auto font-mono text-[11px] text-[var(--text-muted)]">Low Eyestrain</span>
              </div>
            </div>

            {/* Card 2: Warm Cream */}
            <div
              id="theme-btn-light"
              onClick={() => handleSelectTheme('light')}
              className={`p-6 rounded-2xl border-2 transition-all cursor-pointer flex flex-col justify-between space-y-5 bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] ${
                currentThemeMode === 'light'
                  ? 'border-[var(--primary-orange)] shadow-lg ring-2 ring-[var(--primary-orange)]/25'
                  : 'border-[var(--border)] opacity-85 hover:opacity-100'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3.5">
                  <div className="w-11 h-11 rounded-xl bg-[#FFFDF8] border border-[#DDD2C5] flex items-center justify-center text-[#D96B27] shadow-xs">
                    <Sun size={22} />
                  </div>
                  <div>
                    <div className="font-bold text-[16px] text-[var(--text-primary)] flex items-center gap-2">
                      <span>Warm Cream</span>
                      <span className="text-[11px] font-normal px-2 py-0.5 rounded-full bg-[#D96B27]/15 text-[#D96B27] border border-[#D96B27]/30">
                        Editorial
                      </span>
                    </div>
                    <div className="text-[12.5px] text-[var(--text-secondary)] mt-0.5">
                      Warm Archival Forensic Paper Theme
                    </div>
                  </div>
                </div>

                {currentThemeMode === 'light' ? (
                  <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-[var(--primary-orange)] text-white text-[12px] font-bold shadow-xs">
                    <Check size={14} />
                    <span>Active</span>
                  </div>
                ) : (
                  <span className="text-[12px] text-[var(--text-muted)] hover:text-[var(--text-primary)] font-medium">
                    Click to switch
                  </span>
                )}
              </div>

              {/* Realistic Desktop Mockup Preview (Light) */}
              <div className="rounded-xl overflow-hidden border border-[#DDD2C5] bg-[#F7F3EB] p-3 shadow-inner space-y-2">
                <div className="flex items-center gap-1.5 pb-2 border-b border-[#EBE3D7]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#C53030]/80"></span>
                  <span className="w-2.5 h-2.5 rounded-full bg-[#B7791F]/80"></span>
                  <span className="w-2.5 h-2.5 rounded-full bg-[#2E7D32]/80"></span>
                  <span className="ml-2 text-[10.5px] font-mono text-[#756B63]">ForensiVault Cream UI</span>
                </div>
                <div className="flex gap-2">
                  <div className="w-1/4 h-14 rounded-md bg-[#F1EBDD] border border-[#DDD2C5] p-1.5 space-y-1">
                    <div className="w-3/4 h-1.5 rounded bg-[#D96B27]"></div>
                    <div className="w-1/2 h-1.5 rounded bg-[#DDD2C5]"></div>
                    <div className="w-2/3 h-1.5 rounded bg-[#DDD2C5]"></div>
                  </div>
                  <div className="flex-1 h-14 rounded-md bg-[#FFFDF8] border border-[#DDD2C5] p-2 flex flex-col justify-between">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-[#29231F] font-bold">Deleted Files</span>
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-[#2E7D32]/20 text-[#2E7D32]">Recovered</span>
                    </div>
                    <div className="flex gap-1">
                      <div className="w-5 h-2 rounded bg-[#F1EBDD]"></div>
                      <div className="w-8 h-2 rounded bg-[#F1EBDD]"></div>
                      <div className="w-4 h-2 rounded bg-[#F1EBDD]"></div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Color Swatch Dots */}
              <div className="flex items-center gap-2 pt-2 border-t border-[var(--border-subtle)] text-[12px] text-[var(--text-secondary)]">
                <span>Palette:</span>
                <span className="w-4 h-4 rounded-full bg-[#F7F3EB] border border-[#DDD2C5]" title="Cream #F7F3EB" />
                <span className="w-4 h-4 rounded-full bg-[#FFFDF8] border border-[#DDD2C5]" title="Paper #FFFDF8" />
                <span className="w-4 h-4 rounded-full bg-[#D96B27]" title="Accent #D96B27" />
                <span className="w-4 h-4 rounded-full bg-[#2E7D32]" title="Success #2E7D32" />
                <span className="ml-auto font-mono text-[11px] text-[var(--text-muted)]">High Contrast</span>
              </div>
            </div>
          </div>
        </div>

        {/* ============================================================ */}
        {/* SECTION 2: EXAMINER & LABORATORY CREDENTIALS                 */}
        {/* ============================================================ */}
        <div className="workstation-card p-8 lg:p-10 space-y-7">
          <div className="space-y-1 pb-2 border-b border-[var(--border-subtle)]">
            <h2 className="text-[19px] font-bold text-[var(--text-primary)] flex items-center gap-2.5">
              <User size={20} className="text-[var(--primary-orange)]" aria-hidden="true" focusable="false" />
              <span>Examiner & Laboratory Credentials</span>
            </h2>
            <p className="text-[13.5px] text-[var(--text-secondary)]">
              These details authenticate generated case reports, legal exhibits, and local audit trail ledger records.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-1">
            {/* Field 1: Examiner Name */}
            <div className="space-y-2.5">
              <label className="block text-[13px] font-semibold text-[var(--text-primary)]">
                Lead Examiner Full Name
              </label>
              <input
                type="text"
                value={settings.examinerName}
                onChange={(e) => setSettings({ ...settings, examinerName: e.target.value })}
                placeholder="e.g. Ruben Mullangi"
                className="w-full h-13 px-4.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] focus:border-[var(--primary-orange)] focus:ring-2 focus:ring-[var(--primary-orange)]/25 text-[14px] text-[var(--text-primary)] outline-none transition-all"
              />
              <p className="text-[12px] text-[var(--text-muted)]">
                Author name stamped into forensic report cover pages and digital certificates.
              </p>
            </div>

            {/* Field 2: Agency Name */}
            <div className="space-y-2.5">
              <label className="block text-[13px] font-semibold text-[var(--text-primary)]">
                Forensics Laboratory / Law Enforcement Agency
              </label>
              <input
                type="text"
                value={settings.agencyName}
                onChange={(e) => setSettings({ ...settings, agencyName: e.target.value })}
                placeholder="National Cyber Crime Forensics Lab"
                className="w-full h-13 px-4.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] focus:border-[var(--primary-orange)] focus:ring-2 focus:ring-[var(--primary-orange)]/25 text-[14px] text-[var(--text-primary)] outline-none transition-all"
              />
              <p className="text-[12px] text-[var(--text-muted)]">
                Organization or institution responsible for maintaining chain-of-custody.
              </p>
            </div>
          </div>
        </div>

        {/* ============================================================ */}
        {/* SECTION 3: WORKSPACE & STORAGE DIRECTORIES                   */}
        {/* ============================================================ */}
        <div className="workstation-card p-8 lg:p-10 space-y-7">
          <div className="space-y-1 pb-2 border-b border-[var(--border-subtle)]">
            <h2 className="text-[19px] font-bold text-[var(--text-primary)] flex items-center gap-2.5">
              <FolderOpen size={20} className="text-[var(--primary-orange)]" aria-hidden="true" focusable="false" />
              <span>Workspace & Storage Repositories</span>
            </h2>
            <p className="text-[13.5px] text-[var(--text-secondary)]">
              Default system directory paths for mounting evidence disk images and outputting carved files.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-1">
            {/* Field 1: Default Case Identifier */}
            <div className="space-y-2.5">
              <label className="block text-[13px] font-semibold text-[var(--text-primary)]">
                Default Case Identifier
              </label>
              <input
                type="text"
                value={settings.defaultCaseName}
                onChange={(e) => setSettings({ ...settings, defaultCaseName: e.target.value })}
                placeholder="SIH Demo Case"
                className="w-full h-13 px-4.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] focus:border-[var(--primary-orange)] focus:ring-2 focus:ring-[var(--primary-orange)]/25 text-[14px] text-[var(--text-primary)] outline-none transition-all"
              />
              <p className="text-[12px] text-[var(--text-muted)]">
                Automatically preselected when initializing new forensic recovery tasks.
              </p>
            </div>

            {/* Field 2: Evidence Directory */}
            <div className="space-y-2.5">
              <label className="block text-[13px] font-semibold text-[var(--text-primary)]">
                Default Evidence Storage Path
              </label>
              <input
                type="text"
                value={settings.defaultEvidenceFolder}
                onChange={(e) => setSettings({ ...settings, defaultEvidenceFolder: e.target.value })}
                placeholder="test_data"
                className="w-full h-13 px-4.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] focus:border-[var(--primary-orange)] focus:ring-2 focus:ring-[var(--primary-orange)]/25 font-mono text-[13.5px] text-[var(--text-primary)] outline-none transition-all"
              />
              <p className="text-[12px] text-[var(--text-muted)]">
                Local directory scanned by the low-level C++ filesystem engine.
              </p>
            </div>
          </div>

          {/* Immutability Guarantee Notice */}
          <div className="p-5 rounded-2xl bg-[var(--surface-secondary)] border border-[var(--border)] flex items-start gap-4">
            <div className="w-9 h-9 rounded-xl bg-[#2E7D32]/15 flex items-center justify-center text-[#2E7D32] flex-shrink-0 mt-0.5">
              <Shield size={19} />
            </div>
            <div className="space-y-1">
              <div className="text-[13.5px] font-bold text-[var(--text-primary)]">
                Forensic Immutability & Write-Blocking Policy
              </div>
              <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
                All recovered and carved files are strictly isolated into <code className="font-mono text-[var(--primary-orange)] font-semibold">recovered</code> directory. Source evidence images and disk sectors remain strictly read-only and will never be modified.
              </p>
            </div>
          </div>
        </div>

        {/* ============================================================ */}
        {/* SECTION 4: NOTIFICATIONS & AUDIT INTEGRITY                   */}
        {/* ============================================================ */}
        <div className="workstation-card p-8 lg:p-10 space-y-7">
          <div className="space-y-1 pb-2 border-b border-[var(--border-subtle)]">
            <h2 className="text-[19px] font-bold text-[var(--text-primary)] flex items-center gap-2.5">
              <Bell size={20} className="text-[var(--primary-orange)]" aria-hidden="true" focusable="false" />
              <span>Notifications & Forensic Subsystems</span>
            </h2>
            <p className="text-[13.5px] text-[var(--text-secondary)]">
              Configure background operation alerts and forensic audit log enforcement.
            </p>
          </div>

          <div className="space-y-5 pt-1">
            {/* Toggle 1: Completion Notifications */}
            <label className="flex items-start justify-between gap-4 p-4.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] hover:border-[var(--primary-orange)]/40 transition-colors cursor-pointer select-none">
              <div className="space-y-1">
                <div className="text-[14px] font-semibold text-[var(--text-primary)] flex items-center gap-2">
                  <span>Forensic Job Completion Alerts</span>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--surface)] text-[var(--text-secondary)] border border-[var(--border)]">
                    Desktop Alert
                  </span>
                </div>
                <p className="text-[13px] text-[var(--text-secondary)]">
                  Notify upon completion of deep signature carving, partition scanning, or cryptographic hashing jobs.
                </p>
              </div>
              <input
                type="checkbox"
                checked={settings.notificationsEnabled}
                onChange={(e) => setSettings({ ...settings, notificationsEnabled: e.target.checked })}
                className="w-5 h-5 rounded text-[var(--primary-orange)] border-[var(--border)] focus:ring-0 cursor-pointer mt-1"
              />
            </label>

            {/* Toggle 2: Cryptographic Audit Ledger */}
            <div className="flex items-start justify-between gap-4 p-4.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] opacity-90 select-none">
              <div className="space-y-1">
                <div className="text-[14px] font-semibold text-[var(--text-primary)] flex items-center gap-2">
                  <Lock size={15} className="text-[#2E7D32]" />
                  <span>Immutable SQLite Audit Trail (SHA-256)</span>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#2E7D32]/15 text-[#2E7D32] border border-[#2E7D32]/30 font-bold">
                    Enforced by Core
                  </span>
                </div>
                <p className="text-[13px] text-[var(--text-secondary)]">
                  Every user login, scan execution, file export, and erasure operation is cryptographically logged.
                </p>
              </div>
              <div className="flex items-center gap-1.5 text-[12px] font-bold text-[#2E7D32] mt-1">
                <Check size={16} />
                <span>Locked</span>
              </div>
            </div>
          </div>
        </div>

        {/* ============================================================ */}
        {/* SECTION 5: ACTION CONTROLS                                  */}
        {/* ============================================================ */}
        <div className="pt-2 flex flex-wrap items-center justify-between gap-4 border-t border-[var(--border-subtle)] pt-6">
          <div className="flex items-center gap-4">
            <button
              type="submit"
              className="h-13 px-8 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--dark-orange)] text-white font-bold text-[14.5px] flex items-center gap-2.5 shadow-md hover:shadow-lg transition-all cursor-pointer"
            >
              <Save size={18} aria-hidden="true" focusable="false" />
              <span>Save Configuration</span>
            </button>

            <button
              type="button"
              onClick={handleResetDefaults}
              className="h-13 px-6 rounded-xl bg-[var(--surface)] hover:bg-[var(--surface-secondary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--border)] text-[13.5px] font-semibold flex items-center gap-2 transition-all cursor-pointer"
            >
              <RotateCcw size={16} aria-hidden="true" focusable="false" />
              <span>Reset to Defaults</span>
            </button>
          </div>

          <div className="flex items-center gap-2 text-[12.5px] text-[var(--text-muted)]">
            <Sparkles size={15} className="text-[var(--primary-orange)]" />
            <span>Changes persist immediately into local workstation storage</span>
          </div>
        </div>
      </form>
    </div>
  );
};
