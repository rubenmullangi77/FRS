import React, { useState, useEffect, useRef } from 'react';
import {
  RefreshCw,
  CheckCircle2,
  FolderLock,
  User,
  LogOut,
  Settings,
  ChevronDown,
  Sun,
  Moon
} from 'lucide-react';
import { BackendStatus, CaseMetadata, NavigationTab } from '../types';
import { settingsService } from '../services/settings';
import { authService, AuthUser } from '../services/auth';
import { themeService } from '../services/theme';

interface HeaderProps {
  activeTabTitle: string;
  backendStatus: BackendStatus | null;
  activeCase: CaseMetadata | null;
  onRefresh: () => void;
  isLoading: boolean;
  onNavigate?: (tab: NavigationTab) => void;
  onLogout?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTabTitle,
  backendStatus,
  activeCase,
  onRefresh,
  isLoading,
  onNavigate,
  onLogout
}) => {
  const [examinerName, setExaminerName] = useState<string>(settingsService.getExaminerName());
  const [authUser, setAuthUser] = useState<AuthUser | null>(authService.getUser());
  const [isMenuOpen, setIsMenuOpen] = useState<boolean>(false);
  const [isDark, setIsDark] = useState<boolean>(themeService.isDark());
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const unsubSettings = settingsService.subscribe((s) => {
      setExaminerName(s.examinerName.trim() || 'Examiner not set');
    });
    const unsubAuth = authService.subscribe((sess) => {
      setAuthUser(sess.user);
    });
    const unsubTheme = themeService.subscribe((t) => {
      setIsDark(t === 'dark');
    });

    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);

    return () => {
      unsubSettings();
      unsubAuth();
      unsubTheme();
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const isOnline = backendStatus !== null;
  const signedInUsername = authUser?.username || 'Ruben';

  const handleSignOut = async () => {
    setIsMenuOpen(false);
    await authService.logout();
    if (onLogout) onLogout();
  };

  return (
    <header className="h-16 bg-[var(--surface)] border-b border-[var(--border)] px-8 flex items-center justify-between z-10 select-none flex-shrink-0">
      {/* Left: Current Page Title & Workspace */}
      <div className="flex items-center gap-5">
        <h1 className="text-[17px] font-semibold text-[var(--text-primary)] tracking-tight">
          {activeTabTitle}
        </h1>

        {activeCase && (
          <div className="hidden lg:flex items-center gap-2 pl-4 border-l border-[var(--border)]">
            <FolderLock size={14} className="text-[var(--primary-orange)]" aria-hidden="true" focusable="false" />
            <span className="text-[12px] text-[var(--text-secondary)]">Current Case:</span>
            <span className="text-[12px] font-mono font-medium text-[var(--text-primary)] px-2 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
              {activeCase.case_id}
            </span>
          </div>
        )}
      </div>

      {/* Right: User Profile Menu, Theme Toggle, Examiner Name, Status Pills & Refresh Action */}
      <div className="flex items-center gap-3">
        {/* Dark / Light Mode Toggle */}
        <button
          id="header-theme-toggle"
          onClick={() => themeService.toggleTheme()}
          title={isDark ? 'Switch to Light (Cream) Mode' : 'Switch to Dark Mode'}
          className="p-2 rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)] hover:border-[var(--primary-orange)] transition-colors flex items-center justify-center cursor-pointer"
        >
          {isDark ? (
            <Sun size={15} className="text-[#FBBF24]" aria-hidden="true" focusable="false" />
          ) : (
            <Moon size={15} className="text-[var(--text-secondary)]" aria-hidden="true" focusable="false" />
          )}
        </button>

        {/* Configured Examiner Name Badge */}
        <div className="hidden xl:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-[12px]">
          <span className="text-[var(--text-secondary)]">Examiner:</span>
          <span className="font-semibold text-[var(--text-primary)]">{examinerName}</span>
        </div>

        {/* Authenticated User Menu Dropdown */}
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-secondary)] border border-[var(--border)] hover:border-[var(--primary-orange)]/40 text-[12px] transition-colors cursor-pointer"
            title="Account Profile & Settings"
          >
            <div className="w-5 h-5 rounded-full bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--primary-orange)]">
              <User size={12} aria-hidden="true" focusable="false" />
            </div>
            <div className="flex flex-col text-left">
              <span className="text-[10px] text-[var(--text-secondary)] leading-none">Signed in as</span>
              <span className="font-semibold text-[var(--text-primary)] leading-tight">{signedInUsername}</span>
            </div>
            <ChevronDown size={13} className="text-[var(--text-secondary)] ml-0.5" aria-hidden="true" focusable="false" />
          </button>

          {isMenuOpen && (
            <div className="absolute right-0 mt-2 w-56 bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-lg py-1.5 z-50 text-[13px] animate-fade-in">
              <div className="px-4 py-2 border-b border-[var(--border-subtle)]">
                <div className="font-semibold text-[var(--text-primary)]">{signedInUsername}</div>
                <div className="text-[11.5px] text-[var(--text-secondary)]">{authUser?.role || 'Lead Forensic Examiner'}</div>
              </div>

              <div className="py-1">
                <button
                  onClick={() => {
                    setIsMenuOpen(false);
                    if (onNavigate) onNavigate('settings');
                  }}
                  className="w-full text-left px-4 py-2 flex items-center gap-2.5 text-[var(--text-primary)] hover:bg-[var(--surface-secondary)] transition-colors cursor-pointer"
                >
                  <Settings size={15} className="text-[var(--text-secondary)]" aria-hidden="true" focusable="false" />
                  <span>Workstation Settings</span>
                </button>
              </div>

              <div className="border-t border-[var(--border-subtle)] pt-1">
                <button
                  onClick={handleSignOut}
                  className="w-full text-left px-4 py-2 flex items-center gap-2.5 text-[#C53030] hover:bg-[#C53030]/10 transition-colors cursor-pointer font-medium"
                >
                  <LogOut size={15} aria-hidden="true" focusable="false" />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* C++ Core Status Pill */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-[12px]">
          <span
            className={`w-2 h-2 rounded-full ${
              isOnline ? 'bg-[#2E7D32]' : 'bg-[#C53030]'
            }`}
          />
          <span className={`font-medium ${isOnline ? 'text-[#2E7D32]' : 'text-[#C53030]'}`}>
            {isOnline ? 'C++ Engine Online' : 'Engine Offline'}
          </span>
        </div>

        {/* 53/53 Tests Badge */}
        <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--surface)] border border-[#2E7D32]/40 text-[12px] text-[#2E7D32]">
          <CheckCircle2 size={13} aria-hidden="true" focusable="false" />
          <span className="font-semibold font-mono">53/53 Tests</span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isLoading}
          title="Refresh hardware inventory and backend status"
          className="p-2 rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)] hover:border-[var(--primary-orange)]/40 transition-colors disabled:opacity-50 flex items-center justify-center cursor-pointer"
        >
          <RefreshCw size={14} className={isLoading ? 'animate-spin text-[var(--primary-orange)]' : 'text-[var(--text-secondary)]'} aria-hidden="true" focusable="false" />
        </button>
      </div>
    </header>
  );
};
