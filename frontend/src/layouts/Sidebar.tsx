import React from 'react';
import {
  LayoutDashboard,
  HardDrive,
  RotateCcw,
  Binary,
  ShieldAlert,
  Disc,
  FileText,
  ScrollText,
  Activity,
  Settings,
  ShieldCheck,
  LucideIcon
} from 'lucide-react';
import { NavigationTab } from '../types';

interface SidebarProps {
  activeTab: NavigationTab;
  onTabChange: (tab: NavigationTab) => void;
  engineVersion?: string;
  isBackendOnline: boolean;
}

interface NavItem {
  id: NavigationTab;
  label: string;
  subLabel?: string;
  icon: LucideIcon;
  group: 'recovery' | 'sanitization' | 'reporting' | 'system';
}

const NAV_ITEMS: NavItem[] = [
  // RECOVERY
  { id: 'dashboard', label: 'Files Recovery', subLabel: 'Deleted & Recovered', icon: LayoutDashboard, group: 'recovery' },
  { id: 'evidence', label: 'Evidence Files', icon: HardDrive, group: 'recovery' },
  { id: 'recovery', label: 'Filesystem Scan', icon: RotateCcw, group: 'recovery' },
  { id: 'carving', label: 'Raw Data Carving', subLabel: 'Signature Scanner', icon: Binary, group: 'recovery' },

  // SECURE DELETION
  { id: 'file_eraser', label: 'Secure File Deletion', icon: ShieldAlert, group: 'sanitization' },
  { id: 'drive_sanitization', label: 'Secure Drive Eraser', icon: Disc, group: 'sanitization' },

  // REPORTS & AUDIT
  { id: 'reports', label: 'Forensic Reports', icon: FileText, group: 'reporting' },
  { id: 'audit_logs', label: 'Activity & Audit Log', icon: ScrollText, group: 'reporting' },

  // SYSTEM
  { id: 'diagnostics', label: 'System Status', icon: Activity, group: 'system' },
  { id: 'settings', label: 'Settings', icon: Settings, group: 'system' },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  isBackendOnline
}) => {
  const renderNavGroup = (title: string, groupKey: NavItem['group']) => (
    <div className="mb-8">
      <div className="px-4 pb-3 text-[11px] font-bold uppercase tracking-wider text-[var(--text-secondary)] font-sans opacity-85">
        {title}
      </div>
      <div className="space-y-2.5">
        {NAV_ITEMS.filter((i) => i.group === groupKey).map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              id={`nav-${item.id}`}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center gap-3.5 px-3.5 py-3 rounded-xl text-[13.5px] transition-all text-left cursor-pointer group ${
                isActive
                  ? 'bg-[var(--surface-secondary)] text-[var(--primary-orange)] font-semibold shadow-xs ring-1 ring-[var(--primary-orange)]/25'
                  : 'text-[var(--text-primary)] hover:bg-[var(--surface-secondary)]/80 hover:text-[var(--text-primary)] font-medium'
              }`}
            >
              {/* Dedicated Icon Badge with proper breathing room */}
              <div
                className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 transition-colors ${
                  isActive
                    ? 'bg-[var(--primary-orange)]/15 text-[var(--primary-orange)]'
                    : 'bg-[var(--surface-secondary)]/60 text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] group-hover:bg-[var(--surface-secondary)]'
                }`}
              >
                <Icon size={19} aria-hidden="true" focusable="false" />
              </div>

              {/* Label & Description */}
              <div className="min-w-0 flex-1">
                <div className="truncate leading-tight">{item.label}</div>
                {item.subLabel && (
                  <div className="text-[11px] font-normal text-[var(--text-secondary)] mt-1 truncate opacity-85">
                    {item.subLabel}
                  </div>
                )}
              </div>

              {/* Active Indicator Pill */}
              {isActive && (
                <div className="w-1.5 h-4 rounded-full bg-[var(--primary-orange)] flex-shrink-0" />
              )}
            </button>
          );
        })}
      </div>
    </div>
  );

  return (
    <aside className="w-[280px] bg-[var(--surface)] border-r border-[var(--border)] flex flex-col flex-shrink-0 h-screen select-none transition-colors duration-200">
      {/* Brand Header */}
      <div className="p-6 border-b border-[var(--border)] flex items-center gap-3.5">
        <div className="w-10 h-10 rounded-xl bg-[var(--surface-secondary)] border border-[var(--primary-orange)]/30 flex items-center justify-center text-[var(--primary-orange)] flex-shrink-0">
          <ShieldCheck size={22} aria-hidden="true" focusable="false" />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-bold text-[var(--text-primary)] tracking-tight text-[15px]">FORENSIVAULT</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--primary-orange)]/15 text-[var(--primary-orange)] font-semibold border border-[var(--primary-orange)]/25">
              PRO
            </span>
          </div>
          <p className="text-[11.5px] text-[var(--text-secondary)] tracking-normal truncate mt-0.5">Desktop Workstation</p>
        </div>
      </div>

      {/* Primary Navigation */}
      <nav className="flex-1 overflow-y-auto px-4 py-7">
        {renderNavGroup('RECOVERY', 'recovery')}
        {renderNavGroup('SECURE DELETION', 'sanitization')}
        {renderNavGroup('REPORTS & AUDIT', 'reporting')}
        {renderNavGroup('SYSTEM', 'system')}
      </nav>

      {/* Sidebar Footer / System Status Panel */}
      <div className="p-5 border-t border-[var(--border)] bg-[var(--surface)] text-[12px] space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-[10.5px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
            SYSTEM ENGINE
          </span>
          <span className="text-[11px] font-mono text-[var(--text-secondary)]">v1.0.0</span>
        </div>
        <div className="flex items-center gap-2.5">
          <span
            className={`w-2.5 h-2.5 rounded-full ${
              isBackendOnline ? 'bg-[#2E7D32]' : 'bg-[#C53030]'
            }`}
          />
          <span className={`text-[12.5px] font-medium ${isBackendOnline ? 'text-[#2E7D32]' : 'text-[#C53030]'}`}>
            {isBackendOnline ? 'C++ Engine Online' : 'C++ Engine Offline'}
          </span>
        </div>
        <div className="flex items-center justify-between pt-2 border-t border-[var(--border-subtle)] text-[11px] text-[var(--text-secondary)]">
          <span>IPC Bridge</span>
          <span className="font-mono font-medium text-[var(--text-primary)]">127.0.0.1:8765</span>
        </div>
      </div>
    </aside>
  );
};
