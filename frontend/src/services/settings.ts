import { themeService, ThemeMode } from './theme';

export interface UserSettings {
  examinerName: string;
  agencyName: string;
  defaultCaseName: string;
  defaultEvidenceFolder: string;
  theme: ThemeMode;
  notificationsEnabled: boolean;
}

const STORAGE_KEY = 'forensivault_settings_v1';

const DEFAULT_SETTINGS: Omit<UserSettings, 'theme'> = {
  examinerName: '',
  agencyName: 'National Cyber Crime Forensics Lab',
  defaultCaseName: 'SIH Demo Case',
  defaultEvidenceFolder: 'D:\\SIH\\test_data',
  notificationsEnabled: true
};

type Listener = (settings: UserSettings) => void;
const listeners: Set<Listener> = new Set();

export const settingsService = {
  getSettings(): UserSettings {
    const activeTheme = themeService.getTheme();
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        return {
          ...DEFAULT_SETTINGS,
          ...parsed,
          theme: activeTheme // Always authoritative from themeService
        };
      }
    } catch {
      // ignore
    }
    return {
      ...DEFAULT_SETTINGS,
      theme: activeTheme
    };
  },

  saveSettings(newSettings: Partial<UserSettings>): UserSettings {
    if (newSettings.theme) {
      themeService.setTheme(newSettings.theme);
    }
    const current = this.getSettings();
    const updated: UserSettings = {
      ...current,
      ...newSettings,
      theme: themeService.getTheme()
    };
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // ignore
    }
    listeners.forEach((fn) => fn(updated));
    return updated;
  },

  getExaminerName(): string {
    const s = this.getSettings();
    return s.examinerName.trim() || 'Examiner not set';
  },

  subscribe(listener: Listener): () => void {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }
};
