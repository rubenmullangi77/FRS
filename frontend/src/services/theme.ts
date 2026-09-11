// Centralized Theme Service for ForensiVault Desktop Workstation
export type ThemeMode = 'dark' | 'light';

const THEME_KEY = 'forensivault_theme_mode';
type ThemeListener = (theme: ThemeMode) => void;
const listeners: Set<ThemeListener> = new Set();

class ThemeService {
  private currentTheme: ThemeMode;

  constructor() {
    this.currentTheme = this.loadInitialTheme();
    this.applyTheme(this.currentTheme);
  }

  private loadInitialTheme(): ThemeMode {
    try {
      const saved = localStorage.getItem(THEME_KEY) as ThemeMode | null;
      if (saved === 'light' || saved === 'dark') {
        return saved;
      }
    } catch {
      // Ignore storage errors
    }
    // Default to dark mode as requested for modern forensic workstation aesthetics
    return 'dark';
  }

  getTheme(): ThemeMode {
    return this.currentTheme;
  }

  isDark(): boolean {
    return this.currentTheme === 'dark';
  }

  setTheme(theme: ThemeMode): void {
    this.currentTheme = theme;
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      // Ignore storage errors
    }
    this.applyTheme(theme);
    listeners.forEach((fn) => fn(theme));
  }

  toggleTheme(): ThemeMode {
    const next = this.currentTheme === 'dark' ? 'light' : 'dark';
    this.setTheme(next);
    return next;
  }

  private applyTheme(theme: ThemeMode): void {
    if (typeof document !== 'undefined') {
      const root = document.documentElement;
      if (theme === 'dark') {
        root.classList.add('dark');
        root.setAttribute('data-theme', 'dark');
      } else {
        root.classList.remove('dark');
        root.setAttribute('data-theme', 'light');
      }
    }
  }

  subscribe(listener: ThemeListener): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }
}

export const themeService = new ThemeService();
