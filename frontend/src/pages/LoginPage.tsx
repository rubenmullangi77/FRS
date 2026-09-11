import React, { useState, useEffect } from 'react';
import { Shield, Lock, User, AlertCircle, ArrowRight, Sun, Moon, Eye, EyeOff, CheckCircle2 } from 'lucide-react';
import { authService } from '../services/auth';
import { themeService, ThemeMode } from '../services/theme';

interface LoginPageProps {
  onLoginSuccess: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [rememberMe, setRememberMe] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [themeMode, setThemeMode] = useState<ThemeMode>(themeService.getTheme());

  useEffect(() => {
    return themeService.subscribe((t) => setThemeMode(t));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setErrorMessage('Please enter both username and password.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      await authService.login(username.trim(), password, rememberMe);
      onLoginSuccess();
    } catch (err: any) {
      setErrorMessage(err.message || 'Invalid username or password.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleAutofillDemo = () => {
    setUsername('Ruben');
    setPassword('rube');
    setErrorMessage(null);
  };

  const isDark = themeMode === 'dark';

  return (
    <div className="min-h-screen w-full flex flex-col justify-between bg-[var(--bg-main)] text-[var(--text-primary)] font-sans transition-colors duration-200 select-none">
      {/* 1. TOP BAR */}
      <header className="h-20 px-8 lg:px-14 flex items-center justify-between border-b border-[var(--border)] bg-[var(--surface)] flex-shrink-0">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-[var(--surface-secondary)] border border-[var(--primary-orange)]/40 flex items-center justify-center text-[var(--primary-orange)] shadow-xs">
            <Shield size={22} aria-hidden="true" focusable="false" />
          </div>
          <div className="flex items-center gap-2.5">
            <span className="font-bold text-[18px] tracking-tight text-[var(--text-primary)]">FORENSIVAULT</span>
            <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-[var(--primary-orange)]/15 text-[var(--primary-orange)] font-semibold border border-[var(--primary-orange)]/25">
              PRO v1.0.0
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Explicit Theme Mode Switcher */}
          <button
            id="login-theme-toggle"
            onClick={() => themeService.toggleTheme()}
            title={isDark ? 'Switch to Warm Cream (Light) Mode' : 'Switch to Dark Obsidian Mode'}
            className="flex items-center gap-2.5 px-3.5 py-2 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] text-[var(--text-primary)] border border-[var(--border)] hover:border-[var(--primary-orange)] transition-all cursor-pointer text-[13px] font-medium"
          >
            {isDark ? (
              <>
                <Sun size={16} className="text-[#FBBF24]" aria-hidden="true" focusable="false" />
                <span className="hidden sm:inline">Dark Mode</span>
              </>
            ) : (
              <>
                <Moon size={16} className="text-[var(--text-secondary)]" aria-hidden="true" focusable="false" />
                <span className="hidden sm:inline">Cream Light</span>
              </>
            )}
          </button>

          <div className="hidden md:flex items-center gap-2 text-[12.5px] px-3.5 py-1.5 rounded-full bg-[var(--surface-secondary)] border border-[var(--border)]">
            <span className="w-2.5 h-2.5 rounded-full bg-[#2E7D32] animate-pulse"></span>
            <span className="font-semibold text-[#2E7D32]">Security Subsystem Online</span>
          </div>
        </div>
      </header>

      {/* 2. CENTERED LOGIN PANEL */}
      <main className="flex-1 flex items-center justify-center p-6 sm:p-12 my-auto">
        <div className="w-full max-w-[500px] space-y-8">
          {/* Header Typography */}
          <div className="text-center space-y-3">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[var(--surface)] border border-[var(--border)] shadow-sm">
              <Lock size={28} className="text-[var(--primary-orange)]" aria-hidden="true" focusable="false" />
            </div>
            <h1 className="text-[30px] font-extrabold tracking-tight text-[var(--text-primary)]">
              FORENSIVAULT
            </h1>
            <p className="text-[14.5px] text-[var(--text-secondary)]">
              Digital Forensics & Incident Response Workstation
            </p>
          </div>

          {/* Form Card */}
          <div className="workstation-card p-10 sm:p-12 border border-[var(--border)] rounded-2xl shadow-xl space-y-8 bg-[var(--surface)]">
            <div className="border-b border-[var(--border-subtle)] pb-5">
              <h2 className="text-[18px] font-bold text-[var(--text-primary)] tracking-tight">Sign In to Workstation</h2>
              <p className="text-[13.5px] text-[var(--text-secondary)] mt-1">Enter authorized forensic examiner credentials to access cases</p>
            </div>

            {errorMessage && (
              <div
                role="alert"
                className="p-4 rounded-xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13.5px] flex items-center gap-3 animate-fade-in"
              >
                <AlertCircle size={20} className="flex-shrink-0" aria-hidden="true" focusable="false" />
                <span className="font-medium">{errorMessage}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Username Input */}
              <div className="space-y-2.5">
                <label className="block text-[13px] font-semibold text-[var(--text-primary)]">
                  Examiner Username
                </label>
                <div className="flex items-center h-14 px-4.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] focus-within:border-[var(--primary-orange)] focus-within:ring-2 focus-within:ring-[var(--primary-orange)]/25 transition-all gap-3.5">
                  <User size={19} className="text-[var(--text-secondary)] flex-shrink-0" aria-hidden="true" focusable="false" />
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="e.g. Ruben"
                    autoComplete="username"
                    className="bg-transparent w-full text-[14.5px] text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none"
                  />
                </div>
              </div>

              {/* Password Input */}
              <div className="space-y-2.5">
                <label className="block text-[13px] font-semibold text-[var(--text-primary)]">
                  Password
                </label>
                <div className="flex items-center h-14 px-4.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] focus-within:border-[var(--primary-orange)] focus-within:ring-2 focus-within:ring-[var(--primary-orange)]/25 transition-all gap-3.5">
                  <Lock size={19} className="text-[var(--text-secondary)] flex-shrink-0" aria-hidden="true" focusable="false" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter workstation password"
                    autoComplete="current-password"
                    className="bg-transparent w-full text-[14.5px] text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors p-1 cursor-pointer"
                    title={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>

              {/* Remember me & Audit indicator */}
              <div className="flex items-center justify-between pt-1">
                <label className="flex items-center gap-3 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="w-4 h-4 rounded text-[var(--primary-orange)] border-[var(--border)] focus:ring-0 cursor-pointer"
                  />
                  <span className="text-[13px] text-[var(--text-secondary)] font-medium">Remember this workstation</span>
                </label>

                <span className="text-[11.5px] font-mono text-[var(--text-muted)] hidden sm:inline">
                  Local Session
                </span>
              </div>

              {/* Primary Action Button */}
              <div className="pt-2 space-y-4">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full h-13 rounded-xl bg-[var(--primary-orange)] hover:bg-[var(--dark-orange)] text-white font-bold text-[14.5px] flex items-center justify-center gap-2.5 transition-all disabled:opacity-60 shadow-md hover:shadow-lg cursor-pointer"
                >
                  {isLoading ? (
                    <span className="inline-block w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                  ) : (
                    <>
                      <span>Authenticate & Enter Workstation</span>
                      <ArrowRight size={17} aria-hidden="true" focusable="false" />
                    </>
                  )}
                </button>

                {/* Quick Demo Autofill Card */}
                <div
                  onClick={handleAutofillDemo}
                  className="p-3.5 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] hover:border-[var(--primary-orange)]/50 transition-all cursor-pointer flex items-center justify-between group"
                  title="Click to populate default examiner credentials"
                >
                  <div className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-[var(--primary-orange)] group-hover:scale-110 transition-transform" />
                    <span className="text-[12.5px] text-[var(--text-secondary)] font-medium">
                      Demo Credentials:
                    </span>
                    <span className="font-mono text-[12.5px] font-bold text-[var(--primary-orange)]">
                      Ruben / rube
                    </span>
                  </div>
                  <span className="text-[11.5px] font-semibold text-[var(--primary-orange)] group-hover:underline">
                    Autofill →
                  </span>
                </div>
              </div>
            </form>
          </div>

          {/* Secure Environment Notice */}
          <div className="text-center text-[12.5px] text-[var(--text-secondary)] space-y-1.5 opacity-80">
            <p className="font-medium">Smart India Hackathon 2026 • Digital Forensics & Data Purge</p>
            <p className="text-[11.5px] opacity-75">
              All authorization events are cryptographically recorded in the local SQLite audit ledger.
            </p>
          </div>
        </div>
      </main>

      {/* 3. SUBTLE FOOTER */}
      <footer className="h-16 px-8 lg:px-14 flex items-center justify-between border-t border-[var(--border)] bg-[var(--surface)] text-[12.5px] text-[var(--text-secondary)] select-none flex-shrink-0">
        <span>ForensiVault Forensic Core v1.0.0</span>
        <span className="font-mono">127.0.0.1:8765 Local Native IPC</span>
      </footer>
    </div>
  );
};
