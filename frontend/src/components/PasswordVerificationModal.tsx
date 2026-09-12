import React, { useState } from 'react';
import { Lock, ShieldAlert, AlertCircle, CheckCircle2 } from 'lucide-react';
import { Modal } from './Modal';
import { authService } from '../services/auth';

interface PasswordVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onVerified: () => void;
  title?: string;
  actionDescription?: string;
  actionName?: string;
  targetIdentifier?: string;
}

export const PasswordVerificationModal: React.FC<PasswordVerificationModalProps> = ({
  isOpen,
  onClose,
  onVerified,
  title = 'Confirm Sensitive Action',
  actionDescription = 'This action can modify or permanently remove data. To continue, verify your password.',
  actionName = 'CONFIRM_SENSITIVE_ACTION',
  targetIdentifier = ''
}) => {
  const [password, setPassword] = useState<string>('');
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [verifiedSuccess, setVerifiedSuccess] = useState<boolean>(false);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) {
      setErrorMessage('Please enter your password.');
      return;
    }

    setIsVerifying(true);
    setErrorMessage(null);

    try {
      const ok = await authService.verifyPassword(password, actionName, targetIdentifier);
      if (ok) {
        setVerifiedSuccess(true);
        setTimeout(() => {
          setPassword('');
          setVerifiedSuccess(false);
          onVerified();
        }, 400);
      } else {
        setErrorMessage('Password verification failed.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Password verification failed.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleClose = () => {
    setPassword('');
    setErrorMessage(null);
    setVerifiedSuccess(false);
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title={title}
      variant="danger"
    >
      <div className="p-6 space-y-5 bg-[var(--surface)]">
        {/* Warning Banner */}
        <div className="p-4 rounded-lg bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px] flex items-start gap-3">
          <ShieldAlert size={18} className="flex-shrink-0 mt-0.5" aria-hidden="true" focusable="false" />
          <div className="space-y-1">
            <div className="font-semibold uppercase tracking-wider text-[11px]">Security Verification Required</div>
            <p className="text-[13px] text-[var(--text-primary)] leading-relaxed">
              {actionDescription}
            </p>
          </div>
        </div>

        {targetIdentifier && (
          <div className="px-3.5 py-2 rounded-md bg-[var(--surface-secondary)] border border-[var(--border)] text-[12px] text-[var(--text-secondary)] flex items-center justify-between">
            <span>Target Resource:</span>
            <span className="font-mono text-[var(--text-primary)] truncate max-w-[320px]">{targetIdentifier}</span>
          </div>
        )}

        {errorMessage && (
          <div
            role="alert"
            className="p-3 rounded-md bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[12.5px] flex items-center gap-2"
          >
            <AlertCircle size={15} aria-hidden="true" focusable="false" />
            <span>{errorMessage}</span>
          </div>
        )}

        {verifiedSuccess && (
          <div className="p-3 rounded-md bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-[12.5px] flex items-center gap-2">
            <CheckCircle2 size={15} aria-hidden="true" focusable="false" />
            <span>Identity verified. Proceeding to confirmation...</span>
          </div>
        )}

        <form onSubmit={handleVerify} className="space-y-4">
          <div>
            <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
              Enter Password:
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--text-secondary)]">
                <Lock size={15} aria-hidden="true" focusable="false" />
              </div>
              <input
                type="password"
                required
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Verify your password"
                className="w-full bg-[var(--surface-secondary)] border border-[var(--border)] rounded-lg pl-9 pr-3.5 py-2.5 text-[13.5px] text-[var(--text-primary)] focus:outline-none focus:border-[#D96B27] focus:ring-1 focus:ring-[#D96B27]"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={handleClose}
              disabled={isVerifying}
              className="px-4 py-2 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-hover)] text-[13px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isVerifying || !password}
              className="px-5 py-2 rounded-lg bg-[#D96B27] hover:bg-[#B9541D] text-white font-semibold text-[13px] transition-colors disabled:opacity-50 cursor-pointer"
            >
              {isVerifying ? 'Verifying...' : 'Verify & Continue'}
            </button>
          </div>
        </form>
      </div>
    </Modal>
  );
};
