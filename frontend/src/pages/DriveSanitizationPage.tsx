import React, { useState, useEffect } from 'react';
import {
  Disc,
  AlertTriangle,
  CheckCircle2,
  HardDrive,
  Hash,
  ShieldAlert,
  ShieldCheck,
  Lock,
  PlusCircle,
  FileText
} from 'lucide-react';
import { api } from '../services/api';
import { DiskImage } from '../types';
import { Modal } from '../components/Modal';
import { PasswordVerificationModal } from '../components/PasswordVerificationModal';
import { getFriendlyEvidenceName } from '../utils/evidenceNames';

export const DriveSanitizationPage: React.FC = () => {
  const [diskImages, setDiskImages] = useState<DiskImage[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string>('');
  const [selectedMethod, setSelectedMethod] = useState<string>('nist');
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [sanitizationOutput, setSanitizationOutput] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Pre-and-post Hashes
  const [preHash, setPreHash] = useState<string>('');
  const [postHash, setPostHash] = useState<string>('');

  // Step 2: Password Verification Modal
  const [isPasswordModalOpen, setIsPasswordModalOpen] = useState<boolean>(false);

  // Step 3: Two-step explicit confirmation
  const [isConfirmOpen, setIsConfirmOpen] = useState<boolean>(false);
  const [hasAcknowledgedConsequences, setHasAcknowledgedConsequences] = useState<boolean>(false);
  const [confirmationCode, setConfirmationCode] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  const loadDrives = async () => {
    try {
      const res = await api.getDrives();
      const images = res.disk_images || [];
      setDiskImages(images);
      if (images.length > 0 && !selectedTarget) {
        setSelectedTarget(images[0].path);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    loadDrives();
  }, []);

  const handleCreateSampleDrive = async () => {
    setError(null);
    try {
      const res = await api.generateSampleFile('disposable_drive.img');
      setSelectedTarget(res.created_path);
      setSuccessMessage(`Disposable drive image ready at: ${res.created_path} (${(res.size_bytes / (1024 * 1024)).toFixed(2)} MB)`);
      setTimeout(() => setSuccessMessage(null), 4000);
      await loadDrives();
    } catch (err: any) {
      setError(err.message || 'Failed to generate disposable drive image');
    }
  };

  // Step 1 -> Click trigger -> Open Password Verification Modal
  const handleStartSanitization = async () => {
    if (!selectedTarget.trim()) {
      setError('Please select or specify a target disk image.');
      return;
    }
    setError(null);
    setIsPasswordModalOpen(true);
  };

  // Step 2 -> Password verified -> Open final explicit consequence confirmation
  const handlePasswordVerified = () => {
    setIsPasswordModalOpen(false);
    setHasAcknowledgedConsequences(false);
    setConfirmationCode('');
    setIsConfirmOpen(true);
  };

  // Step 3 -> Execute sanitization
  const handleExecuteSanitization = async () => {
    if (!hasAcknowledgedConsequences) {
      setError('You must acknowledge that this operation permanently removes data.');
      return;
    }
    const cleanCode = confirmationCode.trim().toUpperCase();
    if (cleanCode !== 'PURGE DRIVE') {
      setError('Please type PURGE DRIVE to authorize sanitization.');
      return;
    }
    setIsProcessing(true);
    setError(null);
    setSanitizationOutput(null);

    try {
      // Calculate pre-hash safely
      try {
        const beforeHashRes = await api.computeHash(selectedTarget.trim());
        setPreHash(beforeHashRes.sha256);
      } catch {
        setPreHash('Calculating...');
      }

      const res = await api.sanitizeDrive(selectedTarget.trim(), true, selectedMethod);
      setSanitizationOutput(res.output || res.message);
      if (res.sha256) {
        setPostHash(res.sha256);
      } else {
        const afterHashRes = await api.computeHash(selectedTarget.trim());
        setPostHash(afterHashRes.sha256);
      }

      setIsConfirmOpen(false);
      setConfirmationCode('');
      setHasAcknowledgedConsequences(false);
      setSuccessMessage(`Drive sanitized successfully: ${selectedTarget}`);
      await loadDrives();
    } catch (err: any) {
      setError(err.message || 'Drive sanitization failed');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="p-8 lg:p-14 space-y-10 max-w-5xl mx-auto min-h-full pb-28">
      {/* Title */}
      <div className="pb-6 border-b border-[var(--border-subtle)]">
        <div className="flex items-center gap-3">
          <h1 className="text-[28px] lg:text-[32px] font-bold text-[var(--text-primary)] tracking-tight">
            Secure Drive Eraser
          </h1>
          <span className="px-3 py-1 rounded-full text-[11.5px] font-mono font-semibold bg-[var(--surface-secondary)] text-[#C53030] border border-[var(--border)]">
            NIST SP 800-88 / DoD 5220.22-M
          </span>
        </div>
        <p className="text-[14.5px] text-[var(--text-secondary)] mt-2 leading-relaxed max-w-2xl">
          Sanitize storage device images with verified overwrite patterns and cryptographic entropy verification.
        </p>
      </div>

      {/* Advisory Card */}
      <div className="p-5 rounded-2xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2">
        <div className="flex items-center gap-2 text-[#C53030] font-bold text-[13px] uppercase">
          <ShieldAlert size={18} aria-hidden="true" focusable="false" />
          <span>Storage Media Sanitization Protocol</span>
        </div>
        <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
          Sanitization method depends on storage technology. Logical sector overwriting effectively purges magnetic media (HDD) and disk images (.img / .dd / .raw).
          Physical host OS volumes (C:\ Windows, System32) are strictly protected by ForensiVault SystemProtectionGuard.
        </p>
        <div className="text-[#2E7D32] text-[12.5px] font-semibold pt-1 flex items-center gap-2">
          <ShieldCheck size={16} />
          <span>Safe Mode Active: Operating exclusively on forensic evidence disk images to protect host hardware.</span>
        </div>
      </div>

      {/* Success Alert */}
      {successMessage && (
        <div className="p-5 rounded-2xl bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-[14px] flex items-center gap-3 shadow-xs animate-fade-in">
          <CheckCircle2 size={20} className="flex-shrink-0" />
          <span className="font-semibold">{successMessage}</span>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="p-5 rounded-2xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[14px] flex items-center gap-3 shadow-xs animate-fade-in">
          <AlertTriangle size={20} className="flex-shrink-0" />
          <span className="font-medium">{error}</span>
        </div>
      )}

      {/* Quick Disposable Test Images Bar */}
      <div className="workstation-card p-6 lg:p-8 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <h2 className="text-[16px] font-bold text-[var(--text-primary)] flex items-center gap-2">
              <HardDrive size={18} className="text-[var(--primary-orange)]" />
              <span>Disposable Test Drive Images</span>
            </h2>
            <p className="text-[12.5px] text-[var(--text-secondary)]">
              Quickly pick or regenerate a safe test disk image in <code className="font-mono text-[var(--primary-orange)]">test_data/disposable</code> without touching real evidence.
            </p>
          </div>
          <button
            type="button"
            onClick={handleCreateSampleDrive}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[12.5px] font-semibold text-[var(--primary-orange)] transition-colors cursor-pointer"
          >
            <PlusCircle size={15} />
            <span>Generate Disposable Drive Image</span>
          </button>
        </div>

        {diskImages.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            {diskImages.map((img, idx) => {
              const sizeMb = img.size_mb != null ? img.size_mb : (img.size_bytes ? img.size_bytes / (1024 * 1024) : 0);
              const isSelected = selectedTarget.toLowerCase() === (img.path || '').toLowerCase();
              return (
                <div
                  key={img.path || idx}
                  onClick={() => {
                    setSelectedTarget(img.path);
                    setSanitizationOutput(null);
                    setError(null);
                  }}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between gap-3 ${
                    isSelected
                      ? 'bg-[var(--primary-orange)]/10 border-[var(--primary-orange)] text-[var(--text-primary)] font-medium ring-1 ring-[var(--primary-orange)]/30'
                      : 'bg-[var(--surface-secondary)] border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <Disc size={16} className={isSelected ? 'text-[var(--primary-orange)]' : 'text-[var(--text-muted)]'} />
                    <div className="truncate">
                      <div className="text-[13px] font-medium text-[var(--text-primary)] truncate">
                        {getFriendlyEvidenceName(img.name || '')}
                      </div>
                      <div className="text-[11px] font-mono text-[var(--text-muted)] truncate">
                        {img.name}
                      </div>
                    </div>
                  </div>
                  <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded-md bg-[var(--surface-primary)] border border-[var(--border)] text-[var(--text-secondary)] flex-shrink-0">
                    {sizeMb.toFixed(1)} MB
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Target & Method Selection Card */}
      <div className="workstation-card p-6 lg:p-8 space-y-6">
        <h2 className="text-[17px] font-bold text-[var(--text-primary)] flex items-center gap-2">
          <HardDrive size={18} className="text-[#C53030]" aria-hidden="true" focusable="false" />
          <span>Target Image & Overwrite Method</span>
        </h2>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
              Target Disk Image Path:
            </label>
            <input
              type="text"
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              disabled={isProcessing}
              placeholder="e.g. /path/to/disk_image.img or pick an image above"
              className="w-full h-12 bg-[var(--surface-secondary)] border border-[var(--border)] rounded-xl px-4 text-[13.5px] font-mono text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[#C53030] focus:ring-1 focus:ring-[#C53030]"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
              Sanitization Method:
            </label>
            <select
              value={selectedMethod}
              onChange={(e) => setSelectedMethod(e.target.value)}
              disabled={isProcessing}
              className="w-full h-12 bg-[var(--surface-secondary)] border border-[var(--border)] rounded-xl px-4 text-[13.5px] text-[var(--text-primary)] focus:outline-none focus:border-[#C53030]"
            >
              <option value="nist">NIST SP 800-88 Clear (Single Pass 0x00 + Head/Tail Zeroing)</option>
              <option value="dod">DoD 5220.22-M (3-Pass Fixed Pattern & Inversion)</option>
              <option value="random">Pseudorandom Sequence (High-Entropy Noise)</option>
            </select>
          </div>
        </div>

        <div className="pt-2">
          <button
            onClick={handleStartSanitization}
            disabled={isProcessing || !selectedTarget.trim()}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 h-12 rounded-xl bg-[#C53030] hover:bg-[#A82828] disabled:opacity-50 text-white text-[13.5px] font-semibold cursor-pointer shadow-sm transition-all"
          >
            <Lock size={16} aria-hidden="true" focusable="false" />
            <span>{isProcessing ? 'Sanitizing Disk Image...' : 'Authorize Drive Sanitization'}</span>
          </button>
        </div>
      </div>

      {/* Cryptographic Hash Verification Cards */}
      {(preHash || postHash) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div className="workstation-card p-6 space-y-2">
            <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs font-semibold uppercase">
              <Hash size={14} className="text-[var(--primary-orange)]" />
              <span>Pre-Sanitization SHA-256</span>
            </div>
            <div className="font-mono text-xs text-[var(--text-primary)] break-all bg-[var(--surface-secondary)] p-3 rounded-lg border border-[var(--border)]">
              {preHash || 'Calculating...'}
            </div>
          </div>

          <div className="workstation-card p-6 space-y-2">
            <div className="flex items-center gap-2 text-[#2E7D32] text-xs font-semibold uppercase">
              <CheckCircle2 size={14} />
              <span>Post-Sanitization SHA-256</span>
            </div>
            <div className="font-mono text-xs text-[var(--text-primary)] break-all bg-[var(--surface-secondary)] p-3 rounded-lg border border-[var(--border)]">
              {postHash || 'Pending completion...'}
            </div>
          </div>
        </div>
      )}

      {/* Console Output */}
      {sanitizationOutput && (
        <div className="workstation-card p-6 space-y-3 font-mono text-xs">
          <div className="flex items-center gap-2 text-[#2E7D32] border-b border-[var(--border)] pb-3 font-bold text-[13px]">
            <CheckCircle2 size={16} />
            <span>DRIVE SANITIZATION VERIFICATION LOG</span>
          </div>
          <pre className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed">
            {sanitizationOutput}
          </pre>
        </div>
      )}

      {/* Step 2: Password Verification Modal */}
      <PasswordVerificationModal
        isOpen={isPasswordModalOpen}
        onClose={() => setIsPasswordModalOpen(false)}
        onVerified={handlePasswordVerified}
        title="Verify Identity for Drive Sanitization"
        actionDescription="This operation permanently overwrites sectors on the selected disk image. To continue, verify your examiner password."
        actionName="DRIVE_SANITIZE"
        targetIdentifier={selectedTarget}
      />

      {/* Step 3: Two-step explicit confirmation modal */}
      <Modal
        isOpen={isConfirmOpen}
        onClose={() => setIsConfirmOpen(false)}
        title="Confirm Drive Sanitization"
        variant="danger"
        confirmText="Execute Sanitization"
        onConfirm={handleExecuteSanitization}
        isConfirmDisabled={!hasAcknowledgedConsequences || confirmationCode.trim().toUpperCase() !== 'PURGE DRIVE' || isProcessing}
        isLoading={isProcessing}
      >
        <div className="space-y-4 text-xs">
          <p className="text-[#C53030] font-bold text-[13px] font-sans">
            WARNING: Identity verified. This operation will permanently overwrite sectors on the target image.
          </p>
          <p className="text-[var(--text-primary)] font-mono break-all bg-[var(--surface-secondary)] p-3 rounded-xl border border-[var(--border)]">
            {selectedTarget}
          </p>

          {/* Consequence Acknowledgment Checkbox */}
          <div className="p-3.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2">
            <label className="flex items-start gap-2.5 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={hasAcknowledgedConsequences}
                onChange={(e) => setHasAcknowledgedConsequences(e.target.checked)}
                className="w-4 h-4 mt-0.5 rounded text-[#C53030] border-[var(--border)] focus:ring-0 cursor-pointer"
              />
              <span className="text-[12.5px] text-[var(--text-primary)] font-medium leading-tight">
                I understand that this operation permanently removes data and cannot be undone.
              </span>
            </label>
          </div>

          <div>
            <label className="block text-[12px] font-semibold text-[var(--text-primary)] mb-1.5 font-sans">
              Type <strong className="font-mono text-[#C53030]">PURGE DRIVE</strong> to confirm:
            </label>
            <input
              type="text"
              value={confirmationCode}
              onChange={(e) => setConfirmationCode(e.target.value)}
              placeholder="PURGE DRIVE"
              className="w-full bg-[var(--surface-secondary)] border border-[var(--border)] rounded-xl px-3.5 py-2.5 text-[13px] font-mono text-[var(--text-primary)] focus:outline-none focus:border-[#C53030]"
            />
          </div>
        </div>
      </Modal>
    </div>
  );
};
