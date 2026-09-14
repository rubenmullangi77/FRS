import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  HardDrive,
  Hash,
  ShieldAlert,
  ShieldCheck,
  Lock,
  RefreshCw,
  Server,
  Usb
} from 'lucide-react';
import { api } from '../services/api';
import { SanitizationDriveItem } from '../types';
import { Modal } from '../components/Modal';
import { PasswordVerificationModal } from '../components/PasswordVerificationModal';

export const DriveSanitizationPage: React.FC = () => {
  const [drives, setDrives] = useState<SanitizationDriveItem[]>([]);
  const [selectedDrive, setSelectedDrive] = useState<SanitizationDriveItem | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<string>('nist');
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [sanitizationOutput, setSanitizationOutput] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Pre-and-post Hashes
  const [preHash, setPreHash] = useState<string>('');
  const [postHash, setPostHash] = useState<string>('');

  // Password Verification Modal
  const [isPasswordModalOpen, setIsPasswordModalOpen] = useState<boolean>(false);

  // Explicit confirmation modal
  const [isConfirmOpen, setIsConfirmOpen] = useState<boolean>(false);
  const [hasAcknowledgedConsequences, setHasAcknowledgedConsequences] = useState<boolean>(false);
  const [confirmationCode, setConfirmationCode] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const loadDrives = async () => {
    setIsRefreshing(true);
    setError(null);
    try {
      const res = await api.getSanitizationDrives();
      const driveList = res.drives || [];
      setDrives(driveList);
      if (driveList.length > 0) {
        setSelectedDrive((prev) => {
          if (prev) {
            const match = driveList.find((d) => d.id === prev.id);
            if (match) return match;
          }
          const readyOne = driveList.find((d) => d.can_sanitize);
          return readyOne || driveList[0];
        });
      } else {
        setSelectedDrive(null);
      }
    } catch {
      setError('Unable to detect physical drives or mounted storage volumes.');
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadDrives();
  }, []);

  const handleStartSanitization = () => {
    if (!selectedDrive) {
      setError('Please select a target storage device.');
      return;
    }
    if (!selectedDrive.can_sanitize) {
      setError(`Sanitization method unavailable for this device: ${selectedDrive.reason}`);
      return;
    }
    setError(null);
    setIsPasswordModalOpen(true);
  };

  const handlePasswordVerified = () => {
    setIsPasswordModalOpen(false);
    setHasAcknowledgedConsequences(false);
    setConfirmationCode('');
    setIsConfirmOpen(true);
  };

  const handleExecuteSanitization = async () => {
    if (!selectedDrive) return;
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
      const targetPath = selectedDrive.device_path;
      const res = await api.sanitizeDrive(targetPath, true, selectedMethod);
      setSanitizationOutput(res.output || res.message);
      if (res.sha256) {
        setPostHash(res.sha256);
      }

      setIsConfirmOpen(false);
      setConfirmationCode('');
      setHasAcknowledgedConsequences(false);
      setSuccessMessage(`Drive sanitization completed: ${selectedDrive.name}`);
      await loadDrives();
    } catch (err: any) {
      setError(err.message || 'Drive sanitization failed');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="p-6 lg:p-10 space-y-8 max-w-6xl mx-auto w-full min-w-0 min-h-full pb-24 box-border">
      {/* Header */}
      <div className="pb-5 border-b border-[var(--border-subtle)] flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl lg:text-3xl font-bold text-[var(--text-primary)] tracking-tight">
              Secure Drive Eraser
            </h1>
            <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-[var(--surface-secondary)] text-[#C53030] border border-[var(--border)]">
              NIST SP 800-88 / DoD 5220.22-M
            </span>
          </div>
          <p className="text-sm text-[var(--text-secondary)] mt-1.5 leading-relaxed max-w-3xl">
            Detect real Windows physical storage drives, NVMe/SATA SSDs, and USB storage devices. Sanitize authorized external media with forensic verification while protecting host operating system volumes.
          </p>
        </div>

        <button
          type="button"
          onClick={loadDrives}
          disabled={isRefreshing || isProcessing}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-xs font-semibold text-[var(--text-primary)] transition-all cursor-pointer shadow-xs"
          title="Refresh physical storage devices"
        >
          <RefreshCw size={15} className={isRefreshing ? 'animate-spin' : ''} />
          <span>Refresh Storage Devices</span>
        </button>
      </div>

      {/* Safety Advisory */}
      <div className="p-5 rounded-2xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2">
        <div className="flex items-center gap-2 text-[#C53030] font-bold text-xs uppercase tracking-wider">
          <ShieldAlert size={18} />
          <span>Storage Media Sanitization Protocol</span>
        </div>
        <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
          Sanitization permanently destroys all user data and filesystem structures. Physical host OS volumes (<code className="font-mono text-[var(--text-primary)]">C:\ Windows</code>, active EFI Boot partitions, and the running ForensiVault application volume) are strictly protected by <code className="font-mono text-[var(--text-primary)]">SystemProtectionGuard</code>.
        </p>
        <div className="text-[#2E7D32] text-xs font-semibold pt-1 flex items-center gap-2">
          <ShieldCheck size={16} />
          <span>Real Windows Storage Detection Active: Only genuine storage devices and mounted partitions are listed.</span>
        </div>
      </div>

      {/* Success Alert */}
      {successMessage && (
        <div className="p-4 rounded-2xl bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-sm flex items-center gap-3 shadow-xs">
          <CheckCircle2 size={20} className="flex-shrink-0" />
          <span className="font-semibold">{successMessage}</span>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="p-4 rounded-2xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-sm flex items-center gap-3 shadow-xs">
          <AlertTriangle size={20} className="flex-shrink-0" />
          <span className="font-medium">{error}</span>
        </div>
      )}

      {/* Device List Table / Cards */}
      <div className="workstation-card p-5 lg:p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-3">
          <div>
            <h2 className="text-base font-bold text-[var(--text-primary)] flex items-center gap-2">
              <HardDrive size={18} className="text-[var(--primary-orange)]" />
              <span>Detected Storage Devices & Volumes</span>
            </h2>
            <p className="text-xs text-[var(--text-secondary)] mt-0.5">
              Select an authorized physical disk or mounted partition to configure sanitization.
            </p>
          </div>
          <span className="text-xs font-mono text-[var(--text-muted)] bg-[var(--surface-secondary)] px-2.5 py-1 rounded-md border border-[var(--border)]">
            {drives.length} Detected
          </span>
        </div>

        {drives.length === 0 ? (
          <div className="p-8 text-center text-xs text-[var(--text-muted)] border border-dashed border-[var(--border)] rounded-xl">
            {isRefreshing ? 'Scanning storage bus and volumes...' : 'No storage devices detected. Click "Refresh Storage Devices" to rescan.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="table-fixed w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[var(--border)] text-[var(--text-secondary)] uppercase tracking-wider font-mono text-[11px]">
                  <th className="py-2.5 px-3 w-[28%]">Device / Volume</th>
                  <th className="py-2.5 px-3 w-[15%]">Type / Bus</th>
                  <th className="py-2.5 px-3 w-[15%]">Capacity</th>
                  <th className="py-2.5 px-3 w-[15%]">Filesystem</th>
                  <th className="py-2.5 px-3 w-[15%]">Status</th>
                  <th className="py-2.5 px-3 w-[12%] text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {drives.map((d) => {
                  const isSelected = selectedDrive?.id === d.id;
                  const isProtected = d.is_system_protected || !d.can_sanitize;

                  return (
                    <tr
                      key={d.id}
                      onClick={() => {
                        setSelectedDrive(d);
                        setSanitizationOutput(null);
                        setError(null);
                      }}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-[var(--primary-orange)]/10 font-medium'
                          : 'hover:bg-[var(--surface-hover)]'
                      }`}
                    >
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-2.5 min-w-0">
                          {d.is_removable ? (
                            <Usb size={16} className="text-[var(--primary-orange)] shrink-0" />
                          ) : d.device_type === 'PHYSICAL_DISK' ? (
                            <Server size={16} className="text-[var(--text-muted)] shrink-0" />
                          ) : (
                            <HardDrive size={16} className="text-[var(--text-muted)] shrink-0" />
                          )}
                          <div className="truncate">
                            <div className="text-xs font-semibold text-[var(--text-primary)] truncate">
                              {d.name}
                            </div>
                            <div className="text-[11px] font-mono text-[var(--text-muted)] truncate">
                              {d.device_path}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="font-mono text-xs text-[var(--text-secondary)]">
                          {d.bus_type} ({d.media_type})
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-xs text-[var(--text-primary)] font-semibold">
                        {d.capacity_str}
                      </td>
                      <td className="py-3 px-3 font-mono text-xs text-[var(--text-secondary)]">
                        {d.filesystem || (d.partitions_count ? `${d.partitions_count} partition(s)` : 'Raw Disk')}
                      </td>
                      <td className="py-3 px-3">
                        {isProtected ? (
                          <span
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-[#C53030]/10 text-[#C53030] border border-[#C53030]/20 truncate"
                            title={d.reason}
                          >
                            <Lock size={12} className="shrink-0" />
                            <span className="truncate">Protected</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20">
                            <CheckCircle2 size={12} className="shrink-0" />
                            <span>Selectable</span>
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <span
                          className={`text-xs font-semibold px-2.5 py-1 rounded-md transition-colors ${
                            isSelected
                              ? 'bg-[var(--primary-orange)] text-white'
                              : 'bg-[var(--surface-secondary)] text-[var(--text-secondary)] border border-[var(--border)]'
                          }`}
                        >
                          {isSelected ? 'Active' : 'Select'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Selected Target Details & Sanitization Configuration */}
      {selectedDrive && (
        <div className="workstation-card p-6 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border)] pb-4">
            <div>
              <h2 className="text-base font-bold text-[var(--text-primary)] flex items-center gap-2">
                <HardDrive size={18} className="text-[#C53030]" />
                <span>Selected Target: {selectedDrive.name}</span>
              </h2>
              <p className="text-xs font-mono text-[var(--text-secondary)] mt-0.5">
                Path: {selectedDrive.device_path} | Media: {selectedDrive.media_type} | Bus: {selectedDrive.bus_type} | Capacity: {selectedDrive.capacity_str}
              </p>
            </div>

            {selectedDrive.can_sanitize ? (
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/30">
                Ready For Sanitization
              </span>
            ) : (
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-[#C53030]/10 text-[#C53030] border border-[#C53030]/30">
                LOCKED: System Protected
              </span>
            )}
          </div>

          {!selectedDrive.can_sanitize ? (
            <div className="p-4 rounded-xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-xs space-y-1">
              <div className="font-bold flex items-center gap-1.5 text-sm">
                <ShieldAlert size={16} />
                <span>Sanitization method unavailable for this device</span>
              </div>
              <p className="text-xs leading-relaxed">
                {selectedDrive.reason}. ForensiVault SystemProtectionGuard prohibits destructive write operations to this storage source to safeguard operating system integrity.
              </p>
            </div>
          ) : (
            <div className="space-y-5">
              <div className="space-y-2">
                <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
                  Sanitization Standard / Overwrite Method:
                </label>
                <select
                  value={selectedMethod}
                  onChange={(e) => setSelectedMethod(e.target.value)}
                  disabled={isProcessing}
                  className="w-full h-11 bg-[var(--surface-secondary)] border border-[var(--border)] rounded-xl px-4 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[#C53030]"
                >
                  <option value="nist">NIST SP 800-88 Rev. 1 Clear (Single-Pass Zero Fill + Verification)</option>
                  <option value="dod">DoD 5220.22-M (3-Pass Character/Complement Overwrite)</option>
                  <option value="random">Pseudorandom Sequence (High-Entropy Noise)</option>
                </select>
              </div>

              <div>
                <button
                  type="button"
                  onClick={handleStartSanitization}
                  disabled={isProcessing}
                  className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 h-11 rounded-xl bg-[#C53030] hover:bg-[#A82828] text-white text-xs font-semibold cursor-pointer shadow-sm transition-all"
                >
                  <Lock size={15} />
                  <span>Authorize Drive Sanitization</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Hash Verification Cards */}
      {(preHash || postHash) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="workstation-card p-5 space-y-2">
            <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs font-semibold uppercase">
              <Hash size={14} className="text-[var(--primary-orange)]" />
              <span>Pre-Sanitization Digest</span>
            </div>
            <div className="font-mono text-xs text-[var(--text-primary)] break-all bg-[var(--surface-secondary)] p-3 rounded-lg border border-[var(--border)]">
              {preHash || 'Calculating...'}
            </div>
          </div>

          <div className="workstation-card p-5 space-y-2">
            <div className="flex items-center gap-2 text-[#2E7D32] text-xs font-semibold uppercase">
              <CheckCircle2 size={14} />
              <span>Post-Sanitization Digest</span>
            </div>
            <div className="font-mono text-xs text-[var(--text-primary)] break-all bg-[var(--surface-secondary)] p-3 rounded-lg border border-[var(--border)]">
              {postHash || 'Pending completion...'}
            </div>
          </div>
        </div>
      )}

      {/* Output Console */}
      {sanitizationOutput && (
        <div className="workstation-card p-5 space-y-3 font-mono text-xs">
          <div className="flex items-center gap-2 text-[#2E7D32] border-b border-[var(--border)] pb-2 font-bold text-xs">
            <CheckCircle2 size={15} />
            <span>DRIVE SANITIZATION AUDIT LOG</span>
          </div>
          <pre className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed overflow-x-auto">
            {sanitizationOutput}
          </pre>
        </div>
      )}

      {/* Step 1: Password Verification Modal */}
      <PasswordVerificationModal
        isOpen={isPasswordModalOpen}
        onClose={() => setIsPasswordModalOpen(false)}
        onVerified={handlePasswordVerified}
        title="Verify Identity for Drive Sanitization"
        actionDescription="This operation permanently overwrites sectors on the selected storage device. To continue, verify your examiner password."
        actionName="DRIVE_SANITIZE"
        targetIdentifier={selectedDrive?.device_path}
      />

      {/* Step 2: Explicit Confirmation Modal */}
      <Modal
        isOpen={isConfirmOpen}
        onClose={() => setIsConfirmOpen(false)}
        title="Confirm Storage Media Sanitization"
        variant="danger"
        confirmText="Execute Sanitization"
        onConfirm={handleExecuteSanitization}
        isConfirmDisabled={!hasAcknowledgedConsequences || confirmationCode.trim().toUpperCase() !== 'PURGE DRIVE' || isProcessing}
        isLoading={isProcessing}
      >
        <div className="space-y-4 text-xs">
          <p className="text-[#C53030] font-bold text-xs font-sans">
            WARNING: Identity verified. This operation will permanently overwrite all sectors on the selected target.
          </p>
          <div className="p-3 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1 font-mono">
            <div className="text-[var(--text-primary)] font-bold">{selectedDrive?.name}</div>
            <div className="text-[var(--text-muted)] text-[11px]">{selectedDrive?.device_path}</div>
            <div className="text-[var(--text-secondary)] text-[11px]">Capacity: {selectedDrive?.capacity_str}</div>
          </div>

          <div className="p-3.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)]">
            <label className="flex items-start gap-2.5 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={hasAcknowledgedConsequences}
                onChange={(e) => setHasAcknowledgedConsequences(e.target.checked)}
                className="w-4 h-4 mt-0.5 rounded text-[#C53030] border-[var(--border)] focus:ring-0 cursor-pointer"
              />
              <span className="text-xs text-[var(--text-primary)] font-medium leading-tight">
                I understand that this operation permanently removes data and cannot be undone.
              </span>
            </label>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1.5 font-sans">
              Type <strong className="font-mono text-[#C53030]">PURGE DRIVE</strong> to confirm:
            </label>
            <input
              type="text"
              value={confirmationCode}
              onChange={(e) => setConfirmationCode(e.target.value)}
              placeholder="PURGE DRIVE"
              className="w-full bg-[var(--surface-secondary)] border border-[var(--border)] rounded-xl px-3.5 py-2.5 text-xs font-mono text-[var(--text-primary)] focus:outline-none focus:border-[#C53030]"
            />
          </div>
        </div>
      </Modal>
    </div>
  );
};
