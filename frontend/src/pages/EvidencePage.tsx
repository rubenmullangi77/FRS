import React, { useState, useEffect } from 'react';
import {
  FolderPlus,
  HardDrive,
  Hash,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Lock,
  FolderOpen,
  RefreshCw
} from 'lucide-react';
import { api } from '../services/api';
import { CaseMetadata, DiskImage } from '../types';
import { Modal } from '../components/Modal';
import { settingsService } from '../services/settings';
import { getFriendlyEvidenceName } from '../utils/evidenceNames';

interface EvidencePageProps {
  activeCase: CaseMetadata | null;
  onSelectCase: (c: CaseMetadata) => void;
}

export const EvidencePage: React.FC<EvidencePageProps> = ({ activeCase, onSelectCase }) => {
  const [cases, setCases] = useState<CaseMetadata[]>([]);
  const [diskImages, setDiskImages] = useState<DiskImage[]>([]);
  const [selectedImagePath, setSelectedImagePath] = useState<string>('');
  const [isHashing, setIsHashing] = useState<boolean>(false);
  const [computedHash, setComputedHash] = useState<{ sha256: string; md5: string; size_bytes: number } | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<{ verified: boolean; currentSha: string } | null>(null);
  const [examinerName, setExaminerName] = useState<string>(settingsService.getExaminerName());

  // New Case Modal State
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState<boolean>(false);
  const [newCaseId, setNewCaseId] = useState<string>('');
  const [newCaseName, setNewCaseName] = useState<string>('');
  const [newInvestigator, setNewInvestigator] = useState<string>(settingsService.getSettings().examinerName || '');
  const [newAgency, setNewAgency] = useState<string>(settingsService.getSettings().agencyName || '');
  const [caseCreationLoading, setCaseCreationLoading] = useState<boolean>(false);

  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    return settingsService.subscribe((s) => {
      setExaminerName(s.examinerName.trim() || 'Examiner not set');
    });
  }, []);

  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const loadData = async () => {
    setIsRefreshing(true);
    setError(null);
    try {
      const [casesRes, drivesRes] = await Promise.all([
        api.listCases(),
        api.getDrives()
      ]);
      setCases(casesRes.cases || []);
      setDiskImages(drivesRes.disk_images || []);
      if (!selectedImagePath && drivesRes.disk_images && drivesRes.disk_images.length > 0) {
        setSelectedImagePath(drivesRes.disk_images[0].path);
      }
    } catch (err: any) {
      setError('Unable to refresh data.');
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleComputeHash = async () => {
    if (!selectedImagePath) {
      setError('Please select an evidence file first.');
      return;
    }
    setIsHashing(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await api.computeHash(selectedImagePath);
      setComputedHash({
        sha256: res.sha256,
        md5: res.md5,
        size_bytes: res.size_bytes
      });
      setSuccessMsg('Cryptographic hash baseline calculated and verified.');
    } catch (err: any) {
      setError(err.message || 'Failed to compute SHA-256 hash');
    } finally {
      setIsHashing(false);
    }
  };

  const handleVerifyImmutability = async () => {
    if (!selectedImagePath || !computedHash) {
      setError('Compute initial hash before verifying immutability.');
      return;
    }
    setIsVerifying(true);
    setError(null);
    try {
      const res = await api.verifyEvidence(selectedImagePath, computedHash.sha256);
      setVerificationResult({
        verified: res.verified_unmodified,
        currentSha: res.current_sha256
      });
      if (res.verified_unmodified) {
        setSuccessMsg('Evidence Immutability Verified: SHA-256 baseline match confirmed.');
      } else {
        setError('Evidence Hash Mismatch! Target container appears modified.');
      }
    } catch (err: any) {
      setError(err.message || 'Verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleCreateCase = async () => {
    if (!newCaseId || !newCaseName) {
      setError('Case ID and Case Name are required.');
      return;
    }
    setCaseCreationLoading(true);
    setError(null);
    try {
      const res = await api.createCase({
        case_id: newCaseId,
        case_name: newCaseName,
        investigator_name: newInvestigator || examinerName,
        agency: newAgency || 'Forensics Lab'
      });
      const newCase: CaseMetadata = {
        case_id: newCaseId,
        case_name: newCaseName,
        investigator_name: newInvestigator || examinerName,
        agency: newAgency,
        workspace_path: res.workspace_path
      };
      setCases((prev) => [...prev, newCase]);
      onSelectCase(newCase);
      setIsNewCaseModalOpen(false);
      setSuccessMsg(`Case ${newCaseId} created successfully.`);
    } catch (err: any) {
      setError(err.message || 'Failed to create case');
    } finally {
      setCaseCreationLoading(false);
    }
  };

  return (
    <div className="p-8 lg:p-10 space-y-8 max-w-[1400px] mx-auto bg-[var(--bg-main)] min-h-full">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="page-title text-[30px] font-bold text-[var(--text-primary)] tracking-tight">
            Evidence Files
          </h1>
          <p className="text-[14px] text-[var(--text-secondary)] mt-1 leading-relaxed">
            Manage evidence disk images, calculate baseline hashes, and verify read-only integrity.
          </p>
        </div>

        <div className="flex items-center gap-2.5 self-start sm:self-auto">
          <button
            onClick={loadData}
            disabled={isRefreshing}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[12.5px] font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all cursor-pointer shadow-xs"
            title="Refresh evidence list"
          >
            <RefreshCw size={15} className={isRefreshing ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => setIsNewCaseModalOpen(true)}
            className="btn-primary h-[40px] px-4 text-[13px] font-semibold"
          >
            <FolderPlus size={15} aria-hidden="true" focusable="false" />
            <span>New Case</span>
          </button>
        </div>
      </div>

      {/* Read-Only Notice Callout */}
      <div className="workstation-card p-5 bg-[var(--surface)] border border-[var(--border)] rounded-[10px] flex items-start gap-4">
        <div className="w-9 h-9 rounded-lg bg-[#2E7D32]/10 border border-[#2E7D32]/20 flex items-center justify-center text-[#2E7D32] shrink-0">
          <Lock size={18} aria-hidden="true" focusable="false" />
        </div>
        <div className="space-y-1 text-xs">
          <span className="font-bold text-[var(--text-primary)] text-[13.5px]">
            Read-Only Evidence Protection:
          </span>
          <p className="text-[var(--text-secondary)] leading-relaxed text-[13px]">
            ForensiVault accesses all evidence files strictly in read-only mode. All file recovery and metadata extraction
            occur in memory and write output solely to the case recovery folder.
          </p>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px] flex items-center gap-3">
          <AlertTriangle size={18} className="flex-shrink-0" aria-hidden="true" focusable="false" />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div className="p-4 rounded-lg bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-[13px] flex items-center gap-3">
          <CheckCircle2 size={18} className="flex-shrink-0" aria-hidden="true" focusable="false" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Two Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-7">
        {/* Case Selection & Management */}
        <div className="workstation-card p-6 bg-[var(--surface)] border border-[var(--border)] rounded-[10px] space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="section-title text-[17px] font-semibold text-[var(--text-primary)] flex items-center gap-2">
              <FolderOpen size={16} className="text-[#D96B27]" aria-hidden="true" focusable="false" />
              Registered Cases
            </h2>
            <span className="text-[12px] text-[var(--text-secondary)]">{cases.length} Registered</span>
          </div>

          <div className="space-y-2.5 max-h-96 overflow-y-auto">
            {cases.length === 0 ? (
              <div className="p-6 text-center text-[13px] text-[var(--text-secondary)] border border-dashed border-[var(--border)] rounded-lg">
                No cases initialized yet. Click &quot;New Case&quot; above.
              </div>
            ) : (
              cases.map((c) => {
                const isActive = activeCase?.case_id === c.case_id;
                return (
                  <div
                    key={c.case_id}
                    onClick={() => onSelectCase(c)}
                    className={`p-3.5 rounded-lg border transition-all cursor-pointer flex items-center justify-between ${
                      isActive
                        ? 'bg-[#F4D5BF]/30 border-[#D96B27]'
                        : 'bg-[var(--surface-secondary)] border-[var(--border)] hover:border-[#D96B27]/40'
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[13.5px] font-bold text-[var(--text-primary)]">{c.case_id}</span>
                        <span className="text-[12.5px] text-[var(--text-secondary)]">— {c.case_name}</span>
                        {isActive && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/25">
                            Active
                          </span>
                        )}
                      </div>
                      <div className="text-[12px] text-[var(--text-secondary)] mt-0.5">
                        Examiner: {c.investigator_name || examinerName} • Agency: {c.agency || 'Forensics Lab'}
                      </div>
                    </div>
                    <button
                      type="button"
                      className={`text-[12px] px-3 py-1 rounded-md font-medium transition-colors ${
                        isActive
                          ? 'bg-[#D96B27] text-white'
                          : 'bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)]'
                      }`}
                    >
                      {isActive ? 'Loaded' : 'Select'}
                    </button>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Evidence Image Selector & Hashing */}
        <div className="workstation-card p-6 bg-[var(--surface)] border border-[var(--border)] rounded-[10px] space-y-4">
          <h2 className="section-title text-[17px] font-semibold text-[var(--text-primary)] flex items-center gap-2">
            <Hash size={16} className="text-[#D96B27]" aria-hidden="true" focusable="false" />
            Choose Evidence File & Verify Hash
          </h2>

          <div className="space-y-3.5">
            <div>
              <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
                Select Evidence Image:
              </label>
              <select
                value={selectedImagePath}
                onChange={(e) => {
                  setSelectedImagePath(e.target.value);
                  setComputedHash(null);
                  setVerificationResult(null);
                }}
                className="w-full bg-[var(--surface-secondary)] border border-[var(--border)] rounded-lg px-3 py-2 text-[13px] text-[var(--text-primary)] focus:outline-none focus:border-[#D96B27]"
              >
                {diskImages.map((img, idx) => {
                  const sizeMb = img.size_mb != null ? img.size_mb : (img.size_bytes ? img.size_bytes / (1024 * 1024) : 0);
                  return (
                    <option key={img.path || idx} value={img.path}>
                      {getFriendlyEvidenceName(img?.name || '')} ({img?.name || 'Image'}) — {sizeMb.toFixed(2)} MB
                    </option>
                  );
                })}
              </select>
            </div>

            <div>
              <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
                File Path:
              </label>
              <input
                type="text"
                value={selectedImagePath}
                onChange={(e) => {
                  setSelectedImagePath(e.target.value);
                  setComputedHash(null);
                  setVerificationResult(null);
                }}
                className="w-full bg-[var(--surface-secondary)] border border-[var(--border)] rounded-lg px-3 py-2 text-[12.5px] font-mono text-[var(--text-primary)] focus:outline-none focus:border-[#D96B27]"
              />
            </div>

            <div className="pt-2 flex flex-wrap items-center gap-2.5">
              <button
                onClick={handleComputeHash}
                disabled={isHashing || !selectedImagePath}
                className="btn-primary h-[38px] px-4 text-[13px] font-semibold"
              >
                <Hash size={14} className={isHashing ? 'animate-spin' : ''} aria-hidden="true" focusable="false" />
                <span>{isHashing ? 'Calculating...' : 'Calculate SHA-256 Hash'}</span>
              </button>

              {computedHash && (
                <button
                  onClick={handleVerifyImmutability}
                  disabled={isVerifying}
                  className="btn-secondary h-[38px] px-3.5 text-[12.5px]"
                >
                  <ShieldCheck size={14} className={isVerifying ? 'animate-spin text-[#2E7D32]' : 'text-[#2E7D32]'} aria-hidden="true" focusable="false" />
                  <span>Verify Immutability</span>
                </button>
              )}
            </div>

            {/* Computed Hash Box */}
            {computedHash && (
              <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2 font-mono text-[11.5px] pt-3">
                <div className="flex items-center justify-between text-[var(--text-secondary)]">
                  <span>SHA-256 Baseline:</span>
                  <span className="text-[var(--text-primary)] font-bold">{(computedHash.size_bytes / 1024).toFixed(1)} KB</span>
                </div>
                <div className="p-2 rounded bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] break-all font-semibold select-all">
                  {computedHash.sha256}
                </div>
                {computedHash.md5 && (
                  <div className="text-[11px] text-[var(--text-secondary)]">
                    MD5: <span className="text-[var(--text-primary)] select-all">{computedHash.md5}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* New Case Modal */}
      <Modal
        isOpen={isNewCaseModalOpen}
        onClose={() => setIsNewCaseModalOpen(false)}
        title="Create New Case"
        confirmText="Create Case"
        onConfirm={handleCreateCase}
        isLoading={caseCreationLoading}
      >
        <div className="space-y-4">
          <div>
            <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1">
              Case ID:
            </label>
            <input
              type="text"
              value={newCaseId}
              onChange={(e) => setNewCaseId(e.target.value)}
              placeholder="e.g. CASE-2026-001"
              className="w-full bg-[var(--surface-secondary)] border border-[var(--border)] rounded-lg px-3 py-2 text-[13px] font-mono text-[var(--text-primary)] focus:outline-none focus:border-[#D96B27]"
            />
          </div>
          <div>
            <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1">
              Case Name:
            </label>
            <input
              type="text"
              value={newCaseName}
              onChange={(e) => setNewCaseName(e.target.value)}
              placeholder="e.g. Digital Media Investigation"
              className="w-full bg-[var(--surface-secondary)] border border-[var(--border)] rounded-lg px-3 py-2 text-[13px] text-[var(--text-primary)] focus:outline-none focus:border-[#D96B27]"
            />
          </div>
          <div>
            <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1">
              Examiner Name:
            </label>
            <input
              type="text"
              value={newInvestigator}
              onChange={(e) => setNewInvestigator(e.target.value)}
              placeholder={examinerName}
              className="w-full bg-[var(--surface-secondary)] border border-[var(--border)] rounded-lg px-3 py-2 text-[13px] text-[var(--text-primary)] focus:outline-none focus:border-[#D96B27]"
            />
          </div>
        </div>
      </Modal>
    </div>
  );
};
