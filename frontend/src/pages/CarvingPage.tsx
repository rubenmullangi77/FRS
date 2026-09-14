import React, { useState, useEffect } from 'react';
import {
  Binary,
  HardDrive,
  Play,
  CheckCircle2,
  AlertTriangle,
  Search,
  Layers,
  ArrowRight,
  ShieldCheck,
  FileText,
  RefreshCw,
  FolderOpen,
  Upload,
  X,
  Plus,
  Lock,
  Info
} from 'lucide-react';
import { api } from '../services/api';
import { DiskImage, CarvedFile, CarveJob, CaseMetadata, PrivilegeStatusResponse } from '../types';
import { ProgressBar } from '../components/ProgressBar';
import { FileDetailsDrawer } from '../components/FileDetailsDrawer';
import { getFriendlyEvidenceName } from '../utils/evidenceNames';

interface CarvingPageProps {
  activeCase: CaseMetadata | null;
}

export const CarvingPage: React.FC<CarvingPageProps> = ({ activeCase }) => {
  const [diskImages, setDiskImages] = useState<DiskImage[]>([]);
  const [selectedImage, setSelectedImage] = useState<string>('');
  const [isCarving, setIsCarving] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [stage, setStage] = useState<string>('Ready');
  const [carvedFiles, setCarvedFiles] = useState<CarvedFile[]>([]);
  const [selectedFileForDrawer, setSelectedFileForDrawer] = useState<CarvedFile | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Evidence Import State
  const [isImportModalOpen, setIsImportModalOpen] = useState<boolean>(false);
  const [manualImportPath, setManualImportPath] = useState<string>('');
  const [isImporting, setIsImporting] = useState<boolean>(false);
  const [importSuccessMsg, setImportSuccessMsg] = useState<string | null>(null);

  // Recovery Options (Simplified Filters)
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [minConfidence, setMinConfidence] = useState<number>(0);
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Fragment Recovery State
  const [isReconstructing, setIsReconstructing] = useState<boolean>(false);
  const [fragmentResult, setFragmentResult] = useState<any | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  // Administrative Privilege State
  const [privileges, setPrivileges] = useState<PrivilegeStatusResponse | null>(null);
  const [isRelaunchingElevated, setIsRelaunchingElevated] = useState<boolean>(false);

  const handleRelaunchElevated = async (targetSource?: string) => {
    setIsRelaunchingElevated(true);
    setError(null);
    try {
      const src = targetSource || selectedImage;
      const res = await api.relaunchElevated({
        targetSource: src,
        caseId: activeCase?.case_id || 'CASE-2026-001',
        currentRoute: 'carving'
      });
      if (res.cancelled) {
        setError(res.message || 'Administrator elevation was cancelled or declined. ForensiVault will continue running as Standard User.');
      } else if (res.success) {
        setImportSuccessMsg(res.message || 'Windows Administrator elevation requested. Please confirm the UAC prompt on your screen.');
      } else {
        setError(res.message || 'Failed to request elevation.');
      }
    } catch (err: any) {
      setError(`Failed to request elevation: ${err.message}`);
    } finally {
      setIsRelaunchingElevated(false);
    }
  };


  const handleRefresh = async () => {
    setIsRefreshing(true);
    setError(null);
    try {
      const [res, privRes] = await Promise.all([
        api.getDrives(),
        api.getSystemPrivileges().catch(() => null)
      ]);
      const images = res.disk_images || [];
      setDiskImages(images);
      if (privRes) setPrivileges(privRes);
      // Explicit requirement: Evidence list must start empty. Never auto-select.
    } catch (err: any) {
      setError('Unable to refresh data.');
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    handleRefresh();
  }, []);

  const handleImportFilePath = async (filePath: string) => {
    const trimmed = filePath.trim();
    if (!trimmed) {
      setError('Please specify a valid evidence file path.');
      return;
    }
    const lower = trimmed.toLowerCase();
    const validExtensions = ['.img', '.dd', '.raw', '.bin'];
    const hasValidExt = validExtensions.some((ext) => lower.endsWith(ext));
    if (!hasValidExt) {
      setError(`Invalid evidence image format. Supported formats: ${validExtensions.join(', ')}`);
      return;
    }

    console.log(`[Evidence Import]\nSelected Path: ${trimmed}`);

    setIsImporting(true);
    setError(null);
    try {
      const imported = await api.importEvidence({
        source_path: trimmed,
        case_id: activeCase?.case_id || 'DEFAULT_CASE',
        evidence_id: `EV-${Date.now()}`
      });

      const res = await api.getDrives();
      const images = res.disk_images || [];
      const cleanFileName = trimmed.replace(/^.*[\\\/]/, '');
      const formatStr = trimmed.split('.').pop()?.toUpperCase() || 'IMG';
      const szBytes = imported.size_bytes || 0;
      const szMb = szBytes ? Math.round((szBytes / (1024 * 1024)) * 100) / 100 : 0;

      const newContainer: DiskImage = {
        name: imported.name || cleanFileName,
        path: trimmed,
        size_bytes: szBytes,
        size_mb: szMb,
        format: formatStr,
        is_safe: true
      };

      const filtered = images.filter((img) => img.path.toLowerCase() !== trimmed.toLowerCase());
      setDiskImages([newContainer, ...filtered]);
      setSelectedImage(trimmed);
      setImportSuccessMsg(`Evidence container imported: ${imported.name || cleanFileName}`);
      setIsImportModalOpen(false);
      setManualImportPath('');
    } catch (err: any) {
      setError(err.message || 'Failed to import evidence container');
    } finally {
      setIsImporting(false);
    }
  };

  const handleOpenImportDialog = async () => {
    try {
      const desktopApi = (window as any).forensiVaultDesktop;
      if (desktopApi && typeof desktopApi.selectEvidenceFile === 'function') {
        const selected = await desktopApi.selectEvidenceFile();
        if (selected) {
          await handleImportFilePath(selected);
          return;
        }
      }
    } catch (err) {
      console.warn('Native dialog unavailable or failed, falling back to manual import:', err);
    }
    setIsImportModalOpen(true);
  };

  const handleStartCarving = async () => {
    if (!selectedImage) {
      setError('No evidence image selected. Import a forensic image before starting recovery.');
      return;
    }
    console.log(`[Recovery Request]\nSource Path: ${selectedImage}`);
    setIsCarving(true);
    setError(null);
    setProgress(10);
    setStage('Scanning evidence for file signatures...');
    setCarvedFiles([]);

    try {
      const startRes = await api.startCarving(selectedImage, activeCase?.workspace_path);
      const directFiles = startRes.discovered_files || startRes.carved_files || startRes.files || [];
      if (directFiles.length > 0) {
        setCarvedFiles(directFiles);
        setProgress(100);
        setStage(`Scan completed: ${directFiles.length} recovered files found.`);
        return;
      }

      const jobId = startRes.job_id;
      if (!jobId) {
        setProgress(100);
        setStage('Scan completed: 0 files found.');
        return;
      }

      let completed = false;
      let pollAttempts = 0;
      while (!completed && pollAttempts < 60) {
        pollAttempts++;
        await new Promise((resolve) => setTimeout(resolve, 800));
        const job: CarveJob = await api.getJob(jobId);
        setProgress(job.progress ?? 50);
        setStage(job.stage ?? 'Scanning...');
        if (job.discovered_files && job.discovered_files.length > 0) {
          setCarvedFiles(job.discovered_files);
        }

        if (job.status === 'COMPLETED') {
          completed = true;
          setProgress(100);
          setStage(`Scan completed: ${job.files_carved ?? (job.discovered_files?.length || 0)} recovered files found.`);
          if (job.discovered_files) {
            setCarvedFiles(job.discovered_files);
          }
        } else if (job.status === 'FAILED') {
          completed = true;
          setError(job.error || 'File recovery scan failed');
        }
      }
    } catch (err: any) {
      setError(err.message || 'Failed to execute file recovery');
    } finally {
      setIsCarving(false);
    }
  };

  const handleReconstructFragments = async () => {
    if (!selectedImage) {
      setError('Please select an evidence file first.');
      return;
    }
    setIsReconstructing(true);
    setError(null);
    setFragmentResult(null);
    try {
      const res = await api.reconstructFragments({
        image_path: selectedImage,
        file_type: 'JPEG',
        case_id: activeCase?.case_id
      });
      setFragmentResult(res);
    } catch (err: any) {
      setError(err.message || 'Fragment recovery failed');
    } finally {
      setIsReconstructing(false);
    }
  };

  // Filter categorized items
  const filteredFiles = carvedFiles.filter((file) => {
    const ext = (file?.extension || '').toLowerCase();
    let matchesCategory = true;
    if (categoryFilter === 'IMAGES') {
      matchesCategory = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].includes(ext);
    } else if (categoryFilter === 'DOCUMENTS') {
      matchesCategory = ['pdf', 'docx', 'doc', 'txt', 'rtf', 'xlsx'].includes(ext);
    } else if (categoryFilter === 'VIDEOS') {
      matchesCategory = ['mp4', 'avi', 'mov', 'mkv'].includes(ext);
    } else if (categoryFilter === 'ARCHIVES') {
      matchesCategory = ['zip', 'rar', '7z', 'tar', 'gz'].includes(ext);
    }

    const matchesConfidence = (file?.confidence_score ?? 0) >= minConfidence;
    const search = (searchTerm || '').toLowerCase();
    const matchesSearch =
      !search ||
      (file?.file_type && file.file_type.toLowerCase().includes(search)) ||
      (file?.extension && file.extension.toLowerCase().includes(search)) ||
      (file?.offset_hex && file.offset_hex.toLowerCase().includes(search)) ||
      `#${file?.id ?? ''}`.includes(search);

    return matchesCategory && matchesConfidence && matchesSearch;
  });

  const getConfidenceBadge = (score: number) => {
    let color = 'bg-[#2E7D32]/10 text-[#2E7D32] border-[#2E7D32]/30';
    if (score < 60) color = 'bg-[#C53030]/10 text-[#C53030] border-[#C53030]/30';
    else if (score < 80) color = 'bg-[#B45309]/10 text-[#B45309] border-[#B45309]/30';

    return (
      <span className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold border ${color}`}>
        {(score ?? 0).toFixed(0)}%
      </span>
    );
  };

  return (
    <div className="p-8 lg:p-10 space-y-8 max-w-[1400px] mx-auto bg-[var(--bg-main)] min-h-full">
      {/* Page Title & Subtitle */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="page-title text-[30px] font-bold text-[var(--text-primary)] tracking-tight">
              File Recovery from Raw Data
            </h1>
            <span className="text-[12px] font-mono px-2 py-0.5 rounded bg-[#F4D5BF] text-[#B9541D] font-semibold border border-[#D96B27]/25">
              Signature Carving
            </span>
          </div>
          <p className="text-[14px] text-[var(--text-secondary)] mt-1.5 leading-relaxed">
            Search an evidence image for deleted or identifiable files without modifying the original evidence.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Operation Mode Badge */}
          <span className="px-3 py-1.5 rounded-lg text-xs font-bold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/30 flex items-center gap-1.5 shadow-xs">
            <ShieldCheck size={14} className="text-[#2E7D32]" />
            <span>Operation Mode: READ-ONLY</span>
          </span>

          {/* Privilege Status Badge */}
          {privileges?.is_elevated ? (
            <span className="px-3 py-1.5 rounded-lg text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 shadow-xs">
              <CheckCircle2 size={14} className="text-emerald-400" />
              <span>Privilege: Administrator (Elevated)</span>
            </span>
          ) : (
            <div className="flex items-center gap-1.5">
              <span className="px-3 py-1.5 rounded-lg text-xs font-bold bg-amber-500/10 text-amber-300 border border-amber-500/30 flex items-center gap-1.5 shadow-xs">
                <AlertTriangle size={14} className="text-amber-400" />
                <span>Privilege: Standard User (Restricted)</span>
              </span>
              <button
                type="button"
                onClick={() => handleRelaunchElevated()}
                disabled={isRelaunchingElevated}
                className="px-3 py-1.5 rounded-lg text-xs font-bold bg-[var(--primary-orange)] text-white hover:opacity-90 transition-all flex items-center gap-1 cursor-pointer disabled:opacity-50 shadow-xs"
                title="Restart ForensiVault as Administrator via Windows UAC"
              >
                <Lock size={12} />
                <span>{isRelaunchingElevated ? 'Restarting...' : 'Restart as Admin'}</span>
              </button>
            </div>
          )}

          <button
            type="button"
            aria-label="Refresh"
            onClick={handleRefresh}
            disabled={isRefreshing || isCarving}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[12.5px] font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all cursor-pointer shadow-xs"
            title="Refresh evidence drives"
          >
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <RefreshCw size={15} className={isRefreshing ? 'animate-spin' : ''} aria-hidden="true" focusable="false" role="presentation" />
            </span>
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {importSuccessMsg && (
        <div className="p-3.5 rounded-lg bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-[13px] flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <CheckCircle2 size={16} aria-hidden="true" focusable="false" role="presentation" />
            </span>
            <span>{importSuccessMsg}</span>
          </div>
          <button
            type="button"
            aria-label="Dismiss alert"
            onClick={() => setImportSuccessMsg(null)}
            className="text-[#2E7D32] hover:opacity-75 cursor-pointer p-0.5"
          >
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <X size={15} aria-hidden="true" focusable="false" role="presentation" />
            </span>
          </button>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px] space-y-2">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                <AlertTriangle size={18} aria-hidden="true" focusable="false" role="presentation" />
              </span>
              <span className="font-semibold">{error}</span>
            </div>
            {(error.toLowerCase().includes('access denied') || error.toLowerCase().includes('administrator') || error.toLowerCase().includes('error 5')) && (
              <button
                type="button"
                onClick={() => handleRelaunchElevated()}
                disabled={isRelaunchingElevated}
                className="px-3 py-1.5 rounded-lg text-xs font-bold bg-[var(--primary-orange)] text-white hover:opacity-90 flex items-center gap-1 cursor-pointer disabled:opacity-50 flex-shrink-0"
              >
                <Lock size={12} />
                <span>Restart as Administrator</span>
              </button>
            )}
          </div>
          {(error.toLowerCase().includes('access denied') || error.toLowerCase().includes('administrator') || error.toLowerCase().includes('error 5')) && (
            <div className="text-xs text-[var(--text-secondary)] pl-7">
              Direct physical sector-level access to Windows storage devices requires elevation. Forensic images (.img, .dd, .raw) do not require elevation.
            </div>
          )}
        </div>
      )}


      {/* SECTION 1: Choose Evidence File */}
      <div className="workstation-card p-6 lg:p-7 bg-[var(--surface)] border border-[var(--border)] space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="section-title text-[18px] font-semibold text-[var(--text-primary)]">
              Choose Evidence File
            </h2>
            <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
              Select an evidence container to inspect. All analysis operates strictly in read-only mode.
            </p>
          </div>
          <button
            type="button"
            aria-label="Import / Select Evidence Image"
            onClick={handleOpenImportDialog}
            disabled={isCarving || isImporting}
            className="btn-primary h-[38px] px-4 text-[13px] font-medium flex items-center gap-2 cursor-pointer shadow-xs"
            title="Browse or import raw disk image (.img, .dd, .raw, .bin)"
          >
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <FolderOpen size={16} aria-hidden="true" focusable="false" role="presentation" />
            </span>
            {' '}
            <span>Import / Select Evidence Image</span>
          </button>
        </div>

        {/* Evidence File Cards List or Empty State */}
        {!selectedImage ? (
          <div className="p-8 rounded-xl border border-dashed border-[var(--border)] bg-[var(--surface-secondary)]/40 text-center space-y-3">
            <div className="w-12 h-12 mx-auto rounded-full bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-secondary)]">
              <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                <HardDrive size={24} aria-hidden="true" focusable="false" role="presentation" />
              </span>
            </div>
            <div>
              <h3 className="text-[15px] font-bold text-[var(--text-primary)]">No evidence image selected</h3>
              <p className="text-[12.5px] text-[var(--text-secondary)] max-w-md mx-auto mt-1">
                No evidence image selected. Import a forensic image (<code className="font-mono text-[11px] bg-[var(--surface)] px-1 py-0.5 rounded">.img</code>, <code className="font-mono text-[11px] bg-[var(--surface)] px-1 py-0.5 rounded">.dd</code>, <code className="font-mono text-[11px] bg-[var(--surface)] px-1 py-0.5 rounded">.raw</code>, <code className="font-mono text-[11px] bg-[var(--surface)] px-1 py-0.5 rounded">.bin</code>) before starting recovery.
              </p>
            </div>
            <button
              type="button"
              aria-label="Import / Select Evidence Image"
              onClick={handleOpenImportDialog}
              className="btn-primary h-[36px] px-4 text-[12.5px] font-medium inline-flex items-center gap-2 cursor-pointer shadow-xs"
            >
              <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                <Plus size={15} aria-hidden="true" focusable="false" role="presentation" />
              </span>
              {' '}
              <span>Import / Select Evidence Image</span>
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 max-h-72 overflow-y-auto pr-1">
            {diskImages.filter((img) => img.path === selectedImage || !img.path.toLowerCase().includes('test_data')).map((img, idx) => {
              const isSelected = selectedImage === img.path;
              const cleanFileName = img.name || img.path.replace(/^.*[\\\/]/, '');
              const formatStr = img.format || cleanFileName.split('.').pop()?.toUpperCase() || 'IMG';
              return (
                <div
                  key={idx}
                  onClick={() => !isCarving && setSelectedImage(img.path)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer flex flex-col justify-between space-y-3 ${
                    isSelected
                      ? 'bg-[#F4D5BF]/40 border-[#D96B27] ring-1 ring-[#D96B27]'
                      : 'bg-[var(--surface-secondary)] border-[var(--border)] hover:border-[#D96B27]/40'
                  } ${isCarving ? 'opacity-60 cursor-not-allowed' : ''}`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-[11px] font-mono text-[var(--text-secondary)] uppercase tracking-wider">
                        Evidence Image
                      </div>
                      <div className="text-[14px] font-bold text-[var(--text-primary)] tracking-tight mt-0.5">
                        {cleanFileName}
                      </div>
                      <div className="text-[11px] font-mono text-[var(--text-muted)] truncate mt-0.5" title={img.path}>
                        {img.path}
                      </div>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20 shrink-0 font-medium">
                      Read-Only
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[11.5px] font-mono text-[var(--text-secondary)] pt-2 border-t border-[var(--border)]/60">
                    <span className="font-semibold text-[var(--text-primary)]">
                      {formatStr}
                    </span>
                    <span className="font-semibold text-[var(--text-primary)]">
                      {img.size_mb != null
                        ? `${img.size_mb.toFixed(2)} MB`
                        : img.size_bytes
                        ? `${(img.size_bytes / (1024 * 1024)).toFixed(2)} MB`
                        : '0.00 MB'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Source Audit & Verification Banner */}
        {selectedImage && (
          <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs font-mono grid grid-cols-1 md:grid-cols-3 gap-2">
            <div>
              <span className="text-[var(--text-secondary)] block text-[10px] uppercase font-semibold">Selected Source:</span>
              <span className="text-[var(--text-primary)] font-bold truncate block" title={selectedImage}>{selectedImage}</span>
            </div>
            <div>
              <span className="text-[var(--text-secondary)] block text-[10px] uppercase font-semibold">Resolved Source:</span>
              <span className="text-[var(--text-primary)] font-bold truncate block" title={selectedImage}>{selectedImage}</span>
            </div>
            <div>
              <span className="text-[var(--text-secondary)] block text-[10px] uppercase font-semibold">Access Mode:</span>
              <span className="text-[#2E7D32] font-bold block">READ-ONLY (WRITE-BLOCKED)</span>
            </div>
          </div>
        )}

        {/* Primary Action Buttons */}
        <div className="flex flex-wrap items-center gap-3 pt-2">
          <button
            type="button"
            aria-label="Start File Recovery"
            onClick={handleStartCarving}
            disabled={isCarving || !selectedImage}
            className="btn-primary h-[42px] px-6 text-[13.5px] font-semibold flex items-center gap-2"
          >
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <Play size={15} className={isCarving ? 'animate-spin' : ''} aria-hidden="true" focusable="false" role="presentation" />
            </span>
            {' '}
            <span>{isCarving ? 'Scanning Evidence...' : 'Start File Recovery'}</span>
            <span className="text-[11px] opacity-80 font-mono font-normal">| Signature Carving</span>
          </button>

          <button
            type="button"
            aria-label="Fragment Recovery"
            onClick={handleReconstructFragments}
            disabled={isReconstructing || isCarving || !selectedImage}
            className="btn-secondary h-[42px] px-4 text-[13px] flex items-center gap-2"
          >
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <Layers size={14} className={isReconstructing ? 'animate-spin text-[var(--primary-orange)]' : 'text-[var(--text-secondary)]'} aria-hidden="true" focusable="false" role="presentation" />
            </span>
            {' '}
            <span>{isReconstructing ? 'Analyzing Fragments...' : 'Fragment Recovery'}</span>
          </button>
        </div>

        {isCarving && (
          <div className="pt-2">
            <ProgressBar progress={progress} stage={stage} color="orange" />
          </div>
        )}
      </div>

      {/* Fragment Diagnostic Result */}
      {fragmentResult && (
        <div className="workstation-card p-6 bg-[var(--surface)] border border-[#D96B27]/40 space-y-5 animate-fade-in">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border)]">
            <div className="flex items-center gap-2.5">
              <Layers size={18} className="text-[#D96B27]" />
              <div>
                <h3 className="text-[16px] font-bold text-[var(--text-primary)]">
                  Fragment Recovery & Reconstruction Analysis
                </h3>
                <p className="text-[12px] text-[var(--text-secondary)]">
                  Bi-directional fragment chain analysis, header/continuation matching, and conservative segregation of uncertain candidates.
                </p>
              </div>
            </div>
            <button
              onClick={() => setFragmentResult(null)}
              className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer px-3 py-1.5 rounded-lg border border-[var(--border)] hover:bg-[var(--surface-hover)]"
            >
              Dismiss
            </button>
          </div>

          {/* Metrics summary cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)]">
              <div className="text-[11px] font-mono text-[var(--text-secondary)] uppercase">Fragments Discovered</div>
              <div className="text-[20px] font-bold text-[var(--text-primary)] font-mono mt-0.5">
                {fragmentResult.total_fragments_discovered ?? 0}
              </div>
            </div>
            <div className="p-3.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)]">
              <div className="text-[11px] font-mono text-[var(--text-secondary)] uppercase">Headers Identified</div>
              <div className="text-[20px] font-bold text-[var(--text-primary)] font-mono mt-0.5">
                {fragmentResult.headers_found ?? 0}
              </div>
            </div>
            <div className="p-3.5 rounded-xl bg-[#2E7D32]/10 border border-[#2E7D32]/30">
              <div className="text-[11px] font-mono text-[#2E7D32] uppercase font-semibold">Reconstructed Files</div>
              <div className="text-[20px] font-bold text-[#2E7D32] font-mono mt-0.5">
                {fragmentResult.reconstructed_count ?? 0}
              </div>
            </div>
            <div className="p-3.5 rounded-xl bg-[#B45309]/10 border border-[#B45309]/30">
              <div className="text-[11px] font-mono text-[#B45309] uppercase font-semibold">Segregated Unpaired</div>
              <div className="text-[20px] font-bold text-[#B45309] font-mono mt-0.5">
                {fragmentResult.segregated_count ?? 0}
              </div>
            </div>
          </div>

          {/* Reconstructions & Candidates Table */}
          {fragmentResult.reconstructions && fragmentResult.reconstructions.length > 0 && (
            <div className="space-y-2">
              <div className="text-[12.5px] font-bold text-[var(--text-primary)] uppercase tracking-wider">
                Reconstruction & Assembly Candidates
              </div>
              <div className="overflow-x-auto rounded-xl border border-[var(--border)]">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-[var(--surface-secondary)] border-b border-[var(--border)] text-[var(--text-secondary)] font-semibold uppercase tracking-wider text-[11px]">
                      <th className="py-2.5 px-4">Status</th>
                      <th className="py-2.5 px-4">Type</th>
                      <th className="py-2.5 px-4">Total Size</th>
                      <th className="py-2.5 px-4">Confidence</th>
                      <th className="py-2.5 px-4">SHA-256 Checksum</th>
                      <th className="py-2.5 px-4">Assembly / Uncertainty Notes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border-subtle)] font-mono">
                    {fragmentResult.reconstructions.map((rec: any, idx: number) => (
                      <tr key={idx} className="hover:bg-[var(--surface-hover)]">
                        <td className="py-2.5 px-4">
                          {rec.is_reconstructed ? (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10.5px] font-bold bg-[#2E7D32]/15 text-[#2E7D32] border border-[#2E7D32]/30">
                              <CheckCircle2 size={12} />
                              RECONSTRUCTED
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10.5px] font-bold bg-[#B45309]/15 text-[#B45309] border border-[#B45309]/30">
                              <AlertTriangle size={12} />
                              SEGREGATED
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-4 text-[var(--text-primary)] font-bold">{rec.file_type}</td>
                        <td className="py-2.5 px-4 text-[var(--text-secondary)]">{(rec.total_size / 1024).toFixed(1)} KB</td>
                        <td className="py-2.5 px-4">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                            rec.confidence_score >= 80
                              ? 'bg-[#2E7D32]/10 text-[#2E7D32] border-[#2E7D32]/30'
                              : 'bg-[#B45309]/10 text-[#B45309] border-[#B45309]/30'
                          }`}>
                            {rec.confidence_score}%
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-[var(--text-primary)] font-mono text-[11px] max-w-xs truncate">
                          {rec.sha256 ? rec.sha256 : <span className="text-[var(--text-muted)]">N/A (Segregated)</span>}
                        </td>
                        <td className="py-2.5 px-4 font-sans text-[var(--text-secondary)]">
                          {rec.uncertainty_reason ? (
                            <span className="text-[#B45309]">{rec.uncertainty_reason}</span>
                          ) : (
                            <span className="text-[#2E7D32]">Bit-perfect assembly verified across fragmented sectors.</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Discovered Raw Fragments Table */}
          {fragmentResult.fragments && fragmentResult.fragments.length > 0 && (
            <div className="space-y-2 pt-2">
              <div className="text-[12.5px] font-bold text-[var(--text-primary)] uppercase tracking-wider">
                Discovered Sector Fragments
              </div>
              <div className="overflow-x-auto rounded-xl border border-[var(--border)]">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-[var(--surface-secondary)] border-b border-[var(--border)] text-[var(--text-secondary)] font-semibold uppercase tracking-wider text-[11px]">
                      <th className="py-2 px-3">Fragment ID</th>
                      <th className="py-2 px-3">Byte Offset</th>
                      <th className="py-2 px-3">Start Sector</th>
                      <th className="py-2 px-3">Length</th>
                      <th className="py-2 px-3">Role</th>
                      <th className="py-2 px-3">Entropy</th>
                      <th className="py-2 px-3">Diagnostics</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border-subtle)] font-mono text-[11px]">
                    {fragmentResult.fragments.map((frag: any) => (
                      <tr key={frag.id} className="hover:bg-[var(--surface-hover)]">
                        <td className="py-2 px-3 text-[var(--text-primary)]">#{frag.id}</td>
                        <td className="py-2 px-3 text-[var(--text-secondary)]">0x{frag.offset.toString(16).toUpperCase()}</td>
                        <td className="py-2 px-3 text-[var(--text-secondary)]">{frag.start_sector}</td>
                        <td className="py-2 px-3 text-[var(--text-secondary)]">{frag.length} B</td>
                        <td className="py-2 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                            frag.role === 'HEADER'
                              ? 'bg-[var(--primary-orange)]/15 text-[var(--primary-orange)] border-[var(--primary-orange)]/30'
                              : frag.role === 'FOOTER'
                              ? 'bg-[#2E7D32]/15 text-[#2E7D32] border-[#2E7D32]/30'
                              : 'bg-[var(--surface-secondary)] text-[var(--text-secondary)] border-[var(--border)]'
                          }`}>
                            {frag.role}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-[var(--text-muted)]">{frag.entropy?.toFixed(3)}</td>
                        <td className="py-2 px-3 font-sans text-[var(--text-secondary)]">{frag.diagnostic_notes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 2 & 3: Recovery Options & Recovered Files */}
      <div className="workstation-card bg-[var(--surface)] border border-[var(--border)] rounded-[10px] overflow-hidden space-y-0">
        <div className="p-6 border-b border-[var(--border)] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="section-title text-[18px] font-semibold text-[var(--text-primary)]">
              Recovered Files
            </h2>
            <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
              {filteredFiles.length} {filteredFiles.length === 1 ? 'file' : 'files'} found
              {carvedFiles.length > 0 && filteredFiles.length !== carvedFiles.length && ` (filtered from ${carvedFiles.length})`}
            </p>
          </div>

          {/* Recovery Options Filters */}
          <div className="flex flex-wrap items-center gap-2.5 text-[12.5px]">
            {/* Search Input */}
            <div className="flex items-center gap-2 bg-[var(--surface-secondary)] border border-[var(--border)] rounded-md px-3 py-1.5">
              <Search size={13} className="text-[var(--text-secondary)]" aria-hidden="true" focusable="false" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search file, offset..."
                className="bg-transparent text-[var(--text-primary)] text-[12.5px] focus:outline-none w-36"
              />
            </div>

            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="bg-[var(--surface-secondary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-[12.5px] text-[var(--text-primary)] focus:outline-none"
            >
              <option value="ALL">All File Types</option>
              <option value="IMAGES">Images (JPEG, PNG)</option>
              <option value="DOCUMENTS">Documents (PDF, DOCX)</option>
              <option value="VIDEOS">Videos</option>
              <option value="ARCHIVES">Archives (ZIP)</option>
            </select>

            {/* Confidence Filter */}
            <select
              value={minConfidence}
              onChange={(e) => setMinConfidence(Number(e.target.value))}
              className="bg-[var(--surface-secondary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-[12.5px] text-[var(--text-primary)] focus:outline-none"
            >
              <option value={0}>Any Confidence</option>
              <option value={60}>60%+ Confidence</option>
              <option value={80}>80%+ Confidence</option>
              <option value={95}>95%+ Confidence</option>
            </select>
          </div>
        </div>

        {/* Recovered Files Table */}
        <div className="overflow-x-auto">
          <table className="workstation-table">
            <thead>
              <tr>
                <th className="w-48">File Name</th>
                <th className="w-24">Type</th>
                <th className="w-36">Recovery Method</th>
                <th className="w-32">Location in Image</th>
                <th className="w-24">Size</th>
                <th className="w-32">Recovery Confidence</th>
                <th>Condition</th>
                <th className="w-28 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredFiles.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[13.5px] text-[var(--text-secondary)]">
                    {carvedFiles.length === 0
                      ? 'No files found yet. Choose an evidence file and click "Start File Recovery" above.'
                      : 'No recovered files match current filter criteria.'}
                  </td>
                </tr>
              ) : (
                filteredFiles.map((file) => {
                  const defaultName = `recovered_${file.id}.${file.extension}`;
                  return (
                    <tr key={file.id} className="hover:bg-[var(--surface-hover)]">
                      <td className="font-medium text-[13px] text-[var(--text-primary)]">
                        <div className="flex items-center gap-2">
                          <FileText size={15} className="text-[#D96B27]" />
                          <span>{defaultName}</span>
                        </div>
                      </td>
                      <td className="text-[12px] font-mono text-[var(--text-secondary)]">
                        {(file.file_type || 'FILE').toUpperCase()}
                      </td>
                      <td className="text-[12px] font-mono">
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-[var(--surface-secondary)] text-[var(--text-secondary)] border border-[var(--border)]">
                          {file.recovery_method || 'Raw Signature Carving'}
                        </span>
                      </td>
                      <td className="font-mono text-[12px] text-[var(--text-secondary)]">
                        {file.offset_hex || `0x${(file.offset_dec || 0).toString(16).toUpperCase()}`}
                      </td>
                      <td className="font-mono text-[12px] text-[var(--text-primary)]">
                        {file.size_bytes != null ? `${(file.size_bytes / 1024).toFixed(1)} KB` : 'N/A'}
                      </td>
                      <td>
                        {getConfidenceBadge(file.confidence_score ?? 0)}
                      </td>
                      <td>
                        <span
                          className={`inline-flex items-center gap-1.5 text-[12px] font-medium ${
                            (file.validation_state === 'VALID' || (!file.validation_state && file.is_valid))
                              ? 'text-[#2E7D32]'
                              : 'text-[#B45309]'
                          }`}
                        >
                          <span
                            className={`w-2 h-2 rounded-full ${
                              (file.validation_state === 'VALID' || (!file.validation_state && file.is_valid))
                                ? 'bg-[#2E7D32]'
                                : 'bg-[#B45309]'
                            }`}
                          />
                          <span>
                            {file.validation_state === 'VALID'
                              ? 'Valid'
                              : file.validation_state === 'PARTIAL'
                              ? 'Partial (Unresolved)'
                              : file.is_valid
                              ? 'Valid'
                              : 'Corrupted / Partial'}
                          </span>
                        </span>
                      </td>
                      <td className="text-right">
                        <button
                          onClick={() => setSelectedFileForDrawer(file)}
                          className="btn-secondary h-[30px] px-2.5 text-[12px] font-medium"
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-out File Details Drawer */}
      <FileDetailsDrawer
        file={selectedFileForDrawer}
        onClose={() => setSelectedFileForDrawer(null)}
      />

      {/* Evidence Import Modal */}
      {isImportModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-fade-in">
          <div className="bg-[var(--surface)] border border-[var(--border)] rounded-xl shadow-2xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
              <div className="flex items-center gap-2 text-[var(--text-primary)]">
                <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                  <FolderOpen size={18} className="text-[#D96B27]" aria-hidden="true" focusable="false" role="presentation" />
                </span>
                <h3 className="font-bold text-[16px]">Select Evidence Image Container</h3>
              </div>
              <button
                type="button"
                aria-label="Close modal"
                onClick={() => setIsImportModalOpen(false)}
                className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer p-1 rounded-lg hover:bg-[var(--surface-hover)]"
              >
                <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                  <X size={18} aria-hidden="true" focusable="false" role="presentation" />
                </span>
              </button>
            </div>

            <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
              Enter the absolute path to a forensic raw disk image file on your system. Supported formats:
              <span className="font-mono text-[#D96B27] ml-1">.img, .dd, .raw, .bin</span>.
            </p>

            <div className="space-y-2">
              <label className="text-[12px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                Absolute File Path
              </label>
              <input
                type="text"
                value={manualImportPath}
                onChange={(e) => setManualImportPath(e.target.value)}
                placeholder="e.g. D:\Evidence\case001.img"
                className="w-full px-3.5 py-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-[13px] text-[var(--text-primary)] font-mono focus:outline-none focus:border-[#D96B27]"
                autoFocus
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    handleImportFilePath(manualImportPath);
                  }
                }}
              />
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-[var(--border)]">
              <button
                type="button"
                aria-label="Cancel"
                onClick={() => setIsImportModalOpen(false)}
                disabled={isImporting}
                className="btn-secondary h-[36px] px-4 text-[12.5px]"
              >
                Cancel
              </button>
              <button
                type="button"
                aria-label="Import Container"
                onClick={() => handleImportFilePath(manualImportPath)}
                disabled={isImporting || !manualImportPath.trim()}
                className="btn-primary h-[36px] px-5 text-[12.5px] font-semibold flex items-center gap-2"
              >
                {isImporting ? (
                  <>
                    <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                      <RefreshCw size={14} className="animate-spin" aria-hidden="true" focusable="false" role="presentation" />
                    </span>
                    <span>Importing...</span>
                  </>
                ) : (
                  <>
                    <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                      <Upload size={14} aria-hidden="true" focusable="false" role="presentation" />
                    </span>
                    <span>Import Container</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
