import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  HardDrive,
  Trash2,
  Lock,
  RefreshCw,
  RotateCcw,
  PlusCircle,
  CheckCircle2,
  FileText,
  ShieldCheck,
  ShieldAlert,
  Hash,
  Clock,
  Layers,
  File,
  Folder,
  Info,
  ArrowUp
} from 'lucide-react';
import { api } from '../services/api';
import { DiskImage, ImageFileEntry, ImageInspectResponse, ImageFileDeleteResponse } from '../types';
import { Modal } from '../components/Modal';

export const FileEraserPage: React.FC = () => {
  const [availableImages, setAvailableImages] = useState<DiskImage[]>([]);
  const [selectedImagePath, setSelectedImagePath] = useState<string>('');
  const [inspectData, setInspectData] = useState<ImageInspectResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // File list filtering tab
  const [fileFilter, setFileFilter] = useState<'active' | 'deleted' | 'all'>('active');
  const [isResetModalOpen, setIsResetModalOpen] = useState<boolean>(false);

  // Deletion state
  const [selectedFile, setSelectedFile] = useState<ImageFileEntry | null>(null);
  const [deleteMode, setDeleteMode] = useState<'normal' | 'secure_wipe'>('normal');
  const [makeBackup, setMakeBackup] = useState<boolean>(true);
  const [isConfirmModalOpen, setIsConfirmModalOpen] = useState<boolean>(false);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);
  const [operationStatus, setOperationStatus] = useState<'idle' | 'modifying' | 'success' | 'failed'>('idle');
  const [deleteResult, setDeleteResult] = useState<ImageFileDeleteResponse | null>(null);

  const formatBytes = (bytes: number): string => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const loadAvailableImages = async () => {
    try {
      const res = await api.getDrives();
      const images = res.disk_images || [];
      setAvailableImages(images);
      if (images.length > 0) {
        setSelectedImagePath((prev) => {
          if (!prev) {
            handleInspectImage(images[0].path);
            return images[0].path;
          }
          return prev;
        });
      }
    } catch {
      // ignore
    }
  };

  const handleInspectImage = async (path: string = selectedImagePath) => {
    if (!path.trim()) {
      return;
    }
    setIsLoading(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const data = await api.inspectDiskImage(path.trim());
      setInspectData(data);
      if (!data.can_modify) {
        setError(data.message || 'This filesystem detected in the disk image does not currently support modification.');
      }
    } catch (err: any) {
      setInspectData(null);
      setError(err.message || 'Failed to inspect virtual disk image.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateTestDisk = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.createTestDiskImage();
      setSelectedImagePath(res.path);
      setSuccessMessage(`Standard test disk created at: ${res.path} (${formatBytes(res.size_bytes)})`);
      setTimeout(() => setSuccessMessage(null), 4000);
      await loadAvailableImages();
      await handleInspectImage(res.path);
    } catch (err: any) {
      setError(err.message || 'Failed to generate standard test disk image.');
    } finally {
      setIsLoading(false);
    }
  };

  // Top-level mode tab
  const [modeTab, setModeTab] = useState<'real_fs' | 'image'>('real_fs');

  // Real Filesystem state
  const [realFsPath, setRealFsPath] = useState<string>('');
  const [realFsItems, setRealFsItems] = useState<any[]>([]);
  const [realFsParentPath, setRealFsParentPath] = useState<string | null>(null);
  const [realFsSelectedFile, setRealFsSelectedFile] = useState<any | null>(null);
  const [realFsMethod, setRealFsMethod] = useState<string>('NIST_800_88_CLEAR');
  const [realFsIsLoading, setRealFsIsLoading] = useState<boolean>(false);
  const [realFsIsDeleting, setRealFsIsDeleting] = useState<boolean>(false);
  const [realFsConfirmModalOpen, setRealFsConfirmModalOpen] = useState<boolean>(false);
  const [realFsConfirmInput, setRealFsConfirmInput] = useState<string>('');
  const [realFsDeleteResult, setRealFsDeleteResult] = useState<any | null>(null);

  const loadRealFs = async (targetPath?: string) => {
    setRealFsIsLoading(true);
    setError(null);
    try {
      const res = await api.browseRealFs(targetPath !== undefined ? targetPath : realFsPath);
      setRealFsPath(res.current_path || '');
      setRealFsParentPath(res.parent_path || null);
      setRealFsItems(res.items || []);
    } catch (err: any) {
      setError('Unable to refresh data.');
    } finally {
      setRealFsIsLoading(false);
    }
  };

  const handleCreateRealFsTestFiles = async () => {
    setRealFsIsLoading(true);
    setError(null);
    try {
      const res = await api.createRealFsTestFiles();
      setSuccessMessage(res.message);
      await loadRealFs(res.directory);
    } catch (err: any) {
      setError(err.message || 'Failed to create test files.');
    } finally {
      setRealFsIsLoading(false);
    }
  };

  const handleDeleteRealFile = async () => {
    if (!realFsSelectedFile) return;
    if (realFsConfirmInput !== 'PERMANENTLY DELETE') {
      setError('You must type "PERMANENTLY DELETE" exactly to confirm erasure.');
      return;
    }
    setRealFsIsDeleting(true);
    setError(null);
    try {
      const res = await api.deleteRealFile({
        filepath: realFsSelectedFile.path,
        method: realFsMethod,
        confirmation: 'PERMANENTLY DELETE'
      });
      setRealFsDeleteResult(res);
      setSuccessMessage(`File permanently deleted and verified absent: ${realFsSelectedFile.name}`);
      setRealFsConfirmModalOpen(false);
      setRealFsSelectedFile(null);
      setRealFsConfirmInput('');
      await loadRealFs(realFsPath);
    } catch (err: any) {
      setError(err.message || 'Real file deletion failed.');
    } finally {
      setRealFsIsDeleting(false);
    }
  };

  useEffect(() => {
    loadAvailableImages();
    loadRealFs('');
  }, []);

  const handlePromptDelete = (file: ImageFileEntry) => {
    if (!inspectData?.can_modify) {
      setError('Filesystem detected, but deletion is not currently supported for this filesystem.');
      return;
    }
    setSelectedFile(file);
    setDeleteResult(null);
    setError(null);
    setIsConfirmModalOpen(true);
  };

  const handleExecuteDelete = async () => {
    if (!selectedFile || !inspectData) return;

    setIsDeleting(true);
    setOperationStatus('modifying');
    setError(null);

    try {
      const res = await api.deleteFileFromImage({
        image_path: inspectData.image_path,
        file_path: selectedFile.full_path,
        mode: deleteMode,
        make_backup: makeBackup
      });

      setDeleteResult(res);
      setOperationStatus('success');
      setSuccessMessage(`${res.message} Disk image updated in-place (no manual saving needed).`);
      setIsConfirmModalOpen(false);

      // Rescan image to reflect modifications
      await handleInspectImage(inspectData.image_path);
    } catch (err: any) {
      setOperationStatus('failed');
      setError(err.message || 'Deletion failed. The disk image was not modified.');
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="p-8 lg:p-14 space-y-10 max-w-6xl mx-auto min-h-full pb-28">
      {/* Header */}
      <div className="pb-6 border-b border-[var(--border-subtle)]">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-[28px] lg:text-[32px] font-bold text-[var(--text-primary)] tracking-tight">
                Secure File Deletion & Sanitization
              </h1>
              <span className="px-3 py-1 rounded-full text-[11.5px] font-mono font-semibold bg-[var(--surface-secondary)] text-[var(--primary-orange)] border border-[var(--border)]">
                {modeTab === 'real_fs' ? 'Real Windows Filesystem' : 'Isolated Virtual Disk (.img)'}
              </span>
            </div>
            <p className="text-[14.5px] text-[var(--text-secondary)] mt-2 leading-relaxed max-w-2xl">
              {modeTab === 'real_fs'
                ? 'Targeted physical file sanitization with native C++ multi-pass overwriting, hardware-level cache flushes, and OS-level system protection guards.'
                : 'Inspect filesystem structures inside virtual .img evidence files and perform sector-level filesystem deletion and data wiping.'}
            </p>
          </div>

          {modeTab === 'image' && (
            <div className="flex flex-col items-end gap-1">
              <button
                type="button"
                onClick={() => setIsResetModalOpen(true)}
                disabled={isLoading || isDeleting}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[13px] font-semibold text-[var(--primary-orange)] transition-all cursor-pointer shadow-xs"
                title="Reset test-disk.img with fresh default sample files"
              >
                <RotateCcw size={16} />
                <span>Reset Demo Disk (test-disk.img)</span>
              </button>
              <span className="text-[11px] text-[var(--text-muted)] font-mono">
                Restores clean sample FAT32 disk
              </span>
            </div>
          )}
        </div>

        {/* Mode Selector Tabs */}
        <div className="flex items-center gap-3 pt-6">
          <button
            type="button"
            onClick={() => setModeTab('real_fs')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-[13px] transition-all cursor-pointer ${
              modeTab === 'real_fs'
                ? 'bg-[var(--primary-orange)] text-white shadow-sm'
                : 'bg-[var(--surface-secondary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--border)]'
            }`}
          >
            <FileText size={16} />
            <span>Targeted Real Filesystem Sanitization</span>
          </button>
          <button
            type="button"
            onClick={() => setModeTab('image')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-[13px] transition-all cursor-pointer ${
              modeTab === 'image'
                ? 'bg-[var(--primary-orange)] text-white shadow-sm'
                : 'bg-[var(--surface-secondary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--border)]'
            }`}
          >
            <HardDrive size={16} />
            <span>Virtual Disk Image (.img)</span>
          </button>
        </div>
      </div>

      {/* Success Notification */}
      {successMessage && (
        <div className="p-5 rounded-2xl bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-[14px] flex items-center gap-3 shadow-xs animate-fade-in">
          <CheckCircle2 size={20} className="flex-shrink-0" />
          <span className="font-semibold">{successMessage}</span>
        </div>
      )}

      {/* Error Notification */}
      {error && (
        <div className="p-5 rounded-2xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[14px] flex items-center gap-3 shadow-xs animate-fade-in">
          <AlertTriangle size={20} className="flex-shrink-0" />
          <span className="font-medium">{error}</span>
        </div>
      )}

      {/* Mode 1: Real Filesystem Sanitizer */}
      {modeTab === 'real_fs' && (
        <div className="space-y-8">
          {/* Safety & Real FS Safeguards Banner */}
          <div className="p-5 rounded-2xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-[#2E7D32] font-bold text-[13px] uppercase tracking-wide">
                <ShieldCheck size={19} />
                <span>Native C++ Secure Eraser & System Protection Guard</span>
              </div>
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20">
                Hardware & OS Guard Active
              </span>
            </div>
            <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
              ForensiVault performs targeted cryptographic overwriting on selected regular files using the C++ native core (<code className="font-mono text-[var(--text-primary)]">SecureFileEraser</code>) with low-level kernel cache flushes (<code className="font-mono text-[var(--text-primary)]">FlushFileBuffers</code>). System protection guards strictly prevent any deletion of OS system files, Windows roots, Program Files, or the application codebase.
            </p>
          </div>

          {/* Quick Access Bookmarks & Test Directory Creation */}
          <div className="workstation-card p-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] uppercase tracking-wider">
                  Quick Navigation & Safe Sandbox
                </h3>
                <p className="text-[12.5px] text-[var(--text-secondary)] mt-0.5">
                  Quickly jump to standard user folders or use the designated safe testing directory.
                </p>
              </div>
              <button
                type="button"
                onClick={handleCreateRealFsTestFiles}
                disabled={realFsIsLoading}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[var(--primary-orange)] text-white hover:opacity-90 font-semibold text-[12.5px] transition-all cursor-pointer shadow-xs"
              >
                <PlusCircle size={15} />
                <span>Create Safe Test Files (5 Files)</span>
              </button>
            </div>

            <div className="flex flex-wrap gap-2 pt-2">
              <button
                type="button"
                onClick={() => loadRealFs('D:\\SIH\\ForensiVault_Test_Delete')}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--primary-orange)]/40 text-[12.5px] font-mono text-[var(--primary-orange)] font-semibold transition-all cursor-pointer"
              >
                <Folder size={15} />
                <span>ForensiVault Safe Test Folder</span>
              </button>
              <button
                type="button"
                onClick={() => loadRealFs('C:\\Users')}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[12.5px] font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all cursor-pointer"
              >
                <Folder size={15} />
                <span>Users Directory</span>
              </button>
              <button
                type="button"
                onClick={() => loadRealFs('D:\\')}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[12.5px] font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all cursor-pointer"
              >
                <HardDrive size={15} />
                <span>D:\ Root</span>
              </button>
            </div>
          </div>

          {/* File Browser Explorer */}
          <div className="workstation-card p-6 space-y-5">
            {/* Address Bar */}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => realFsParentPath && loadRealFs(realFsParentPath)}
                disabled={!realFsParentPath || realFsIsLoading}
                className="p-2.5 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[var(--text-primary)] disabled:opacity-40 disabled:cursor-not-allowed transition-all cursor-pointer"
                title="Go to parent directory"
              >
                <ArrowUp size={16} />
              </button>

              <div className="relative flex-1">
                <input
                  type="text"
                  value={realFsPath}
                  onChange={(e) => setRealFsPath(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') loadRealFs(realFsPath);
                  }}
                  placeholder="Enter filesystem path (e.g. D:\SIH\ForensiVault_Test_Delete)..."
                  className="w-full px-4 py-2.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--primary-orange)]"
                />
              </div>

              <button
                type="button"
                onClick={() => loadRealFs(realFsPath)}
                disabled={realFsIsLoading}
                className="px-4 py-2.5 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[13px] font-semibold text-[var(--text-primary)] transition-all cursor-pointer"
              >
                Go
              </button>

              <button
                type="button"
                onClick={() => loadRealFs(realFsPath)}
                disabled={realFsIsLoading}
                className="p-2.5 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all cursor-pointer"
                title="Refresh directory listing"
              >
                <RefreshCw size={16} className={realFsIsLoading ? 'animate-spin' : ''} />
              </button>
            </div>

            {/* Directory Contents Table */}
            <div className="overflow-x-auto rounded-xl border border-[var(--border)]">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-[var(--surface-secondary)] border-b border-[var(--border)] text-[var(--text-secondary)] font-semibold uppercase tracking-wider text-[11px]">
                    <th className="py-3 px-4">Name</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Size</th>
                    <th className="py-3 px-4">Modified</th>
                    <th className="py-3 px-4">Protection Guard</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)] font-mono">
                  {realFsItems.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-[var(--text-muted)]">
                        {realFsIsLoading ? 'Loading directory contents...' : 'No files or folders found in this directory.'}
                      </td>
                    </tr>
                  ) : (
                    realFsItems.map((item, idx) => {
                      const isSelected = realFsSelectedFile?.path === item.path;
                      return (
                        <tr
                          key={item.path || idx}
                          className={`hover:bg-[var(--surface-hover)] transition-colors ${
                            isSelected ? 'bg-[var(--primary-orange)]/10' : ''
                          }`}
                        >
                          <td className="py-3 px-4 font-sans font-medium text-[var(--text-primary)]">
                            <div className="flex items-center gap-2.5">
                              {item.is_directory ? (
                                <Folder size={16} className="text-[var(--primary-orange)] flex-shrink-0" />
                              ) : (
                                <File size={16} className="text-[var(--text-secondary)] flex-shrink-0" />
                              )}
                              {item.is_directory ? (
                                <button
                                  type="button"
                                  onClick={() => loadRealFs(item.path)}
                                  className="hover:underline text-[var(--text-primary)] font-semibold text-left cursor-pointer"
                                >
                                  {item.name}
                                </button>
                              ) : (
                                <span>{item.name}</span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-4 text-[var(--text-secondary)]">
                            {item.is_directory ? 'Directory' : 'File'}
                          </td>
                          <td className="py-3 px-4 text-[var(--text-secondary)]">
                            {item.is_directory ? '--' : formatBytes(item.size_bytes)}
                          </td>
                          <td className="py-3 px-4 text-[var(--text-muted)] text-[11px]">
                            {item.modified_iso ? item.modified_iso.replace('T', ' ').slice(0, 19) : '--'}
                          </td>
                          <td className="py-3 px-4">
                            {item.is_protected ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-[#C53030]/15 text-[#C53030] border border-[#C53030]/30" title={item.protection_reason}>
                                <ShieldAlert size={12} />
                                PROTECTED
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-[#2E7D32]/15 text-[#2E7D32] border border-[#2E7D32]/30">
                                <ShieldCheck size={12} />
                                SAFE TO SANITIZE
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-right">
                            {!item.is_directory && (
                              <button
                                type="button"
                                onClick={() => setRealFsSelectedFile(item)}
                                disabled={item.is_protected}
                                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                                  item.is_protected
                                    ? 'bg-[var(--surface-secondary)] text-[var(--text-muted)] opacity-50 cursor-not-allowed border border-[var(--border)]'
                                    : isSelected
                                    ? 'bg-[var(--primary-orange)] text-white'
                                    : 'bg-[var(--surface-secondary)] hover:bg-[#C53030]/15 hover:text-[#C53030] border border-[var(--border)] text-[var(--text-primary)]'
                                }`}
                              >
                                {isSelected ? 'Selected' : 'Select'}
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Selected File Sanitization Control Card */}
          {realFsSelectedFile && (
            <div className="workstation-card p-6 space-y-6 border-[var(--primary-orange)]/40 animate-fade-in">
              <div className="flex items-center justify-between pb-3 border-b border-[var(--border-subtle)]">
                <div className="flex items-center gap-2.5">
                  <Trash2 size={20} className="text-[#C53030]" />
                  <h3 className="text-[16px] font-bold text-[var(--text-primary)]">
                    Secure Sanitization Configuration
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={() => setRealFsSelectedFile(null)}
                  className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
                >
                  Deselect
                </button>
              </div>

              {/* File Details */}
              <div className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] font-mono text-xs space-y-2">
                <div><span className="text-[var(--text-muted)]">Target Path: </span><strong className="text-[var(--text-primary)]">{realFsSelectedFile.path}</strong></div>
                <div><span className="text-[var(--text-muted)]">File Size: </span>{formatBytes(realFsSelectedFile.size_bytes)} ({realFsSelectedFile.size_bytes.toLocaleString()} bytes)</div>
              </div>

              {/* Method Selection */}
              <div className="space-y-3">
                <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
                  Select Cryptographic Overwrite Standard:
                </label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <label className={`p-3.5 rounded-xl border cursor-pointer flex items-start gap-3 transition-colors ${
                    realFsMethod === 'NIST_800_88_CLEAR'
                      ? 'bg-[var(--primary-orange)]/10 border-[var(--primary-orange)]'
                      : 'bg-[var(--surface-secondary)] border-[var(--border)]'
                  }`}>
                    <input
                      type="radio"
                      name="realFsMethod"
                      value="NIST_800_88_CLEAR"
                      checked={realFsMethod === 'NIST_800_88_CLEAR'}
                      onChange={() => setRealFsMethod('NIST_800_88_CLEAR')}
                      className="mt-0.5 text-[var(--primary-orange)] focus:ring-0 cursor-pointer"
                    />
                    <div>
                      <div className="text-[13px] font-semibold text-[var(--text-primary)]">NIST SP 800-88 Rev. 1 Clear</div>
                      <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">
                        1-pass logical overwriting with zeros followed by OS verification. Recommended standard for modern magnetic and solid-state media.
                      </p>
                    </div>
                  </label>

                  <label className={`p-3.5 rounded-xl border cursor-pointer flex items-start gap-3 transition-colors ${
                    realFsMethod === 'DOD_5220_22_M'
                      ? 'bg-[var(--primary-orange)]/10 border-[var(--primary-orange)]'
                      : 'bg-[var(--surface-secondary)] border-[var(--border)]'
                  }`}>
                    <input
                      type="radio"
                      name="realFsMethod"
                      value="DOD_5220_22_M"
                      checked={realFsMethod === 'DOD_5220_22_M'}
                      onChange={() => setRealFsMethod('DOD_5220_22_M')}
                      className="mt-0.5 text-[var(--primary-orange)] focus:ring-0 cursor-pointer"
                    />
                    <div>
                      <div className="text-[13px] font-semibold text-[var(--text-primary)]">DoD 5220.22-M Standard</div>
                      <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">
                        3-pass sanitization: Pass 1 (zeros), Pass 2 (ones), Pass 3 (pseudo-random bytes), with read verification.
                      </p>
                    </div>
                  </label>

                  <label className={`p-3.5 rounded-xl border cursor-pointer flex items-start gap-3 transition-colors ${
                    realFsMethod === 'GUTMANN_35'
                      ? 'bg-[var(--primary-orange)]/10 border-[var(--primary-orange)]'
                      : 'bg-[var(--surface-secondary)] border-[var(--border)]'
                  }`}>
                    <input
                      type="radio"
                      name="realFsMethod"
                      value="GUTMANN_35"
                      checked={realFsMethod === 'GUTMANN_35'}
                      onChange={() => setRealFsMethod('GUTMANN_35')}
                      className="mt-0.5 text-[var(--primary-orange)] focus:ring-0 cursor-pointer"
                    />
                    <div>
                      <div className="text-[13px] font-semibold text-[var(--text-primary)]">Gutmann 35-Pass Algorithm</div>
                      <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">
                        Exhaustive 35-pass overwriting designed for legacy magnetic recording patterns. Highly thorough.
                      </p>
                    </div>
                  </label>

                  <label className={`p-3.5 rounded-xl border cursor-pointer flex items-start gap-3 transition-colors ${
                    realFsMethod === 'PSEUDO_RANDOM'
                      ? 'bg-[var(--primary-orange)]/10 border-[var(--primary-orange)]'
                      : 'bg-[var(--surface-secondary)] border-[var(--border)]'
                  }`}>
                    <input
                      type="radio"
                      name="realFsMethod"
                      value="PSEUDO_RANDOM"
                      checked={realFsMethod === 'PSEUDO_RANDOM'}
                      onChange={() => setRealFsMethod('PSEUDO_RANDOM')}
                      className="mt-0.5 text-[var(--primary-orange)] focus:ring-0 cursor-pointer"
                    />
                    <div>
                      <div className="text-[13px] font-semibold text-[var(--text-primary)]">Single Pass Pseudo-Random</div>
                      <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">
                        1-pass cryptographic pseudo-random byte overwriting and cache flush. Fast and effective.
                      </p>
                    </div>
                  </label>
                </div>
              </div>

              {/* Technical Disclosure / Limitations Notice */}
              <div className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2 text-xs text-[var(--text-secondary)]">
                <div className="flex items-center gap-2 text-[var(--primary-orange)] font-semibold text-[12px]">
                  <Info size={15} />
                  <span>Technical Forensic Disclosure & Storage Limitations:</span>
                </div>
                <ul className="list-disc pl-5 space-y-1">
                  <li><strong>Solid-State Drives (SSD):</strong> Wear-leveling controllers and flash translation layers (FTL) may remap logical sectors, leaving previous physical flash pages inaccessible to software-level overwriting until garbage collection or TRIM runs.</li>
                  <li><strong>NTFS Journaling & Metadata:</strong> While file payload and slack clusters are overwritten, filesystem journal logs ($LogFile, $UsnJrnl) and Master File Table ($MFT) resident records may retain historical timestamps or filenames.</li>
                  <li><strong>In-Place Kernel Flush:</strong> ForensiVault issues low-level Win32 FlushFileBuffers to guarantee physical write commit before unlinking the file handle.</li>
                </ul>
              </div>

              {/* Action Button */}
              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setRealFsConfirmInput('');
                    setRealFsConfirmModalOpen(true);
                  }}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl bg-[#C53030] hover:bg-[#B52020] text-white font-bold text-[13px] transition-all cursor-pointer shadow-md"
                >
                  <Trash2 size={16} />
                  <span>Permanently Sanitize Selected File</span>
                </button>
              </div>
            </div>
          )}

          {/* Last Deletion Result */}
          {realFsDeleteResult && (
            <div className="workstation-card p-6 border-[#2E7D32]/40 bg-[#2E7D32]/5 space-y-3 animate-fade-in">
              <div className="flex items-center gap-2 text-[#2E7D32] font-bold text-[14px]">
                <CheckCircle2 size={18} />
                <span>Sanitization Verification Report</span>
              </div>
              <div className="text-xs font-mono space-y-1.5 text-[var(--text-primary)]">
                <div><span className="text-[var(--text-muted)]">Target Path: </span>{realFsDeleteResult.target_path}</div>
                <div><span className="text-[var(--text-muted)]">Standard Applied: </span>{realFsDeleteResult.method}</div>
                <div><span className="text-[var(--text-muted)]">Verification Status: </span><span className="text-[#2E7D32] font-semibold">CONFIRMED ABSENT FROM DISK (Exists: False)</span></div>
                <div><span className="text-[var(--text-muted)]">C++ Core Details: </span>{realFsDeleteResult.details}</div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Mode 2: Virtual Disk Image (.img) */}
      {modeTab === 'image' && (
        <div className="space-y-10">
          {/* Safety & Real-Time Notice */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-5 rounded-2xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2">
              <div className="flex items-center gap-2 text-[#2E7D32] font-bold text-[13px] uppercase">
                <ShieldCheck size={18} aria-hidden="true" focusable="false" />
                <span>Strict Virtual Disk Isolation Active</span>
              </div>
              <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
                Modifications run exclusively on isolated virtual <code className="font-mono text-[var(--text-primary)]">.img</code> disk images. Host partitions, physical drives (<code className="font-mono">/dev/sdX</code>, <code className="font-mono">\\.\PhysicalDriveX</code>), and system paths are strictly protected.
              </p>
            </div>

            <div className="p-5 rounded-2xl bg-[var(--surface-secondary)] border border-[var(--primary-orange)]/30 space-y-2">
              <div className="flex items-center gap-2 text-[var(--primary-orange)] font-bold text-[13px] uppercase">
                <Info size={18} aria-hidden="true" focusable="false" />
                <span>Real-Time In-Place Modifications</span>
              </div>
              <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
                Deletions execute <strong>immediately in-place</strong> on the target disk image with sector-level <code className="font-mono text-[var(--text-primary)]">fsync</code>. No manual saving, exporting, or regenerating is required.
              </p>
            </div>
          </div>

          {/* Operation Status Banner */}
          {operationStatus === 'modifying' && (
            <div className="p-5 rounded-2xl bg-[var(--surface-secondary)] border border-[var(--primary-orange)]/40 text-[var(--primary-orange)] text-[14px] flex items-center gap-3 animate-pulse">
              <RefreshCw size={20} className="animate-spin" />
              <span className="font-semibold">Modifying disk image... Updating filesystem allocation tables and flushing sectors to disk.</span>
            </div>
          )}

      {/* Disk Image Selector Card */}
      <div className="workstation-card p-6 lg:p-8 space-y-5">
        <div className="flex items-center justify-between">
          <h2 className="text-[17px] font-bold text-[var(--text-primary)] flex items-center gap-2">
            <HardDrive size={18} className="text-[var(--primary-orange)]" />
            <span>Select Virtual Disk Image (.img)</span>
          </h2>
          {isLoading && (
            <span className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)]">
              <RefreshCw size={13} className="animate-spin" />
              Scanning filesystem...
            </span>
          )}
        </div>

        {/* Quick Pick Available Disk Images */}
        {availableImages.length > 0 && (
          <div className="space-y-2">
            <label className="block text-[11.5px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
              Detected Evidence & Test Disk Images:
            </label>
            <div className="flex flex-wrap gap-2">
              {availableImages.map((img, idx) => {
                const isSelected = selectedImagePath.toLowerCase() === (img.path || '').toLowerCase();
                return (
                  <button
                    key={img.path || idx}
                    type="button"
                    onClick={() => {
                      setSelectedImagePath(img.path);
                      handleInspectImage(img.path);
                    }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer border ${
                      isSelected
                        ? 'bg-[var(--primary-orange)]/15 border-[var(--primary-orange)] text-[var(--text-primary)] font-bold'
                        : 'bg-[var(--surface-secondary)] border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                    }`}
                  >
                    {img.name}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Custom Path Input */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 pt-1">
          <input
            type="text"
            value={selectedImagePath}
            onChange={(e) => setSelectedImagePath(e.target.value)}
            disabled={isLoading || isDeleting}
            placeholder="Select a virtual disk image from above or enter file path"
            className="flex-1 h-12 px-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] focus:border-[var(--primary-orange)] focus:ring-1 focus:ring-[var(--primary-orange)] text-[13.5px] font-mono text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none"
          />
          <button
            type="button"
            onClick={() => handleInspectImage()}
            disabled={isLoading || isDeleting || !selectedImagePath.trim()}
            className="h-12 px-6 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[13px] font-semibold text-[var(--text-primary)] flex items-center justify-center gap-2 cursor-pointer shadow-xs transition-colors"
          >
            <RefreshCw size={15} className={isLoading ? 'animate-spin' : ''} />
            <span>Inspect Image</span>
          </button>
        </div>
      </div>

      {/* Image Metadata & Filesystem Details Card */}
      {inspectData && (
        <div className="workstation-card p-6 lg:p-8 space-y-6 animate-fade-in">
          <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
            <div className="space-y-1">
              <h2 className="text-[17px] font-bold text-[var(--text-primary)] flex items-center gap-2">
                <Layers size={18} className="text-[var(--primary-orange)]" />
                <span>Filesystem Inspection Status</span>
              </h2>
              <p className="text-[12.5px] font-mono text-[var(--text-muted)] break-all">
                {inspectData.image_path}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <span className="px-3 py-1 rounded-md text-xs font-mono font-bold bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)]">
                {formatBytes(inspectData.size_bytes)}
              </span>
              <span className={`px-3 py-1 rounded-md text-xs font-mono font-bold border ${
                inspectData.can_modify
                  ? 'bg-[#2E7D32]/10 border-[#2E7D32]/30 text-[#2E7D32]'
                  : 'bg-[#B45309]/10 border-[#B45309]/30 text-[#B45309]'
              }`}>
                {inspectData.fs_type} {inspectData.can_modify ? '• Modifiable' : '• Read-Only'}
              </span>
            </div>
          </div>

          {/* Unsupported Filesystem Warning Banner */}
          {!inspectData.can_modify && (
            <div className="p-4 rounded-xl bg-[#B45309]/10 border border-[#B45309]/30 text-[#B45309] text-[13.5px] flex items-center gap-3">
              <ShieldAlert size={18} className="flex-shrink-0" />
              <span className="font-semibold">
                Filesystem detected ({inspectData.fs_type}), but deletion is not currently supported for this filesystem.
              </span>
            </div>
          )}

          {/* Files Inside Disk Image Table */}
          {(() => {
            const activeFiles = inspectData.files.filter(f => f.status === 'ACTIVE');
            const deletedFiles = inspectData.files.filter(f => f.status === 'DELETED');
            const displayedFiles = 
              fileFilter === 'active' 
                ? activeFiles 
                : fileFilter === 'deleted' 
                  ? deletedFiles 
                  : inspectData.files;

            return (
              <div className="space-y-4">
                {/* Header & Filter Tabs */}
                <div className="flex flex-wrap items-center justify-between gap-3 pb-2 border-b border-[var(--border-subtle)]">
                  <h3 className="text-[15px] font-bold text-[var(--text-primary)] flex items-center gap-2">
                    <FileText size={16} className="text-[var(--primary-orange)]" />
                    <span>Filesystem Directory Records</span>
                  </h3>

                  {/* Filter Tabs */}
                  <div className="flex items-center gap-1.5 p-1 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <button
                      type="button"
                      onClick={() => setFileFilter('active')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                        fileFilter === 'active'
                          ? 'bg-[var(--primary-orange)] text-white shadow-xs'
                          : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                      }`}
                    >
                      <span>Active Files</span>
                      <span className={`px-1.5 py-0.5 rounded-full text-[10.5px] font-mono font-bold ${
                        fileFilter === 'active' ? 'bg-black/20 text-white' : 'bg-[var(--surface-hover)] text-[var(--text-muted)]'
                      }`}>
                        {activeFiles.length}
                      </span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setFileFilter('deleted')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                        fileFilter === 'deleted'
                          ? 'bg-[#C53030] text-white shadow-xs'
                          : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                      }`}
                    >
                      <span>Deleted / 0xE5 Records</span>
                      <span className={`px-1.5 py-0.5 rounded-full text-[10.5px] font-mono font-bold ${
                        fileFilter === 'deleted' ? 'bg-black/20 text-white' : 'bg-[var(--surface-hover)] text-[var(--text-muted)]'
                      }`}>
                        {deletedFiles.length}
                      </span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setFileFilter('all')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                        fileFilter === 'all'
                          ? 'bg-[var(--surface-hover)] text-[var(--text-primary)] font-bold shadow-xs'
                          : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                      }`}
                    >
                      <span>All Records</span>
                      <span className={`px-1.5 py-0.5 rounded-full text-[10.5px] font-mono font-bold ${
                        fileFilter === 'all' ? 'bg-[var(--primary-orange)] text-white' : 'bg-[var(--surface-hover)] text-[var(--text-muted)]'
                      }`}>
                        {inspectData.files.length}
                      </span>
                    </button>
                  </div>
                </div>

                {/* Explanatory context when in deleted tab */}
                {fileFilter === 'deleted' && (
                  <div className="p-3.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] text-xs text-[var(--text-secondary)] flex items-start gap-2.5">
                    <Info size={16} className="text-[var(--primary-orange)] flex-shrink-0 mt-0.5" />
                    <span>
                      <strong>Forensic Recovery View:</strong> When a file is normally deleted in FAT32, the operating system marks its directory record with a <code className="font-mono text-[var(--text-primary)]">0xE5</code> tombstone and marks its cluster chain as unallocated. Residual cluster content remains carveable until overwritten or securely wiped.
                    </span>
                  </div>
                )}

                {displayedFiles.length === 0 ? (
                  <div className="p-8 text-center text-sm text-[var(--text-secondary)] bg-[var(--surface-secondary)] rounded-xl border border-[var(--border)] space-y-1">
                    <div className="font-semibold text-[var(--text-primary)]">
                      {fileFilter === 'active' 
                        ? 'No active files remaining in this disk image.' 
                        : fileFilter === 'deleted' 
                          ? 'No deleted / tombstone records found.' 
                          : 'No files detected in directory table.'}
                    </div>
                    <p className="text-xs text-[var(--text-muted)]">
                      {fileFilter === 'active' && 'All files have been deleted or wiped. You can inspect tombstone records in the "Deleted / 0xE5 Records" tab or reset the demo disk.'}
                    </p>
                  </div>
                ) : (
                  <div className="overflow-x-auto rounded-xl border border-[var(--border)]">
                    <table className="w-full text-left text-[13px] border-collapse">
                      <thead>
                        <tr className="bg-[var(--surface-secondary)] border-b border-[var(--border)] text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
                          <th className="py-3 px-4">File Path</th>
                          <th className="py-3 px-4">Size</th>
                          <th className="py-3 px-4">Type</th>
                          <th className="py-3 px-4">Filesystem Status</th>
                          <th className="py-3 px-4 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[var(--border)]">
                        {displayedFiles.map((file, idx) => {
                          const isDeleted = file.status === 'DELETED';
                          return (
                            <tr
                              key={file.full_path + idx}
                              className="hover:bg-[var(--surface-hover)] transition-colors"
                            >
                              <td className="py-3 px-4 font-mono font-medium text-[var(--text-primary)] flex items-center gap-2">
                                {file.is_directory ? (
                                  <Folder size={15} className="text-[var(--primary-orange)] flex-shrink-0" />
                                ) : (
                                  <File size={15} className={isDeleted ? "text-[var(--text-muted)] flex-shrink-0" : "text-[var(--text-secondary)] flex-shrink-0"} />
                                )}
                                <span className={isDeleted ? 'line-through opacity-60' : ''}>
                                  {file.full_path}
                                </span>
                              </td>
                              <td className="py-3 px-4 font-mono text-[var(--text-secondary)]">
                                {file.is_directory ? '—' : formatBytes(file.size_bytes)}
                              </td>
                              <td className="py-3 px-4">
                                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-secondary)]">
                                  {file.file_type}
                                </span>
                              </td>
                              <td className="py-3 px-4">
                                {isDeleted ? (
                                  <div className="inline-flex items-center gap-1.5">
                                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-[#C53030]/10 text-[#C53030] border border-[#C53030]/30">
                                      DELETED (0xE5)
                                    </span>
                                    {file.size_bytes > 0 && (
                                      <span className="text-[10px] font-mono text-[var(--text-muted)]">
                                        (Carveable)
                                      </span>
                                    )}
                                  </div>
                                ) : (
                                  <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/30">
                                    ACTIVE
                                  </span>
                                )}
                              </td>
                              <td className="py-3 px-4 text-right">
                                {file.is_directory ? (
                                  <span className="text-xs text-[var(--text-muted)] italic font-mono">Directory</span>
                                ) : isDeleted ? (
                                  <span className="px-2.5 py-1 rounded text-xs font-mono text-[var(--text-muted)] bg-[var(--surface-secondary)] border border-[var(--border)]">
                                    {file.size_bytes === 0 ? 'Purged / Zeroed' : 'Clusters Freed'}
                                  </span>
                                ) : (
                                  <button
                                    type="button"
                                    onClick={() => handlePromptDelete(file)}
                                    disabled={!inspectData.can_modify || isDeleting}
                                    className="px-3 py-1.5 rounded-lg bg-[#C53030] hover:bg-[#A82828] disabled:opacity-40 text-white text-xs font-semibold cursor-pointer shadow-xs transition-colors inline-flex items-center gap-1.5"
                                  >
                                    <Trash2 size={13} />
                                    <span>Delete</span>
                                  </button>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            );
          })()}
        </div>
      )}

      {/* Verification & Audit Results Card */}
      {deleteResult && (
        <div className="workstation-card p-6 lg:p-8 space-y-5 animate-fade-in">
          <div className="flex items-center gap-2 text-[#2E7D32] pb-3 border-b border-[var(--border-subtle)] font-bold text-[17px]">
            <CheckCircle2 size={20} />
            <span>Operation Result & Filesystem Verification</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2">
              <div className="text-[var(--text-secondary)] font-semibold uppercase text-[11px]">Image Details</div>
              <div className="text-[var(--text-primary)]"><span className="text-[var(--text-muted)]">File: </span>{deleteResult.image_filename}</div>
              <div className="text-[var(--text-primary)]"><span className="text-[var(--text-muted)]">Size: </span>{formatBytes(deleteResult.image_size_bytes)}</div>
              <div className="text-[var(--text-primary)]"><span className="text-[var(--text-muted)]">Filesystem: </span>{deleteResult.detected_filesystem}</div>
              <div className="text-[var(--text-primary)]"><span className="text-[var(--text-muted)]">Clusters Freed: </span>{deleteResult.clusters_freed}</div>
            </div>

            <div className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2">
              <div className="text-[var(--text-secondary)] font-semibold uppercase text-[11px]">Operation & Verification</div>
              <div className="text-[var(--text-primary)]"><span className="text-[var(--text-muted)]">Target: </span>{deleteResult.file_path}</div>
              <div className="text-[var(--text-primary)]"><span className="text-[var(--text-muted)]">Mode: </span>{deleteResult.operation_type}</div>
              <div className="text-[var(--text-primary)]"><span className="text-[var(--text-muted)]">Status: </span><span className="text-[#2E7D32] font-bold">Deleted successfully</span></div>
              <div className="text-[var(--text-primary)]"><span className="text-[var(--text-muted)]">Timestamp: </span>{deleteResult.end_time}</div>
            </div>
          </div>

          {/* Cryptographic SHA-256 Hashes */}
          <div className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2 text-xs font-mono">
            <div className="flex items-center gap-2 text-[var(--text-primary)] font-semibold">
              <Hash size={14} className="text-[var(--primary-orange)]" />
              <span>Disk Image Cryptographic Verification</span>
            </div>
            <div className="text-[var(--text-secondary)] break-all">
              <span className="text-[var(--text-muted)]">Pre-Modification SHA-256: </span>{deleteResult.pre_hash}
            </div>
            <div className="text-[var(--text-secondary)] break-all">
              <span className="text-[var(--text-muted)]">Post-Modification SHA-256: </span>{deleteResult.post_hash}
            </div>
            <div className="text-[#2E7D32] font-semibold pt-1">
              ✓ {deleteResult.verification_result}
            </div>
            {deleteResult.backup_created && (
              <div className="text-[var(--text-muted)] text-[11px] pt-1">
                Backup preserved at: {deleteResult.backup_path}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )}

      {/* Confirmation Modal */}
      <Modal
        isOpen={isConfirmModalOpen}
        onClose={() => setIsConfirmModalOpen(false)}
        title="Delete this file from the disk image?"
        variant="danger"
        confirmText={isDeleting ? 'Modifying disk image...' : 'Delete'}
        cancelText="Cancel"
        onConfirm={handleExecuteDelete}
        isLoading={isDeleting}
        isConfirmDisabled={isDeleting}
      >
        <div className="space-y-4 text-xs">
          <p className="text-[var(--text-primary)] font-medium text-[13.5px]">
            You are about to modify the virtual disk image by deleting the selected file from its filesystem.
          </p>

          <div className="p-3.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] font-mono space-y-1.5">
            <div><span className="text-[var(--text-muted)]">Disk Image: </span>{inspectData?.image_name}</div>
            <div><span className="text-[var(--text-muted)]">File Target: </span><strong className="text-[#C53030]">{selectedFile?.full_path}</strong></div>
            <div><span className="text-[var(--text-muted)]">File Size: </span>{selectedFile ? formatBytes(selectedFile.size_bytes) : '0 B'}</div>
          </div>

          {/* Deletion Mode Selection */}
          <div className="space-y-2 pt-1">
            <label className="block text-[12px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
              Select Deletion Mode:
            </label>
            <div className="grid grid-cols-1 gap-2">
              <label className={`p-3 rounded-xl border cursor-pointer flex items-start gap-3 transition-colors ${
                deleteMode === 'normal'
                  ? 'bg-[var(--primary-orange)]/10 border-[var(--primary-orange)]'
                  : 'bg-[var(--surface-secondary)] border-[var(--border)]'
              }`}>
                <input
                  type="radio"
                  name="del_mode"
                  value="normal"
                  checked={deleteMode === 'normal'}
                  onChange={() => setDeleteMode('normal')}
                  className="mt-0.5 text-[var(--primary-orange)] focus:ring-0 cursor-pointer"
                />
                <div>
                  <div className="text-[13px] font-semibold text-[var(--text-primary)]">NORMAL DELETE (Filesystem Deletion)</div>
                  <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">
                    Marks the directory entry with 0xE5 tombstone and frees allocation clusters in FAT1 & FAT2. Residual cluster data remains unallocated on disk for forensic carving.
                  </p>
                </div>
              </label>

              <label className={`p-3 rounded-xl border cursor-pointer flex items-start gap-3 transition-colors ${
                deleteMode === 'secure_wipe'
                  ? 'bg-[#C53030]/10 border-[#C53030]'
                  : 'bg-[var(--surface-secondary)] border-[var(--border)]'
              }`}>
                <input
                  type="radio"
                  name="del_mode"
                  value="secure_wipe"
                  checked={deleteMode === 'secure_wipe'}
                  onChange={() => setDeleteMode('secure_wipe')}
                  className="mt-0.5 text-[#C53030] focus:ring-0 cursor-pointer"
                />
                <div>
                  <div className="text-[13px] font-semibold text-[var(--text-primary)]">SECURE WIPE (Data Wiping & Forensic Prevention)</div>
                  <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">
                    Permanently overwrites payload clusters and slack space with 0x00 zeroes, zeroes directory metadata, and frees allocation chains. Prevents forensic recovery.
                  </p>
                </div>
              </label>
            </div>
          </div>

          {/* Backup Checkbox */}
          <div className="p-3 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)]">
            <label className="flex items-center gap-2.5 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={makeBackup}
                onChange={(e) => setMakeBackup(e.target.checked)}
                className="w-4 h-4 rounded text-[var(--primary-orange)] border-[var(--border)] focus:ring-0 cursor-pointer"
              />
              <span className="text-[12.5px] text-[var(--text-primary)] font-medium">
                Create automatic backup copy (.bak) before modifying disk image
              </span>
            </label>
          </div>
        </div>
      </Modal>

      {/* Reset Demo Disk Modal */}
      <Modal
        isOpen={isResetModalOpen}
        onClose={() => setIsResetModalOpen(false)}
        title="Reset Standard Demo Disk?"
        variant="warning"
        confirmText="Reset Test Disk"
        cancelText="Cancel"
        onConfirm={() => {
          setIsResetModalOpen(false);
          handleCreateTestDisk();
        }}
        isLoading={isLoading}
      >
        <div className="space-y-4 text-xs">
          <p className="text-[13.5px] text-[var(--text-primary)] font-medium">
            You are about to recreate the demo disk <code className="font-mono text-[var(--primary-orange)]">test-disk.img</code> with fresh sample files.
          </p>

          <div className="p-3.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2 text-[var(--text-secondary)]">
            <div className="text-[12px] font-semibold text-[var(--text-primary)]">What this does:</div>
            <ul className="list-disc pl-4 space-y-1">
              <li>Re-initializes a clean 2 MB FAT32 disk image at <code className="font-mono">test_data/test-disk.img</code>.</li>
              <li>Restores default test files (<code className="font-mono">TEST.TXT</code>, <code className="font-mono">DOCUMENT.PDF</code>, <code className="font-mono">PHOTOS/IMAGE.JPG</code>, <code className="font-mono">SAMPLE/DATA.BIN</code>).</li>
              <li>Clears previous file deletions and tombstone records.</li>
            </ul>
          </div>

          <div className="p-3 rounded-xl bg-[var(--primary-orange)]/10 border border-[var(--primary-orange)]/30 text-[var(--text-secondary)] flex items-start gap-2.5">
            <Info size={16} className="text-[var(--primary-orange)] flex-shrink-0 mt-0.5" />
            <span>
              <strong>Note:</strong> File deletions you execute are already saved automatically in-place. You only need to reset if you want a fresh set of sample files for testing.
            </span>
          </div>
        </div>
      </Modal>

      {/* Real FS Confirmation Modal */}
      <Modal
        isOpen={realFsConfirmModalOpen}
        onClose={() => setRealFsConfirmModalOpen(false)}
        title="Confirm Permanent Real File Erasure"
        variant="danger"
        confirmText={realFsIsDeleting ? 'Sanitizing...' : 'Permanently Delete'}
        cancelText="Cancel"
        onConfirm={handleDeleteRealFile}
        isLoading={realFsIsDeleting}
        isConfirmDisabled={realFsIsDeleting || realFsConfirmInput !== 'PERMANENTLY DELETE'}
      >
        <div className="space-y-4 text-xs">
          <div className="p-3 rounded-xl bg-[#C53030]/15 border border-[#C53030]/30 text-[#C53030] text-[12.5px] font-medium flex items-start gap-2.5">
            <AlertTriangle size={18} className="flex-shrink-0 mt-0.5" />
            <div>
              <strong>CRITICAL WARNING:</strong> This operation performs native C++ cryptographic overwriting directly on your filesystem using standard <strong>{realFsMethod}</strong>. Physical absence will be verified. Data recovery will be impossible.
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] font-mono space-y-1.5">
            <div><span className="text-[var(--text-muted)]">Target File: </span><strong className="text-[#C53030]">{realFsSelectedFile?.path}</strong></div>
            <div><span className="text-[var(--text-muted)]">File Size: </span>{realFsSelectedFile ? formatBytes(realFsSelectedFile.size_bytes) : '0 B'}</div>
            <div><span className="text-[var(--text-muted)]">Sanitization Standard: </span>{realFsMethod}</div>
          </div>

          <div className="space-y-2">
            <label className="block text-[12px] font-semibold text-[var(--text-primary)]">
              To confirm permanent erasure, type <span className="font-mono text-[#C53030] font-bold">PERMANENTLY DELETE</span> below:
            </label>
            <input
              type="text"
              value={realFsConfirmInput}
              onChange={(e) => setRealFsConfirmInput(e.target.value)}
              placeholder="PERMANENTLY DELETE"
              className="w-full px-3.5 py-2.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[#C53030]"
            />
          </div>
        </div>
      </Modal>
    </div>
  );
};

