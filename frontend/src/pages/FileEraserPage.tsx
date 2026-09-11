import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  HardDrive,
  Trash2,
  Lock,
  RefreshCw,
  PlusCircle,
  CheckCircle2,
  FileText,
  ShieldCheck,
  ShieldAlert,
  Hash,
  Clock,
  Layers,
  File,
  Folder
} from 'lucide-react';
import { api } from '../services/api';
import { DiskImage, ImageFileEntry, ImageInspectResponse, ImageFileDeleteResponse } from '../types';
import { Modal } from '../components/Modal';

export const FileEraserPage: React.FC = () => {
  const [availableImages, setAvailableImages] = useState<DiskImage[]>([]);
  const [selectedImagePath, setSelectedImagePath] = useState<string>('D:\\SIH\\test_data\\test-disk.img');
  const [inspectData, setInspectData] = useState<ImageInspectResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

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
    } catch {
      // ignore
    }
  };

  const handleInspectImage = async (path: string = selectedImagePath) => {
    if (!path.trim()) {
      setError('Please select or specify a virtual disk image path.');
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
      const res = await api.createTestDiskImage('D:\\SIH\\test_data\\test-disk.img');
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

  useEffect(() => {
    loadAvailableImages();
    // Auto inspect initial default disk image
    handleInspectImage('D:\\SIH\\test_data\\test-disk.img');
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
      setSuccessMessage(res.message);
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
                Disk Image File Deletion
              </h1>
              <span className="px-3 py-1 rounded-full text-[11.5px] font-mono font-semibold bg-[var(--surface-secondary)] text-[var(--primary-orange)] border border-[var(--border)]">
                Isolated Virtual Disk (.img)
              </span>
            </div>
            <p className="text-[14.5px] text-[var(--text-secondary)] mt-2 leading-relaxed max-w-2xl">
              Inspect filesystem structures inside virtual <code className="font-mono text-[var(--primary-orange)]">.img</code> evidence files and perform sector-level filesystem deletion and data wiping.
            </p>
          </div>

          <button
            type="button"
            onClick={handleCreateTestDisk}
            disabled={isLoading || isDeleting}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[13px] font-semibold text-[var(--primary-orange)] transition-all cursor-pointer shadow-xs"
          >
            <PlusCircle size={16} />
            <span>Generate Standard Test Disk (test-disk.img)</span>
          </button>
        </div>
      </div>

      {/* Safety Notice */}
      <div className="p-5 rounded-2xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2">
        <div className="flex items-center gap-2 text-[#2E7D32] font-bold text-[13px] uppercase">
          <ShieldCheck size={18} aria-hidden="true" focusable="false" />
          <span>Strict Virtual Disk Isolation Active</span>
        </div>
        <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
          ForensiVault executes filesystem modifications exclusively on isolated <code className="font-mono text-[var(--text-primary)]">.img</code> disk images.
          Host operating system partitions, physical disks (<code className="font-mono">\\.\PhysicalDriveX</code>), and mounted system files (<code className="font-mono">C:\Windows</code>) are strictly protected and prohibited from modification.
        </p>
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
            placeholder="D:\SIH\test_data\test-disk.img"
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
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-[15px] font-bold text-[var(--text-primary)] flex items-center gap-2">
                <FileText size={16} className="text-[var(--primary-orange)]" />
                <span>Files Found in Disk Image ({inspectData.files.length})</span>
              </h3>
            </div>

            {inspectData.files.length === 0 ? (
              <div className="p-8 text-center text-sm text-[var(--text-secondary)] bg-[var(--surface-secondary)] rounded-xl border border-[var(--border)]">
                No files detected in root directory table.
              </div>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-[var(--border)]">
                <table className="w-full text-left text-[13px] border-collapse">
                  <thead>
                    <tr className="bg-[var(--surface-secondary)] border-b border-[var(--border)] text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
                      <th className="py-3 px-4">File</th>
                      <th className="py-3 px-4">Size</th>
                      <th className="py-3 px-4">Type</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border)]">
                    {inspectData.files.map((file, idx) => {
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
                              <File size={15} className="text-[var(--text-secondary)] flex-shrink-0" />
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
                              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-[#C53030]/10 text-[#C53030] border border-[#C53030]/30">
                                DELETED (0xE5)
                              </span>
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
                              <span className="text-xs text-[var(--text-muted)] font-mono">Purged</span>
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
    </div>
  );
};

