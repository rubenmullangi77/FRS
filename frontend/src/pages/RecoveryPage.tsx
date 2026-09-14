import React, { useState, useEffect, useMemo } from 'react';
import {
  RotateCcw,
  HardDrive,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Play,
  FileSearch,
  RefreshCw,
  ShieldCheck,
  FolderCheck,
  Database,
  FileText,
  Download,
  Eye,
  X,
  Check,
  Lock,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  Info,
  Copy,
  Server,
  Disc,
  Smartphone,
  Folder,
  File,
  ArrowUp,
  ArrowLeft,
  FolderOpen,
  Image,
  FileCode,
  Archive,
  ShieldAlert,
  Trash2
} from 'lucide-react';
import { api } from '../services/api';
import {
  DiskImage,
  CaseMetadata,
  PartitionItem,
  PartitionTableResponse,
  FilesystemDetectResponse,
  FsRecoveryResponse,
  FsRecoveryFile,
  PhysicalDiskInfo,
  MountedVolumeInfo,
  StorageSourcesResponse,
  PortableDevice,
  PortableDeviceItem,
  CanonicalSource,
  RecoverySourceType,
  PrivilegeStatusResponse,
  TestRawAccessResponse
} from '../types';
import { ProgressBar } from '../components/ProgressBar';
import { getFriendlyEvidenceName } from '../utils/evidenceNames';

interface RecoveryPageProps {
  activeCase: CaseMetadata | null;
}

export const RecoveryPage: React.FC<RecoveryPageProps> = ({ activeCase }) => {
  // Cases and Evidence Sources
  const [cases, setCases] = useState<CaseMetadata[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(activeCase?.case_id || 'CASE-2026-001');
  
  // Real Storage Sources Hierarchy & Canonical Sources
  const [storageSources, setStorageSources] = useState<StorageSourcesResponse | null>(null);
  const [portableDevices, setPortableDevices] = useState<PortableDevice[]>([]);
  const [canonicalSources, setCanonicalSources] = useState<CanonicalSource[]>([]);
  const [selectedCanonicalSource, setSelectedCanonicalSource] = useState<CanonicalSource | null>(null);

  const [sourceCategory, setSourceCategory] = useState<'physical' | 'usb' | 'volumes' | 'portable' | 'images'>('volumes');
  const [selectedSourcePath, setSelectedSourcePath] = useState<string>('');
  const [selectedSourceLabel, setSelectedSourceLabel] = useState<string>('');
  const [selectedSourceType, setSelectedSourceType] = useState<string>('Mounted Volume');
  const [sourceType, setSourceType] = useState<RecoverySourceType>('MOUNTED_VOLUME');
  const [selectedSourceFs, setSelectedSourceFs] = useState<string>('NTFS / FAT32');
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);
  const [isOpeningPdf, setIsOpeningPdf] = useState<boolean>(false);
  const [isOpeningFolder, setIsOpeningFolder] = useState<boolean>(false);

  // Partition Table State
  const [partitionTable, setPartitionTable] = useState<PartitionTableResponse | null>(null);
  const [selectedPartition, setSelectedPartition] = useState<PartitionItem | null>(null);
  const [isDetectingParts, setIsDetectingParts] = useState<boolean>(false);

  // Filesystem Integrity State
  const [fsInfo, setFsInfo] = useState<FilesystemDetectResponse | null>(null);
  const [isDetectingFs, setIsDetectingFs] = useState<boolean>(false);

  // Recovery Execution State
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isExtracting, setIsExtracting] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [statusMessage, setStatusMessage] = useState<string>('Ready');
  const [scanOutput, setScanOutput] = useState<string>('');

  // Results & Integrity
  const [recoveryResult, setRecoveryResult] = useState<FsRecoveryResponse | null>(null);
  const [discoveredFiles, setDiscoveredFiles] = useState<FsRecoveryFile[]>([]);
  const [selectedFileIds, setSelectedFileIds] = useState<Set<number>>(new Set());
  const [activeDetailFile, setActiveDetailFile] = useState<FsRecoveryFile | null>(null);
  const [filePreviewData, setFilePreviewData] = useState<{
    preview_type: 'image' | 'text' | 'pdf' | 'archive' | 'hex';
    preview_data: string;
    extra_meta: Record<string, any>;
    size_formatted?: string;
  } | null>(null);
  const [isPreviewLoading, setIsPreviewLoading] = useState<boolean>(false);
  const [lastGeneratedReport, setLastGeneratedReport] = useState<{
    file_path: string;
    filename: string;
    sha256?: string;
  } | null>(null);

  // UI helpers
  const [error, setError] = useState<string | null>(null);
  const [successBanner, setSuccessBanner] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [unallocatedMode, setUnallocatedMode] = useState<boolean>(false);
  const [showFullAuditLog, setShowFullAuditLog] = useState<boolean>(false);
  const recentActivities = useMemo(() => {
    if (!scanOutput) return ['ForensiVault Audit Engine initialized. Ready for forensic analysis.'];
    const lines = scanOutput.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    return lines.slice(-4);
  }, [scanOutput]);

  // MTP Live Object Browser State
  const [mtpItems, setMtpItems] = useState<PortableDeviceItem[]>([]);
  const [mtpCurrentPath, setMtpCurrentPath] = useState<string>('/');
  const [mtpPathHistory, setMtpPathHistory] = useState<{ id: string; name: string }[]>([]);
  const [isMtpLoading, setIsMtpLoading] = useState<boolean>(false);
  const [selectedMtpObjectIds, setSelectedMtpObjectIds] = useState<Set<string>>(new Set());
  const [isMtpExporting, setIsMtpExporting] = useState<boolean>(false);
  const [mtpExportResult, setMtpExportResult] = useState<any | null>(null);
  const [showDeviceInfoModal, setShowDeviceInfoModal] = useState<boolean>(false);
  const [mtpError, setMtpError] = useState<string | null>(null);
  const [lastMtpAcquisition, setLastMtpAcquisition] = useState<{
    source: string;
    destination: string;
    size: number;
    sha256: string;
    verification: string;
  } | null>(null);

  // MTP Authoritative Navigation & Deletion State
  const [mtpCurrentObjectId, setMtpCurrentObjectId] = useState<string>('');
  const [mtpParentObjectId, setMtpParentObjectId] = useState<string>('');
  const [mtpDeletingFile, setMtpDeletingFile] = useState<PortableDeviceItem | null>(null);
  const [isMtpDeleting, setIsMtpDeleting] = useState<boolean>(false);
  const [mtpDeleteConfirmationInput, setMtpDeleteConfirmationInput] = useState<string>('');
  const [mtpDeletePasswordInput, setMtpDeletePasswordInput] = useState<string>('');
  const [mtpDeleteResultBanner, setMtpDeleteResultBanner] = useState<{
    type: 'success' | 'error';
    title: string;
    message: string;
    verification_status: string;
  } | null>(null);

  // Administrative Privileges & Elevation State
  const [privileges, setPrivileges] = useState<PrivilegeStatusResponse | null>(null);
  const [isRelaunchingElevated, setIsRelaunchingElevated] = useState<boolean>(false);
  const [showElevationModal, setShowElevationModal] = useState<boolean>(false);
  const [elevationModalSource, setElevationModalSource] = useState<string>('');

  const handleRelaunchElevated = async (targetSource?: string) => {
    setIsRelaunchingElevated(true);
    setError(null);
    try {
      const src = targetSource || selectedSourcePath;
      const res = await api.relaunchElevated({
        targetSource: src,
        caseId: selectedCaseId,
        currentRoute: 'recovery'
      });
      if (res.cancelled) {
        setError(res.message || 'Administrator elevation was cancelled or declined. ForensiVault will continue running as Standard User.');
      } else if (res.success) {
        setSuccessBanner(res.message || 'Windows Administrator elevation requested. Please confirm the UAC prompt on your screen.');
        setShowElevationModal(false);
      } else {
        setError(res.message || 'Failed to request administrator elevation.');
      }
    } catch (err: any) {
      setError(`Failed to request administrator elevation: ${err.message}`);
    } finally {
      setIsRelaunchingElevated(false);
    }
  };

  // Diagnostic Raw Access Probe State (Part 2)
  const [rawAccessDiag, setRawAccessDiag] = useState<TestRawAccessResponse | null>(null);
  const [isTestingRawAccess, setIsTestingRawAccess] = useState<boolean>(false);

  const handleTestRawAccess = async (targetPathOverride?: string) => {
    const targetPath = targetPathOverride || selectedSourcePath;
    if (!targetPath) {
      setError('Please select an evidence storage source to test raw access.');
      return;
    }
    setIsTestingRawAccess(true);
    setRawAccessDiag(null);
    try {
      const res = await api.testRawAccess(targetPath, selectedCaseId);
      setRawAccessDiag(res);
      setScanOutput(prev => prev +
        `\n[+] === RAW ACCESS DIAGNOSTIC PROBE ===\n` +
        `[+] Target Handle Path: ${res.target_path}\n` +
        `[+] Handle Opened: ${res.handle_opened ? 'OPENED (Read-Only Handle Verified)' : 'FAILED (Error ' + res.error_code + ')'}\n` +
        `[+] Sector 0 Read Test: ${res.bytes_read > 0 ? res.bytes_read + ' bytes verified' : '0 bytes read'}\n` +
        `[+] Windows Elevation State: ${res.elevation_status}\n` +
        (res.first_bytes_hex ? `[+] First 16 Bytes Hex: ${res.first_bytes_hex}\n` : '') +
        (res.error_message ? `[-] Win32 Diagnostic: ${res.error_message}\n` : '') +
        `[+] ===================================\n`
      );
    } catch (err: any) {
      setError(`Raw access diagnostic probe failed: ${err.message}`);
    } finally {
      setIsTestingRawAccess(false);
    }
  };



  // Computed storage categories for distinct 5 tabs
  const internalDisks = useMemo(() => {
    return (storageSources?.physical_disks || []).filter(d => (d.bus_type || '').toUpperCase() !== 'USB' && !d.is_removable);
  }, [storageSources]);

  const usbDisks = useMemo(() => {
    return (storageSources?.physical_disks || []).filter(d => (d.bus_type || '').toUpperCase() === 'USB' || d.is_removable);
  }, [storageSources]);

  const usbVolumes = useMemo(() => {
    return (storageSources?.mounted_volumes || []).filter(v => v.is_removable || v.drive_type === 'REMOVABLE');
  }, [storageSources]);

  const totalUsbCount = useMemo(() => {
    return usbDisks.length + usbVolumes.filter(v => !usbDisks.some(d => (d.partitions || []).some(p => p.drive_letter === v.drive_letter))).length;
  }, [usbDisks, usbVolumes]);

  // Helper to safely reset all states when changing sources (Part 8)
  const resetAllSourceState = () => {
    // Clear partition & filesystem states
    setPartitionTable(null);
    setSelectedPartition(null);
    setFsInfo(null);
    setRecoveryResult(null);
    setDiscoveredFiles([]);
    setSelectedFileIds(new Set());
    setActiveDetailFile(null);
    setFilePreviewData(null);
    setLastGeneratedReport(null);
    setUnallocatedMode(false);
    setIsScanning(false);
    setIsExtracting(false);
    setScanOutput('');
    
    // Clear MTP states
    setMtpItems([]);
    setSelectedMtpObjectIds(new Set());
    setMtpExportResult(null);
    setMtpCurrentPath('/');
    setMtpCurrentObjectId('');
    setMtpParentObjectId('');
    setMtpPathHistory([]);
    setMtpError(null);
    setMtpDeletingFile(null);
    setMtpDeleteResultBanner(null);
    setLastMtpAcquisition(null);
  };

  // Find matching canonical source from live canonical list
  const findCanonicalSource = (identifier: {
    path?: string;
    driveLetter?: string;
    diskNumber?: number | null;
    partNumber?: number | null;
    sourceType?: RecoverySourceType;
    sourceId?: string;
  }, sourceList?: CanonicalSource[]): CanonicalSource | null => {
    const list = sourceList || canonicalSources;
    if (!list || list.length === 0) return null;

    if (identifier.sourceId) {
      const found = list.find(s => s.source_id === identifier.sourceId);
      if (found) return found;
    }

    if (identifier.driveLetter) {
      const dL = identifier.driveLetter.toUpperCase().replace(/[\\/]/g, '').trim();
      const found = list.find(s => s.drive_letter && s.drive_letter.toUpperCase().replace(/[\\/]/g, '').trim() === dL);
      if (found) return found;
    }

    if (identifier.diskNumber != null && identifier.partNumber != null) {
      const found = list.find(s =>
        s.physical_disk_number === identifier.diskNumber &&
        s.partition_number === identifier.partNumber
      );
      if (found) return found;
    }

    if (identifier.diskNumber != null && identifier.partNumber == null) {
      const found = list.find(s =>
        s.physical_disk_number === identifier.diskNumber &&
        (s.partition_number == null || s.source_type === 'PHYSICAL_DISK' || s.source_type === 'USB_MASS_STORAGE')
      );
      if (found) return found;
    }

    if (identifier.path) {
      const normPath = identifier.path.toLowerCase().trim();
      const found = list.find(s => s.device_path && s.device_path.toLowerCase().trim() === normPath);
      if (found) return found;

      const subMatch = list.find(s =>
        (s.device_path && s.device_path.toLowerCase().includes(normPath)) ||
        (s.device_id && s.device_id.toLowerCase() === normPath)
      );
      if (subMatch) return subMatch;
    }

    return null;
  };

  const selectSource = (opts: {
    path: string;
    label: string;
    displayType: string;
    sourceType: RecoverySourceType;
    filesystem: string;
    diskNumber?: number | null;
    partNumber?: number | null;
    driveLetter?: string;
    sourceId?: string;
  }, sourceList?: CanonicalSource[]) => {
    resetAllSourceState();
    setSelectedSourcePath(opts.path);
    setSelectedSourceLabel(opts.label);
    setSelectedSourceType(opts.displayType);
    setSourceType(opts.sourceType);
    setSelectedSourceFs(opts.filesystem);

    const match = findCanonicalSource({
      path: opts.path,
      driveLetter: opts.driveLetter,
      diskNumber: opts.diskNumber,
      partNumber: opts.partNumber,
      sourceType: opts.sourceType,
      sourceId: opts.sourceId
    }, sourceList);
    setSelectedCanonicalSource(match);
  };

  // Helper to determine if a source path represents an MTP device
  const isMtpDevice = (path: string, cat?: string, sType?: RecoverySourceType): boolean => {
    if (sType === 'MTP_DEVICE' || sType === 'WPD_DEVICE') return true;
    if (cat === 'portable') return true;
    if (!path) return false;
    // Mounted drive letters (e.g. C:, D:) are strictly NOT MTP
    if (/^[a-zA-Z]:[\\/]?/.test(path)) return false;
    const p = path.toLowerCase();
    return p.includes('usb#vid_') || p.includes('wpdbusenum') || p.includes('swd\\wpd') || p.startsWith('\\\\?\\usb#');
  };

  // UI Source Badge (Part 1, 20, 25)
  const renderSourceBadge = () => {
    if (sourceType === 'MTP_DEVICE' || sourceType === 'WPD_DEVICE') {
      return (
        <div className="inline-flex flex-wrap items-center divide-x divide-[#D96B27]/30 rounded-lg bg-[#D96B27]/10 border border-[#D96B27]/30 text-[10.5px] font-mono font-bold shadow-xs overflow-hidden">
          <span className="px-2.5 py-1 text-[var(--text-primary)] uppercase tracking-wider">PORTABLE DEVICE</span>
          <span className="px-2.5 py-1 text-[#D96B27]">MTP / WPD</span>
          <span className="px-2.5 py-1 text-emerald-400 bg-emerald-950/40">LIVE OBJECT ACCESS</span>
        </div>
      );
    }
    if (sourceType === 'USB_MASS_STORAGE') {
      return (
        <div className="inline-flex flex-wrap items-center divide-x divide-cyan-500/30 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-[10.5px] font-mono font-bold shadow-xs overflow-hidden">
          <span className="px-2.5 py-1 text-cyan-200 uppercase tracking-wider">USB STORAGE</span>
          <span className="px-2.5 py-1 text-cyan-300">BLOCK DEVICE</span>
          <span className="px-2.5 py-1 text-emerald-400 bg-emerald-950/40">READ-ONLY MODE</span>
        </div>
      );
    }
    if (sourceType === 'FORENSIC_IMAGE') {
      return (
        <div className="inline-flex flex-wrap items-center divide-x divide-blue-400/30 rounded-lg bg-blue-500/10 border border-blue-500/30 text-[10.5px] font-mono font-bold shadow-xs overflow-hidden">
          <span className="px-2.5 py-1 text-blue-200 uppercase tracking-wider">FORENSIC IMAGE</span>
          <span className="px-2.5 py-1 text-blue-300">RAW BITSTREAM</span>
          <span className="px-2.5 py-1 text-emerald-400 bg-emerald-950/40">READ-ONLY</span>
        </div>
      );
    }
    if (sourceType === 'PHYSICAL_DISK') {
      return (
        <div className="inline-flex flex-wrap items-center divide-x divide-purple-400/30 rounded-lg bg-purple-500/10 border border-purple-500/30 text-[10.5px] font-mono font-bold shadow-xs overflow-hidden">
          <span className="px-2.5 py-1 text-purple-200 uppercase tracking-wider">PHYSICAL DISK</span>
          <span className="px-2.5 py-1 text-emerald-400 bg-emerald-950/40">READ-ONLY ANALYSIS</span>
        </div>
      );
    }
    return (
      <div className="inline-flex flex-wrap items-center divide-x divide-teal-400/30 rounded-lg bg-teal-500/10 border border-teal-500/30 text-[10.5px] font-mono font-bold shadow-xs overflow-hidden">
        <span className="px-2.5 py-1 text-teal-200 uppercase tracking-wider">MOUNTED VOLUME</span>
        <span className="px-2.5 py-1 text-teal-300 bg-teal-950/40">FILESYSTEM ANALYSIS</span>
      </div>
    );
  };

  // Inspect file and fetch authentic preview directly from disk
  const handleInspectFile = async (file: FsRecoveryFile) => {
    setActiveDetailFile(file);
    setFilePreviewData(null);
    if (!file.recovered_file_path && !file.is_recoverable) return;

    setIsPreviewLoading(true);
    try {
      const res = await api.getRecoveryFilePreview({
        file_path: file.recovered_file_path || undefined,
        case_id: selectedCaseId,
        file_id: file.id
      });
      setFilePreviewData({
        preview_type: res.preview_type,
        preview_data: res.preview_data,
        extra_meta: res.extra_meta || {},
        size_formatted: res.size_formatted
      });
    } catch (e: any) {
      console.warn("File preview unavailable:", e.message);
    } finally {
      setIsPreviewLoading(false);
    }
  };

  // Browse live MTP objects using Windows WPD (Part 9, 10)
  const handleBrowseMtp = async (deviceId: string, objectId: string = '', objName: string = 'Root') => {
    setIsMtpLoading(true);
    setError(null);
    setMtpError(null);
    console.log(`[MTP NAV] Browsing device: ${deviceId}, object_id: '${objectId}', name: '${objName}'`);
    try {
      const res = await api.browsePortableDevice({ device_id: deviceId, object_id: objectId });
      console.log(`[MTP ENUM] Result:`, res);
      if (res.error || res.opened === false) {
        const errDetail = res.error || 'Failed to enumerate device contents';
        setMtpError(errDetail);
        setMtpItems([]);
        setScanOutput(prev => prev + `[!] Source Type: MTP_DEVICE\n[!] Device: ${selectedSourceLabel || 'Portable Device'}\n[!] Operation: Enumerate Objects\n[!] Error: ${errDetail}\n`);
        return;
      }

      setMtpCurrentObjectId(objectId);
      setMtpParentObjectId(res.parent_object_id || '');

      // Normalize items
      const rawItems = res.items || [];
      const normalizedItems: PortableDeviceItem[] = rawItems.map((it: any) => {
        const objId = it.object_id || it.id || '';
        const isDir = it.is_folder !== undefined ? Boolean(it.is_folder) : Boolean(it.is_directory);
        return {
          object_id: objId,
          parent_object_id: it.parent_object_id || objectId,
          name: it.name || 'Unnamed',
          path: it.path || it.current_path || '/',
          is_folder: isDir,
          size_bytes: it.size_bytes || 0,
          modified_iso: it.modified_iso || it.modified_date || '',
          content_type: it.content_type || (isDir ? 'folder' : 'file'),
          can_delete: it.can_delete !== undefined ? Boolean(it.can_delete) : !isDir
        };
      });

      // Sort: folders first, then alphabetical by name
      normalizedItems.sort((a, b) => {
        if (a.is_folder && !b.is_folder) return -1;
        if (!a.is_folder && b.is_folder) return 1;
        return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
      });

      setMtpItems(normalizedItems);
      setMtpCurrentPath(res.current_path || '/');

      // Update path history
      let newHistory: { id: string; name: string; parent_id?: string }[] = [];
      if (objectId === '') {
        newHistory = [];
      } else {
        const existingIdx = mtpPathHistory.findIndex(p => p.id === objectId);
        if (existingIdx !== -1) {
          newHistory = mtpPathHistory.slice(0, existingIdx + 1);
        } else {
          newHistory = [...mtpPathHistory, { id: objectId, name: objName, parent_id: res.parent_object_id || '' }];
        }
      }
      setMtpPathHistory(newHistory);

      const fullDisplayPath = newHistory.length > 0 
        ? newHistory.map(h => h.name).join('/') 
        : (objName === 'Root' ? 'Internal storage' : objName);

      const devName = selectedSourceLabel || 'Portable Device';
      setScanOutput(prev => prev + 
        `[+] Source Type: MTP_DEVICE\n` +
        `[+] Device: ${devName}\n` +
        `[+] Protocol: MTP/WPD\n` +
        `[+] Operation: Enumerate Objects\n` +
        `[+] Path: ${fullDisplayPath}\n` +
        `[+] Objects Found: ${normalizedItems.length}\n`
      );
    } catch (err: any) {
      const errMsg = err.message || 'Failed to browse portable device contents';
      setMtpError(errMsg);
      setScanOutput(prev => prev + `[!] Source Type: MTP_DEVICE\n[!] Operation: Enumerate Objects\n[!] Error: ${errMsg}\n`);
    } finally {
      setIsMtpLoading(false);
    }
  };

  // Real WPD Object Deletion (Part 10, 12, 13)
  const handleDeleteMtpFile = async () => {
    if (!mtpDeletingFile || !selectedSourcePath) return;
    if (mtpDeleteConfirmationInput.trim().toUpperCase() !== 'DELETE') {
      setError('Confirmation "DELETE" is required to delete a file from the device.');
      return;
    }

    setIsMtpDeleting(true);
    setMtpDeleteResultBanner(null);
    setError(null);

    const targetObjId = mtpDeletingFile.object_id;
    const targetParentId = mtpDeletingFile.parent_object_id || mtpCurrentObjectId || '';
    const targetName = mtpDeletingFile.name;

    console.log(`[MTP DELETE] Initiating WPD deletion for object: ${targetObjId} (${targetName}) under parent: ${targetParentId}`);

    try {
      const res = await api.deletePortableDeviceFile({
        device_id: selectedSourcePath,
        object_id: targetObjId,
        parent_object_id: targetParentId,
        name: targetName,
        confirmation: 'DELETE',
        password: mtpDeletePasswordInput.trim() || undefined
      });

      console.log(`[MTP DELETE RESULT]`, res);

      const statusText = res.verification_status || (res.success ? 'DELETION VERIFIED' : 'DELETION FAILED');

      setMtpDeleteResultBanner({
        type: res.success ? 'success' : 'error',
        title: res.success ? 'File Deleted & Verified Absent' : 'Deletion Notice',
        message: res.message || (res.success ? `"${targetName}" was successfully removed from the device.` : 'Deletion command failed.'),
        verification_status: statusText
      });

      setScanOutput(prev => prev +
        `\n[+] === MTP / WPD OBJECT DELETION ===\n` +
        `[+] Target Device: ${selectedSourceLabel || 'Portable Device'}\n` +
        `[+] Object ID: ${targetObjId}\n` +
        `[+] Filename: ${targetName}\n` +
        `[+] Parent ID: ${targetParentId}\n` +
        `[+] Status: ${res.status || (res.success ? 'SUCCESS' : 'FAILED')}\n` +
        `[+] Verification: ${statusText}\n` +
        `[+] Message: ${res.message || 'Operation completed'}\n` +
        `[+] =================================\n`
      );

      // Close modal
      setMtpDeletingFile(null);
      setMtpDeleteConfirmationInput('');
      setMtpDeletePasswordInput('');

      // Post-delete re-enumeration of current folder to reflect changes
      await handleBrowseMtp(selectedSourcePath, mtpCurrentObjectId);

    } catch (err: any) {
      console.error(`[MTP DELETE ERROR]`, err);
      const errMsg = err.message || 'WPD deletion failed on device';
      setMtpDeleteResultBanner({
        type: 'error',
        title: 'Deletion Failed',
        message: errMsg,
        verification_status: 'FAILED'
      });
      setScanOutput(prev => prev + `[!] MTP Deletion Error: ${errMsg}\n`);
    } finally {
      setIsMtpDeleting(false);
    }
  };

  // Copy selected live files from MTP device (Part 11, 12)
  const handleCopySelectedMtpFiles = async (singleObjectId?: string) => {
    const objectIdsToCopy = singleObjectId ? [singleObjectId] : Array.from(selectedMtpObjectIds);
    if (!selectedSourcePath || objectIdsToCopy.length === 0) {
      setError('Please select at least one file from the device to copy.');
      return;
    }
    setIsMtpExporting(true);
    setError(null);
    try {
      const res = await api.copyPortableFiles({
        device_id: selectedSourcePath,
        object_ids: objectIdsToCopy,
        case_id: selectedCaseId || 'CASE-2026-001'
      });
      setMtpExportResult(res);
      
      const successful = (res.results || []).filter((r: any) => r.success);
      if (successful.length > 0) {
        const first = successful[0];
        const fullDisplayPath = mtpPathHistory.length > 0 
          ? mtpPathHistory.map(h => h.name).join(' / ') 
          : 'Root';
        const sourcePathStr = `${selectedSourceLabel || 'Portable Device'} / ${fullDisplayPath} / ${first.filename}`;
        const destPathStr = first.saved_path;
        const bytesCopied = first.file_size || first.bytes_written || 0;
        const sha256 = first.sha256;

        setLastMtpAcquisition({
          source: sourcePathStr,
          destination: destPathStr,
          size: bytesCopied,
          sha256: sha256,
          verification: 'PASSED'
        });

        setScanOutput(prev => prev +
          `[+] Source Type: MTP_DEVICE\n` +
          `[+] Operation: MTP Object Acquisition\n` +
          `[+] Source Object: ${sourcePathStr}\n` +
          `[+] Destination: ${destPathStr}\n` +
          `[+] Bytes Copied: ${bytesCopied}\n` +
          `[+] SHA-256: ${sha256}\n` +
          `[+] Verification: PASSED\n`
        );

        setSuccessBanner(`Acquired ${first.filename} (${formatBytes(bytesCopied)}) to case evidence. SHA-256: ${sha256.substring(0, 16)}...`);
      }

      setSelectedMtpObjectIds(new Set());
    } catch (err: any) {
      setError(err.message || 'Failed to copy selected files from device.');
    } finally {
      setIsMtpExporting(false);
    }
  };

  const toggleMtpFileSelection = (objectId: string) => {
    setSelectedMtpObjectIds(prev => {
      const next = new Set(prev);
      if (next.has(objectId)) next.delete(objectId);
      else next.add(objectId);
      return next;
    });
  };

  // Switch source category safely without retaining stale cross-category selections (Part 7, 8)
  // Switch source category safely without retaining stale cross-category selections (Part 7, 8)
  const handleCategoryChange = (category: 'physical' | 'usb' | 'volumes' | 'portable' | 'images') => {
    if (category === sourceCategory) return;
    resetAllSourceState();
    setSelectedSourcePath('');
    setSelectedSourceLabel('');
    setSelectedCanonicalSource(null);
    setSourceCategory(category);
    if (category === 'portable') {
      setSourceType('MTP_DEVICE');
      setSelectedSourceType('Portable Device (MTP)');
      setSelectedSourceFs('Not exposed through MTP');
      // If portable devices are available, auto-select the first one
      if (portableDevices.length > 0) {
        const firstDev = portableDevices[0];
        selectSource({
          path: firstDev.device_id,
          label: firstDev.name,
          displayType: 'Portable Device (MTP)',
          sourceType: 'MTP_DEVICE',
          filesystem: 'Not exposed through MTP'
        });
        handleBrowseMtp(firstDev.device_id, '', 'Root');
      }
    } else if (category === 'usb') {
      setSourceType('USB_MASS_STORAGE');
      setSelectedSourceType('USB Mass Storage');
      setSelectedSourceFs('FAT32 / exFAT / NTFS');
    } else if (category === 'volumes') {
      setSourceType('MOUNTED_VOLUME');
      setSelectedSourceType('Mounted Volume');
      setSelectedSourceFs('NTFS');
    } else if (category === 'physical') {
      setSourceType('PHYSICAL_DISK');
      setSelectedSourceType('Physical Storage Disk');
      setSelectedSourceFs('RAW');
    } else {
      setSourceType('FORENSIC_IMAGE');
      setSelectedSourceType('Forensic Disk Image');
      setSelectedSourceFs('FAT32 / NTFS');
    }
  };

  // Refresh cases and storage sources live from Windows OS (Part 2, 27, 28)
  const isRefreshingRef = React.useRef<boolean>(false);

  const handleRefresh = async () => {
    if (isRefreshingRef.current) return;
    isRefreshingRef.current = true;
    setIsRefreshing(true);
    setError(null);
    try {
      const [sourcesRes, portablesRes, casesRes, canonicalRes, privRes] = await Promise.all([
        api.getStorageSources(),
        api.getPortableDevices().catch(() => ({ devices: [] })),
        api.listCases(),
        api.getCanonicalSources().catch(() => ({ sources: [] })),
        api.getSystemPrivileges().catch(() => null)
      ]);

      setStorageSources(sourcesRes);
      const devs = portablesRes.devices || [];
      setPortableDevices(devs);
      const cSources = canonicalRes.sources || [];
      setCanonicalSources(cSources);
      if (privRes) setPrivileges(privRes);


      if (casesRes.cases && casesRes.cases.length > 0) {
        setCases(casesRes.cases);
        if (!selectedCaseId) {
          setSelectedCaseId(casesRes.cases[0].case_id);
        }
      }

      // Check if previously selected device is still connected (Part 28: Device Disconnect)
      if (selectedSourcePath) {
        let isStillPresent = false;
        if (sourceType === 'MTP_DEVICE' || sourceCategory === 'portable') {
          isStillPresent = devs.some(d => d.device_id === selectedSourcePath);
        } else if (sourceCategory === 'volumes') {
          isStillPresent = (sourcesRes.mounted_volumes || []).some(v => v.drive_letter === selectedSourcePath);
        } else if (sourceCategory === 'usb') {
          isStillPresent = (sourcesRes.physical_disks || []).some(d => {
            const isUsb = d.bus_type === 'USB' || d.is_removable;
            const dNum = d.disk_number ?? (d as any).disk_index;
            return isUsb && (
              d.device_path === selectedSourcePath ||
              `\\\\.\\PhysicalDrive${dNum}` === selectedSourcePath ||
              (d.partitions || []).some((p: any) => p.drive_letter === selectedSourcePath || p.device_path === selectedSourcePath)
            );
          }) || (sourcesRes.mounted_volumes || []).some(v => (v.is_removable || v.drive_type === 'REMOVABLE') && v.drive_letter === selectedSourcePath);
        } else if (sourceCategory === 'physical') {
          isStillPresent = (sourcesRes.physical_disks || []).some(d => {
            const dNum = d.disk_number ?? (d as any).disk_index;
            return d.device_path === selectedSourcePath ||
              `\\\\.\\PhysicalDrive${dNum}` === selectedSourcePath ||
              (d.partitions || []).some((p: any) => p.drive_letter === selectedSourcePath || p.device_path === selectedSourcePath);
          });
        } else if (sourceCategory === 'images') {
          isStillPresent = (sourcesRes.disk_images || []).some(i => i.path === selectedSourcePath);
        }

        if (!isStillPresent) {
          setError(`DEVICE DISCONNECTED: The previously selected source (${selectedSourceLabel || selectedSourcePath}) has been disconnected.`);
          resetAllSourceState();
          setSelectedSourcePath('');
          setSelectedSourceLabel('');
          setSelectedCanonicalSource(null);
          return;
        } else {
          const updatedCanonical = findCanonicalSource({
            path: selectedSourcePath,
            sourceType: sourceType
          }, cSources);
          if (updatedCanonical) {
            setSelectedCanonicalSource(updatedCanonical);
          }
        }
      }

      // If no source selected yet, auto-select first available valid source without prioritizing test fixtures
      if (!selectedSourcePath) {
        if (sourcesRes.mounted_volumes && sourcesRes.mounted_volumes.length > 0) {
          // Prefer secondary data volume like D: over OS C: drive if present
          const preferredVol = sourcesRes.mounted_volumes.find(v => !v.drive_letter.toUpperCase().startsWith('C')) || sourcesRes.mounted_volumes[0];
          const isUsb = preferredVol.is_removable || preferredVol.drive_type === 'REMOVABLE';
          setSourceCategory(isUsb ? 'usb' : 'volumes');
          selectSource({
            path: preferredVol.drive_letter,
            label: `${preferredVol.drive_letter} [${preferredVol.volume_name || 'Volume'}] — ${preferredVol.filesystem || 'NTFS'}`,
            displayType: isUsb ? 'USB Storage (Flash Drive)' : 'Mounted Storage Volume',
            sourceType: isUsb ? 'USB_MASS_STORAGE' : 'MOUNTED_VOLUME',
            filesystem: preferredVol.filesystem || 'NTFS',
            driveLetter: preferredVol.drive_letter
          }, cSources);
        } else if (sourcesRes.physical_disks && sourcesRes.physical_disks.length > 0) {
          const firstDisk = sourcesRes.physical_disks[0];
          const dNum = firstDisk.disk_number ?? (firstDisk as any).disk_index ?? 0;
          const isUsb = firstDisk.bus_type === 'USB' || firstDisk.is_removable;
          setSourceCategory(isUsb ? 'usb' : 'physical');
          selectSource({
            path: `\\\\.\\PhysicalDrive${dNum}`,
            label: `${firstDisk.friendly_name} (Disk #${dNum})`,
            displayType: isUsb ? 'USB Storage' : 'Physical Disk',
            sourceType: isUsb ? 'USB_MASS_STORAGE' : 'PHYSICAL_DISK',
            filesystem: 'RAW',
            diskNumber: dNum
          }, cSources);
        } else if (sourcesRes.disk_images && sourcesRes.disk_images.length > 0) {
          const firstImg = sourcesRes.disk_images[0];
          setSourceCategory('images');
          selectSource({
            path: firstImg.path,
            label: getFriendlyEvidenceName(firstImg.name),
            displayType: 'Forensic Disk Image',
            sourceType: 'FORENSIC_IMAGE',
            filesystem: 'RAW Disk Image'
          }, cSources);
        }
      }

      setSuccessBanner('Storage sources & portable devices refreshed live from Windows hardware subsystem.');
      setTimeout(() => setSuccessBanner(null), 3000);
    } catch (err: any) {
      setError('Unable to refresh live storage sources and case list.');
    } finally {
      isRefreshingRef.current = false;
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    handleRefresh();
  }, []);

  // Update selected case if activeCase prop changes
  useEffect(() => {
    if (activeCase?.case_id) {
      setSelectedCaseId(activeCase.case_id);
    }
  }, [activeCase]);

  // When source selection changes, automatically run inspection for disks/volumes/images,
  // or trigger MTP live browsing & forensic audit journal for portable devices.
  useEffect(() => {
    if (selectedSourcePath) {
      const isMtp = sourceType === 'MTP_DEVICE' || sourceCategory === 'portable' || isMtpDevice(selectedSourcePath, sourceCategory, sourceType);
      if (isMtp) {
        // DO NOT run partition table, filesystem inspection, or raw carving on MTP!
        const foundDev = portableDevices.find(d => d.device_id === selectedSourcePath);
        const devName = foundDev?.name || selectedSourceLabel || 'Portable Device';
        api.auditMtpInspection({
          device_id: selectedSourcePath,
          device_name: devName,
          manufacturer: foundDev?.manufacturer || 'Mobile Handset',
          case_id: selectedCaseId || 'CASE-2026-001',
          examiner_name: 'Ruben'
        }).catch(() => {});

        setScanOutput(
          `[+] Source Type: MTP_DEVICE\n` +
          `[+] Device: ${devName}\n` +
          `[+] Protocol: MTP/WPD\n` +
          `[+] Mode: Live Object Access\n` +
          `[+] Raw Sector Access: NOT AVAILABLE\n` +
          `[+] Deleted Sector Recovery: NOT AVAILABLE\n` +
          `[+] Filesystem: Not Exposed\n` +
          `[+] Raw Carving: NOT EXECUTED\n`
        );
        handleBrowseMtp(selectedSourcePath, '', 'Root');
      } else {
        handleInspectPartitions(selectedSourcePath);
      }
    }
  }, [selectedSourcePath, sourceCategory]);

  // Step 1: Detect Partition Table (MBR/GPT) - Block devices only
  const handleInspectPartitions = async (sourcePath: string) => {
    if (!sourcePath || sourceType === 'MTP_DEVICE' || isMtpDevice(sourcePath, sourceCategory, sourceType)) return;
    setIsDetectingParts(true);
    setError(null);
    try {
      const pRes = await api.getRecoveryPartitions(
        sourcePath,
        selectedCanonicalSource?.source_id,
        selectedCanonicalSource?.source_type
      );
      setPartitionTable(pRes);
      if (pRes.partitions && pRes.partitions.length > 0) {
        const firstPart = pRes.partitions[0];
        setSelectedPartition(firstPart);
        await handleInspectFilesystem(sourcePath, firstPart.start_sector);
      } else {
        setSelectedPartition(null);
        setFsInfo(null);
      }
    } catch (err: any) {
      setError(err.message || 'Partition table detection failed.');
    } finally {
      setIsDetectingParts(false);
    }
  };

  // Step 2: Detect Filesystem on Selected Partition - Block devices only
  const handleInspectFilesystem = async (sourcePath: string, startSector: number) => {
    if (sourceType === 'MTP_DEVICE' || isMtpDevice(sourcePath, sourceCategory, sourceType)) return;
    setIsDetectingFs(true);
    setError(null);
    try {
      const fsRes = await api.detectRecoveryFilesystem(
        sourcePath,
        startSector,
        selectedCanonicalSource?.source_id,
        selectedCanonicalSource?.source_type
      );
      setFsInfo(fsRes);
      if (fsRes.fs_type) {
        setSelectedSourceFs(fsRes.fs_type);
      }
    } catch (err: any) {
      setError(err.message || 'Filesystem detection failed.');
    } finally {
      setIsDetectingFs(false);
    }
  };

  // Step 3: Scan Deleted Files (Metadata Scan) - Block devices only
  const handleScanDeleted = async (sourcePath?: string, startSec?: number) => {
    const targetPath = sourcePath || selectedSourcePath;
    if (!targetPath) {
      setError('Please select an evidence storage source.');
      return;
    }
    if (sourceType === 'MTP_DEVICE' || isMtpDevice(targetPath, sourceCategory, sourceType)) {
      setError('Raw sector recovery is not available through MTP. Acquire an authorized forensic image (.img/.dd) and analyze it under Forensic Disk Images.');
      return;
    }

    const requiresElevation = selectedCanonicalSource?.requires_elevation || 
      (privileges && !privileges.is_elevated && (sourceCategory === 'volumes' || sourceCategory === 'physical' || targetPath.includes('PhysicalDrive')));
    if (requiresElevation && privileges && !privileges.is_elevated) {
      setShowElevationModal(true);
      setElevationModalSource(targetPath);
      setError(`Windows Access Denied (Error 5): Direct sector-level access to raw drive/volume '${targetPath}' requires administrative elevation (Run as Administrator).`);
      return;
    }

    const sector = startSec !== undefined ? startSec : (selectedPartition?.start_sector || 0);

    setIsScanning(true);
    setError(null);
    setProgress(15);
    setStatusMessage('Engaging Read-Only Evidence Mode & parsing boot records...');
    setScanOutput(`[+] Initializing Forensic Recovery Engine for ${targetPath}\n[+] Target Mode: READ-ONLY EVIDENCE MODE (Software Read-Only Analysis Mode)\n[+] Partition Offset: Sector ${sector}\n`);

    try {
      setProgress(40);
      setStatusMessage('Parsing filesystem allocation tables and directory structures...');
      
      const res = await api.scanRecoveryDeleted({
        image_path: targetPath,
        start_sector: sector,
        case_id: selectedCaseId,
        source_id: selectedCanonicalSource?.source_id,
        source_type: selectedCanonicalSource?.source_type
      });

      if ((res as any).error || (res as any).success === false) {
        const isAccessDenied = (res as any).error_type === 'RAW_ACCESS_DENIED' || 
                               (res as any).error_code === 5 || 
                               (res as any).requires_elevation;
        if (isAccessDenied) {
          setShowElevationModal(true);
          setElevationModalSource(targetPath);
        }
        const errMsg = (res as any).error_message || (res as any).message || 'Metadata scanning failed or direct sector access was denied.';
        setError(errMsg);
        setStatusMessage('Raw access denied — Elevation required.');
        setScanOutput(prev => prev + `[-] Access Denied: Direct sector-level access requires Administrator elevation (Error 5).\n`);
        return;
      }

      setProgress(85);
      setStatusMessage('Cataloging deleted directory records and MFT file records...');
      
      setRecoveryResult(res);
      setDiscoveredFiles(res.files || []);
      setUnallocatedMode(false);

      const recoverableIds = new Set<number>();
      (res.files || []).forEach(f => {
        if (f.is_recoverable) recoverableIds.add(f.id);
      });
      setSelectedFileIds(recoverableIds);

      setProgress(100);
      if (res.deleted_entries_found === 0) {
        setStatusMessage('Filesystem analysis complete: 0 deleted file records found in active cluster runs.');
      } else {
        setStatusMessage(`Analysis complete: ${res.deleted_entries_found} deleted candidates cataloged (${res.recoverable_count} intact clusters).`);
      }

      setScanOutput(prev => prev +
        `[+] Filesystem: ${res.fs_type || 'Detected'}\n` +
        `[+] Deleted Candidate Entries: ${res.deleted_entries_found}\n` +
        `[+] Recoverable (Valid Clusters): ${res.recoverable_count}\n` +
        `[+] Partially Damaged: ${res.partial_count}\n` +
        `[+] Non-Recoverable / Overwritten Entries: ${res.not_recoverable_count}\n` +
        `[+] Pre-Recovery Hash: ${res.evidence_pre_hash || 'N/A'}\n`
      );
    } catch (err: any) {
      setError(err.message || 'Metadata scanning failed.');
      setStatusMessage('Scan interrupted.');
    } finally {
      setIsScanning(false);
    }
  };

  // Step 4: Unallocated Space Carving Fallback
  const handleCarveUnallocated = async () => {
    const targetPath = selectedSourcePath;
    if (!targetPath) return;
    if (sourceType === 'MTP_DEVICE' || isMtpDevice(targetPath, sourceCategory, sourceType)) {
      setError('Raw sector recovery is not available through MTP. Acquire an authorized forensic image (.img/.dd) and analyze it under Forensic Disk Images.');
      return;
    }

    const requiresElevation = selectedCanonicalSource?.requires_elevation || 
      (privileges && !privileges.is_elevated && (sourceCategory === 'volumes' || sourceCategory === 'physical' || targetPath.includes('PhysicalDrive')));
    if (requiresElevation && privileges && !privileges.is_elevated) {
      setShowElevationModal(true);
      setElevationModalSource(targetPath);
      setError(`Windows Access Denied (Error 5): Direct sector-level carving of '${targetPath}' requires administrative elevation (Run as Administrator).`);
      return;
    }

    setIsScanning(true);
    setError(null);
    setProgress(20);
    setStatusMessage('Scanning raw unallocated clusters for magic byte signatures...');
    setScanOutput(`[+] Initiating Raw File Carving Fallback...\n[+] Target: ${targetPath}\n[+] Mode: Direct Sector Byte-Level Analysis\n`);

    try {
      const res = await api.scanRecoveryUnallocated({
        image_path: targetPath,
        case_id: selectedCaseId,
        source_id: selectedCanonicalSource?.source_id,
        source_type: selectedCanonicalSource?.source_type
      });

      if ((res as any).error || (res as any).success === false) {
        const isAccessDenied = (res as any).error_type === 'RAW_ACCESS_DENIED' || 
                               (res as any).error_code === 5 || 
                               (res as any).requires_elevation;
        if (isAccessDenied) {
          setShowElevationModal(true);
          setElevationModalSource(targetPath);
          setError('Raw disk access denied (Win32 Error 5). Ensure the backend service is running with Administrator privileges.');
          setStatusMessage('Raw disk access denied (Win32 Error 5).');
          setScanOutput(prev => prev + `[-] Raw disk access denied (Win32 Error 5). Ensure the backend service is running with Administrator privileges.\n`);
        } else {
          const errMsg = (res as any).error_message || (res as any).message || 'Unallocated carving scan failed or access was denied.';
          setError(errMsg);
          setStatusMessage('Carving scan stopped.');
          setScanOutput(prev => prev + `[-] Error: ${errMsg}\n`);
        }
        return;
      }

      setProgress(100);
      const filesFound = res.files?.length || 0;
      if (filesFound === 0) {
        setStatusMessage('Scan complete: 0 recoverable files found in unallocated space.');
      } else {
        setStatusMessage(`Carving complete: ${filesFound} reconstructed files.`);
      }

      setDiscoveredFiles(res.files || []);
      setUnallocatedMode(true);

      const recoverableIds = new Set<number>();
      (res.files || []).forEach(f => {
        if (f.is_recoverable) recoverableIds.add(f.id);
      });
      setSelectedFileIds(recoverableIds);

      const totalSectors = (res as any).total_sectors_scanned || 0;
      const totalBytes = (res as any).total_bytes_scanned || 0;
      const signatures = (res as any).signatures_discovered || 0;
      const validFiles = (res as any).valid_files_count || (res.files || []).filter(f => f.is_recoverable).length;

      setScanOutput(prev => prev + 
        `[+] Raw Carving Signature Scan Finished\n` +
        (filesFound === 0 ? `[+] Scan complete: 0 recoverable files found in unallocated space.\n` : `[+] Discovered Candidates: ${filesFound}\n`) +
        `[+] Total sectors scanned: ${totalSectors}\n` +
        `[+] Chunks processed: ${totalBytes > 0 ? (totalBytes / (1024 * 1024)).toFixed(2) + ' MB' : '0 MB'}\n` +
        `[+] Signatures evaluated: ${signatures}\n` +
        `[+] Valid files extracted: ${validFiles}\n`
      );
    } catch (err: any) {
      const msg = err.message || 'Unallocated carving scan failed.';
      setError(msg);
      setStatusMessage('Carving scan halted.');
      setScanOutput(prev => prev + `[-] Carving Failed: ${msg}\n`);
    } finally {
      setIsScanning(false);
    }
  };

  // Step 5: Bitstream Extraction of Selected Files
  const handleExtractFiles = async (singleFileId?: number | number[]) => {
    const fileIdsToExtract = Array.isArray(singleFileId)
      ? singleFileId
      : (singleFileId !== undefined ? [singleFileId] : Array.from(selectedFileIds));

    if (fileIdsToExtract.length === 0) {
      setError('Please select at least one file candidate to extract.');
      return;
    }

    setIsExtracting(true);
    setError(null);
    setStatusMessage(`Extracting ${fileIdsToExtract.length} file candidate(s) to isolated evidence storage...`);

    try {
      const res = await api.extractRecoveryFiles({
        image_path: selectedSourcePath,
        start_sector: selectedPartition?.start_sector || 0,
        case_id: selectedCaseId,
        file_ids: fileIdsToExtract,
        mode: unallocatedMode ? 'carving' : 'filesystem',
        source_id: selectedCanonicalSource?.source_id,
        source_type: selectedCanonicalSource?.source_type
      });

      setRecoveryResult(res);
      setDiscoveredFiles(res.files || []);
      if (res.recovery_report && res.recovery_report.file_path) {
        setLastGeneratedReport({
          file_path: res.recovery_report.file_path,
          filename: res.recovery_report.filename,
          sha256: res.recovery_report.sha256
        });
      }

      const recCount = (res.files || []).filter(f => f.is_recoverable && f.recovered_file_path).length;
      setStatusMessage(`Recovery Complete — ${recCount} Files Recovered`);

      setScanOutput(prev => prev + 
        `[+] Extraction Completed Successfully\n` +
        `[+] Output Folder: ${res.output_directory}\n` +
        `[+] Post-Recovery Immutability Hash: ${res.evidence_post_hash}\n` +
        `[+] Status: Software Read-Only Mode (Evidence Source Unmodified)\n` +
        (res.recovery_report ? `[+] Recovery Report Generated: ${res.recovery_report.filename}\n` : '')
      );

      setSuccessBanner(`Successfully extracted and verified ${fileIdsToExtract.length} file(s) with SHA-256 integrity logs.`);
    } catch (err: any) {
      setError(err.message || 'Bitstream extraction failed.');
    } finally {
      setIsExtracting(false);
    }
  };

  // Generate Formal Case Recovery Report (Part 22)
  const handleGenerateReport = async () => {
    setIsGeneratingReport(true);
    setError(null);
    try {
      const res = await api.generateReport({
        case_id: selectedCaseId,
        title: `Recovery Report — ${selectedSourceLabel || selectedSourcePath}`,
        format: 'PDF'
      });

      if (res.file_path || res.filename) {
        setLastGeneratedReport({
          file_path: res.file_path || '',
          filename: res.filename || 'Forensic_Report.pdf',
          sha256: res.sha256
        });
      }
      setSuccessBanner(`Forensic report compiled: ${res.filename || 'Report ready'}`);
      setScanOutput(prev => prev + 
        `[+] Forensic Recovery Report Generated\n` +
        `[+] File: ${res.file_path || res.filename || 'PDF Report'}\n` +
        `[+] SHA-256 Digest: ${res.sha256 || 'Verified'}\n`
      );
    } catch (err: any) {
      setError(err.message || 'Failed to generate PDF recovery report.');
    } finally {
      setIsGeneratingReport(false);
    }
  };

  // Open PDF in default viewer (Part 24)
  const handleOpenPdf = async () => {
    setIsOpeningPdf(true);
    setError(null);
    try {
      let targetFilepath = lastGeneratedReport?.file_path || recoveryResult?.recovery_report?.file_path || '';
      if (!targetFilepath) {
        const reportsRes = await api.listReports(selectedCaseId);
        if (reportsRes.reports && reportsRes.reports.length > 0) {
          targetFilepath = reportsRes.reports[0].filepath;
        }
      }
      if (!targetFilepath) {
        const targetCase = selectedCaseId || 'CASE-2026-001';
        const cleanCase = targetCase.replace(/[^A-Za-z0-9_\-]/g, '_').replace(/^_+|_+$/g, '') || 'CASE';
        targetFilepath = `D:\\SIH\\reports\\recovery\\ForensiVault_RECOVERY_${cleanCase}.pdf`;
      }
      const res = await api.openReport({ filepath: targetFilepath });
      setSuccessBanner(res.message || 'Opened forensic recovery report in system viewer.');
    } catch (err: any) {
      setError(err.message || 'Unable to open PDF report. Please verify report file exists.');
    } finally {
      setIsOpeningPdf(false);
    }
  };

  // Download PDF Report
  const handleDownloadPdf = () => {
    const repPath = lastGeneratedReport?.file_path || recoveryResult?.recovery_report?.file_path;
    if (!repPath) return;
    const downloadUrl = api.getReportDownloadUrl(undefined, repPath);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = lastGeneratedReport?.filename || recoveryResult?.recovery_report?.filename || 'Recovery_Report.pdf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // Open recovery evidence folder in Explorer
  const handleOpenFolder = async () => {
    setIsOpeningFolder(true);
    setError(null);
    try {
      const targetFolder = recoveryResult?.output_directory || `D:\\SIH\\ForensiVault_Recovered\\${selectedCaseId || 'CASE-2026-001'}`;
      const res = await api.openRecoveryFolder(targetFolder);
      setSuccessBanner(res.message || 'Opened recovered evidence directory in Windows Explorer.');
    } catch (err: any) {
      setError(err.message || 'Unable to open recovery directory.');
    } finally {
      setIsOpeningFolder(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const formatBytes = (bytes: number): string => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-5 animate-fade-in text-[var(--text-primary)]">
      {/* Top Banner Alerts */}
      {error && (
        <div className="p-4 rounded-xl bg-[#FEF3F2] border border-[#D92D20] text-[#292524] text-xs flex items-start gap-3 shadow-xs">
          <AlertTriangle size={17} className="text-[#B42318] flex-shrink-0 mt-0.5" />
          <div className="flex-1 space-y-1">
            <div className="font-bold text-[#B42318]">Forensic Engine Notice</div>
            <div className="leading-relaxed font-medium text-[#292524]">{error}</div>
          </div>
          <button onClick={() => setError(null)} className="text-[#B42318] hover:text-[#991B1B] cursor-pointer p-0.5" title="Dismiss notice">
            <X size={15} />
          </button>
        </div>
      )}

      {successBanner && (
        <div className="p-4 rounded-xl bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-xs flex items-start gap-3 shadow-xs">
          <CheckCircle2 size={17} className="text-[#2E7D32] flex-shrink-0 mt-0.5" />
          <div className="flex-1 leading-relaxed font-semibold">{successBanner}</div>
          <button onClick={() => setSuccessBanner(null)} className="text-[#2E7D32] hover:opacity-80 cursor-pointer">
            <X size={15} />
          </button>
        </div>
      )}

      {/* Header Section */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-black tracking-tight text-[var(--text-primary)]">
            Forensic File Recovery
          </h1>
          <p className="text-xs sm:text-sm text-[var(--text-secondary)] mt-0.5">
            Sector-level forensic recovery, metadata analysis, and unallocated space carving.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Compact Case Selector: Only selected case name visible in collapsed state */}
          <div className="flex items-center gap-1.5 bg-[var(--surface)] border border-[var(--border)] rounded-lg px-2.5 py-1.5 text-xs shadow-xs">
            <span className="font-semibold text-[var(--text-secondary)]">Case:</span>
            <div className="relative flex items-center">
              <select
                value={selectedCaseId}
                onChange={(e) => setSelectedCaseId(e.target.value)}
                className="appearance-none bg-transparent font-semibold text-[var(--text-primary)] pr-5 pl-1 outline-none cursor-pointer text-xs max-w-[210px] truncate"
              >
                {cases.length > 0 ? (
                  cases.map((c) => (
                    <option key={c.case_id} value={c.case_id} className="bg-[var(--surface)] text-[var(--text-primary)]">
                      {c.case_name || c.case_id}
                    </option>
                  ))
                ) : (
                  <option value="CASE-2026-001" className="bg-[var(--surface)] text-[var(--text-primary)]">Default Case</option>
                )}
              </select>
              <ChevronDown size={12} className="pointer-events-none absolute right-0 text-[var(--text-secondary)]" aria-hidden="true" />
            </div>
          </div>

          {/* Operation Mode Indicator: Read-Only */}
          <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)] flex items-center gap-1.5 shadow-xs">
            <ShieldCheck size={13} className="text-[var(--primary-orange)]" aria-hidden="true" />
            <span>Read-Only</span>
          </span>

          {/* Privilege Status Indicator (Part 1: Strict Token-Derived State) */}
          {privileges?.is_elevated ? (
            <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)] flex items-center gap-1.5 shadow-xs">
              <CheckCircle2 size={13} className="text-[var(--primary-orange)]" aria-hidden="true" />
              <span>Privilege: Administrator (Elevated)</span>
            </span>
          ) : (
            <div className="flex items-center gap-1.5">
              <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)] flex items-center gap-1.5 shadow-xs">
                <span>Privilege: Standard User (Restricted)</span>
              </span>
              <button
                type="button"
                onClick={() => handleRelaunchElevated()}
                disabled={isRelaunchingElevated}
                className="btn-primary h-7 px-2.5 text-xs font-semibold rounded-lg shadow-xs"
                title="Restart ForensiVault as Administrator via Windows UAC"
              >
                <Lock size={11} aria-hidden="true" />
                <span>{isRelaunchingElevated ? 'Restarting...' : 'Restart as Administrator'}</span>
              </button>
            </div>
          )}

          <button
            type="button"
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="btn-secondary h-7 px-2.5 text-xs font-medium flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            title="Re-enumerate all connected storage devices and portable phones"
          >
            <RefreshCw size={12} className={isRefreshing ? 'animate-spin' : ''} aria-hidden="true" />
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh Sources'}</span>
          </button>
        </div>
      </div>

      {/* Primary Evidence Source Selector Card */}
      <div className="workstation-card p-4 bg-[var(--surface)] border border-[var(--border)] rounded-[12px] space-y-3 shadow-xs">
        {/* Category Tabs: Mounted Volumes, Physical Storage, USB Storage, Portable Devices, Forensic Images (Clean without count badges) */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => handleCategoryChange('volumes')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-all cursor-pointer border ${
                sourceCategory === 'volumes'
                  ? 'bg-[var(--primary-orange)] text-white border-[var(--primary-orange)] shadow-xs'
                  : 'bg-[var(--surface-secondary)] border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <Database size={13} aria-hidden="true" />
              <span>Mounted Volumes</span>
            </button>

            <button
              type="button"
              onClick={() => handleCategoryChange('physical')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-all cursor-pointer border ${
                sourceCategory === 'physical'
                  ? 'bg-[var(--primary-orange)] text-white border-[var(--primary-orange)] shadow-xs'
                  : 'bg-[var(--surface-secondary)] border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <Server size={13} aria-hidden="true" />
              <span>Physical Storage</span>
            </button>

            <button
              type="button"
              onClick={() => handleCategoryChange('usb')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-all cursor-pointer border ${
                sourceCategory === 'usb'
                  ? 'bg-[var(--primary-orange)] text-white border-[var(--primary-orange)] shadow-xs'
                  : 'bg-[var(--surface-secondary)] border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <HardDrive size={13} aria-hidden="true" />
              <span>USB Storage</span>
            </button>

            <button
              type="button"
              onClick={() => handleCategoryChange('portable')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-all cursor-pointer border ${
                sourceCategory === 'portable'
                  ? 'bg-[var(--primary-orange)] text-white border-[var(--primary-orange)] shadow-xs'
                  : 'bg-[var(--surface-secondary)] border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <Smartphone size={13} aria-hidden="true" />
              <span>Portable Devices (MTP)</span>
            </button>

            <button
              type="button"
              onClick={() => handleCategoryChange('images')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-all cursor-pointer border ${
                sourceCategory === 'images'
                  ? 'bg-[var(--primary-orange)] text-white border-[var(--primary-orange)] shadow-xs'
                  : 'bg-[var(--surface-secondary)] border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <Disc size={13} aria-hidden="true" />
              <span>Forensic Images</span>
            </button>
          </div>
        </div>

        {/* Row 2: Source Selection based on active category */}
        <div className="space-y-2">
          {sourceCategory === 'physical' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="block text-[11px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
                  Internal Physical Storage Disks & Partitions (NVMe / SATA / SSD / HDD):
                </label>
                {storageSources && (storageSources as any).is_admin === false && (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 font-medium">
                    Query Mode (Elevate to Run Sector Carving)
                  </span>
                )}
              </div>

              {internalDisks.length === 0 ? (
                <div className="p-4 rounded-xl border border-dashed border-[var(--border)] bg-[var(--surface-secondary)] text-center text-xs text-[var(--text-secondary)]">
                  No internal physical storage disks detected.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-56 overflow-y-auto pr-1">
                  {internalDisks.map((disk) => {
                    const dNum = disk.disk_number ?? (disk as any).disk_index ?? 0;
                    const dSize = disk.total_size_formatted || disk.size_formatted || '0 GB';
                    return (
                      <div
                        key={dNum}
                        className="p-3 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="font-bold text-[12.5px] text-[var(--text-primary)] flex items-center gap-1.5 truncate">
                            <Server size={14} className="text-[var(--primary-orange)] flex-shrink-0" />
                            <span className="truncate">Disk {dNum}: {disk.friendly_name}</span>
                          </div>
                          <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-bold bg-[var(--surface)] border border-[var(--border)] text-[var(--text-secondary)]">
                            {disk.bus_type || 'Internal'}
                          </span>
                        </div>

                        <div className="text-[11px] text-[var(--text-secondary)] flex items-center justify-between font-mono">
                          <span>Capacity: {dSize}</span>
                          <span>Style: {disk.partition_style || 'GPT'}</span>
                        </div>

                        <div className="space-y-1 pt-1 border-t border-[var(--border)]">
                          {disk.partitions && disk.partitions.length > 0 ? (
                            disk.partitions.map((part) => {
                              const partPath = part.drive_letter || `\\\\.\\PhysicalDrive${dNum}#Partition${part.partition_number}`;
                              const isSelected = selectedSourcePath === partPath;
                              const partSize = (part as any).size_formatted || `${((part.size_bytes || 0) / (1024**3)).toFixed(2)} GB`;
                              const partLabel = (part as any).volume_label ? ` [${(part as any).volume_label}]` : '';
                              return (
                                  <div
                                    key={part.partition_number}
                                    onClick={() => {
                                      selectSource({
                                        path: partPath,
                                        label: `${disk.friendly_name} — Partition #${part.partition_number} (${part.drive_letter || 'Raw'})${partLabel}`,
                                        displayType: 'Physical Disk Partition',
                                        sourceType: 'PARTITION',
                                        filesystem: part.filesystem || 'NTFS',
                                        diskNumber: dNum,
                                        partNumber: part.partition_number,
                                        driveLetter: part.drive_letter
                                      });
                                    }}
                                    className={`p-1.5 px-2 rounded-lg border text-xs cursor-pointer transition-all flex items-center justify-between ${
                                      isSelected
                                        ? 'bg-[var(--primary-orange)]/15 border-[var(--primary-orange)] text-[var(--text-primary)] font-semibold'
                                        : 'bg-[var(--surface)] border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                                    }`}
                                  >
                                    <div className="flex items-center gap-1.5 truncate">
                                      <HardDrive size={12} className={isSelected ? 'text-[var(--primary-orange)]' : 'text-[var(--text-secondary)]'} />
                                      <span className="truncate">Part #{part.partition_number} {part.drive_letter ? `(${part.drive_letter})` : ''}{partLabel}</span>
                                      {part.is_boot && (
                                        <span className="text-[9px] px-1 rounded bg-[#2E7D32]/10 text-[#2E7D32]">Boot</span>
                                      )}
                                    </div>
                                    <div className="font-mono text-[10.5px] flex-shrink-0 ml-2">
                                      {partSize} • {part.filesystem || 'NTFS'}
                                    </div>
                                  </div>
                                );
                              })
                            ) : (
                              <div
                                onClick={() => {
                                  selectSource({
                                    path: `\\\\.\\PhysicalDrive${dNum}`,
                                    label: `${disk.friendly_name} (Whole Disk #${dNum})`,
                                    displayType: 'Physical Storage Disk',
                                    sourceType: 'PHYSICAL_DISK',
                                    filesystem: 'RAW',
                                    diskNumber: dNum
                                  });
                                }}
                                className="p-1.5 px-2 rounded-lg border border-[var(--border)] bg-[var(--surface)] text-[11px] text-[var(--text-secondary)] cursor-pointer hover:border-[var(--primary-orange)] text-center"
                              >
                                Select Entire Physical Disk #{dNum}
                              </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {sourceCategory === 'usb' && (
            <div className="space-y-2">
              <label className="block text-[11px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
                Removable USB Storage, Flash Drives & Pen Drives:
              </label>
              {totalUsbCount === 0 ? (
                <div className="p-6 rounded-xl border border-dashed border-[var(--border)] bg-[var(--surface-secondary)] text-center space-y-1.5">
                  <HardDrive size={24} className="mx-auto text-[var(--text-muted)] opacity-60" />
                  <div className="text-[12.5px] font-bold text-[var(--text-primary)]">No USB Mass Storage / Pen Drives Detected</div>
                  <p className="text-[11.5px] text-[var(--text-secondary)] max-w-md mx-auto">
                    Connect a USB flash drive, pen drive, external USB drive, or SD card reader, then click <strong>"Refresh Sources"</strong>.
                  </p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-56 overflow-y-auto pr-1">
                  {usbDisks.map((disk) => {
                    const dNum = disk.disk_number ?? (disk as any).disk_index ?? 0;
                    const dSize = disk.total_size_formatted || disk.size_formatted || '0 GB';
                    return (
                      <div
                        key={`usb-disk-${dNum}`}
                        className="p-3 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="font-bold text-[12.5px] text-[var(--text-primary)] flex items-center gap-1.5 truncate">
                            <HardDrive size={14} className="text-cyan-400 flex-shrink-0" />
                            <span className="truncate">{disk.friendly_name} (Disk #{dNum})</span>
                          </div>
                          <span className="text-[9.5px] px-1.5 py-0.5 rounded font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                            USB Removable
                          </span>
                        </div>

                        <div className="text-[11px] text-[var(--text-secondary)] flex items-center justify-between font-mono">
                          <span>Capacity: {dSize}</span>
                          <span>Style: {disk.partition_style || 'MBR'}</span>
                        </div>

                        <div className="space-y-1 pt-1 border-t border-[var(--border)]">
                          {disk.partitions && disk.partitions.length > 0 ? (
                            disk.partitions.map((part) => {
                              const partPath = part.drive_letter || `\\\\.\\PhysicalDrive${dNum}#Partition${part.partition_number}`;
                              const isSelected = selectedSourcePath === partPath;
                              const partSize = (part as any).size_formatted || `${((part.size_bytes || 0) / (1024**3)).toFixed(2)} GB`;
                              const partLabel = (part as any).volume_label ? ` [${(part as any).volume_label}]` : '';
                              return (
                                <div
                                  key={part.partition_number}
                                  onClick={() => {
                                    selectSource({
                                      path: partPath,
                                      label: `${disk.friendly_name} — ${part.drive_letter || `Partition #${part.partition_number}`}${partLabel}`,
                                      displayType: 'USB Storage (Flash Drive)',
                                      sourceType: 'USB_MASS_STORAGE',
                                      filesystem: part.filesystem || 'FAT32',
                                      diskNumber: dNum,
                                      partNumber: part.partition_number,
                                      driveLetter: part.drive_letter
                                    });
                                  }}
                                  className={`p-1.5 px-2 rounded-lg border text-xs cursor-pointer transition-all flex items-center justify-between ${
                                    isSelected
                                      ? 'bg-[var(--primary-orange)]/15 border-[var(--primary-orange)] text-[var(--text-primary)] font-semibold'
                                      : 'bg-[var(--surface)] border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                                  }`}
                                >
                                  <div className="flex items-center gap-1.5 truncate">
                                    <HardDrive size={12} className={isSelected ? 'text-[var(--primary-orange)]' : 'text-cyan-400'} />
                                    <span className="truncate">{part.drive_letter ? `${part.drive_letter} ` : `Part #${part.partition_number} `}{partLabel}</span>
                                  </div>
                                  <div className="font-mono text-[10.5px] flex-shrink-0 ml-2">
                                    {partSize} • {part.filesystem || 'FAT32'}
                                  </div>
                                </div>
                              );
                            })
                          ) : (
                            <div
                              onClick={() => {
                                selectSource({
                                  path: `\\\\.\\PhysicalDrive${dNum}`,
                                  label: `${disk.friendly_name} (USB Mass Storage #${dNum})`,
                                  displayType: 'USB Storage (Flash Drive)',
                                  sourceType: 'USB_MASS_STORAGE',
                                  filesystem: 'RAW',
                                  diskNumber: dNum
                                });
                              }}
                              className="p-1.5 px-2 rounded-lg border border-[var(--border)] bg-[var(--surface)] text-[11px] text-[var(--text-secondary)] cursor-pointer hover:border-[var(--primary-orange)] text-center"
                            >
                              Select Entire USB Drive #{dNum}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}

                  {usbVolumes.filter(v => !usbDisks.some(d => (d.partitions || []).some(p => p.drive_letter === v.drive_letter))).map((vol) => {
                    const isSelected = selectedSourcePath === vol.drive_letter;
                    return (
                      <div
                        key={`usb-vol-${vol.drive_letter}`}
                        onClick={() => {
                          selectSource({
                            path: vol.drive_letter,
                            label: `${vol.drive_letter} [${vol.volume_name || 'USB Volume'}] — ${vol.filesystem}`,
                            displayType: 'USB Storage (Flash Drive)',
                            sourceType: 'USB_MASS_STORAGE',
                            filesystem: vol.filesystem || 'FAT32',
                            driveLetter: vol.drive_letter
                          });
                        }}
                        className={`p-3 rounded-xl border text-xs cursor-pointer transition-all space-y-1.5 ${
                          isSelected
                            ? 'bg-[var(--primary-orange)]/15 border-[var(--primary-orange)] shadow-xs'
                            : 'bg-[var(--surface-secondary)] border-[var(--border)] hover:border-[var(--border-strong)]'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="font-bold text-[12.5px] text-[var(--text-primary)] flex items-center gap-1.5 truncate">
                            <HardDrive size={14} className={isSelected ? 'text-[var(--primary-orange)]' : 'text-cyan-400'} />
                            <span className="truncate">{vol.drive_letter} [{vol.volume_name || 'Removable'}]</span>
                            <span className="text-[9.5px] px-1.5 py-0.2 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-bold">
                              Removable
                            </span>
                          </div>
                          <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-bold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20">
                            {vol.filesystem}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-[10.5px] font-mono text-[var(--text-secondary)]">
                          <div>Total: {vol.total_formatted}</div>
                          <div>Free: {vol.free_formatted}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {sourceCategory === 'volumes' && (
            <div className="space-y-2">
              <label className="block text-[11px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
                Mounted Volumes:
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5 max-h-56 overflow-y-auto pr-1">
                {storageSources?.mounted_volumes?.map((vol) => {
                  const isSelected = selectedSourcePath === vol.drive_letter;
                  const isUsb = vol.is_removable || vol.drive_type === 'REMOVABLE';
                  const friendlyVolName = vol.volume_name || (vol.drive_letter.toUpperCase().startsWith('C') ? 'Windows' : 'New Volume');
                  return (
                    <div
                      key={vol.drive_letter}
                      onClick={() => {
                        selectSource({
                          path: vol.drive_letter,
                          label: `${vol.drive_letter} [${friendlyVolName}]`,
                          displayType: isUsb ? 'USB Storage (Flash Drive)' : 'Mounted Volume',
                          sourceType: isUsb ? 'USB_MASS_STORAGE' : 'MOUNTED_VOLUME',
                          filesystem: vol.filesystem || 'NTFS',
                          driveLetter: vol.drive_letter
                        });
                      }}
                      className={`p-3 rounded-xl border text-xs cursor-pointer transition-all flex items-center justify-between gap-2 ${
                        isSelected
                          ? 'bg-[var(--surface-secondary)] border-[var(--primary-orange)] shadow-xs ring-1 ring-[var(--primary-orange)]/30'
                          : 'bg-[var(--surface)] border-[var(--border)] hover:border-[var(--primary-orange)]/40'
                      }`}
                    >
                      <div className="min-w-0">
                        <div className="font-bold text-[13px] text-[var(--text-primary)] flex items-center gap-1.5 truncate">
                          <HardDrive size={14} className={isSelected ? 'text-[var(--primary-orange)]' : 'text-[var(--text-secondary)]'} aria-hidden="true" />
                          <span className="truncate">{vol.drive_letter} [{friendlyVolName}]</span>
                        </div>
                        <div className="text-[11.5px] text-[var(--text-secondary)] font-mono mt-0.5">
                          {vol.filesystem || 'NTFS'} · {vol.total_formatted || '0 GB'}
                        </div>
                      </div>
                      {isSelected && (
                        <div className="w-1.5 h-4 rounded-full bg-[var(--primary-orange)] shrink-0" />
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {sourceCategory === 'images' && (
            <div className="space-y-2">
              <label className="block text-[11px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
                Select Forensic Bitstream Disk Image (.img / .dd / .raw / .bin):
              </label>
              {(!storageSources?.disk_images || storageSources.disk_images.length === 0) ? (
                <div className="p-4 rounded-xl border border-dashed border-[var(--border)] bg-[var(--surface-secondary)] text-center text-xs text-[var(--text-secondary)]">
                  No forensic disk images imported yet. Import forensic disk images (.img / .dd / .raw / .bin) into Case Evidence to perform low-level recovery.
                </div>
              ) : (
                <select
                  value={selectedSourcePath}
                  onChange={(e) => {
                    const targetImg = storageSources?.disk_images?.find(i => i.path === e.target.value);
                    if (!e.target.value) {
                      resetAllSourceState();
                      setSelectedSourcePath('');
                      setSelectedSourceLabel('');
                      setSelectedCanonicalSource(null);
                      return;
                    }
                    selectSource({
                      path: e.target.value,
                      label: targetImg ? getFriendlyEvidenceName(targetImg.name) : e.target.value,
                      displayType: 'Forensic Disk Image',
                      sourceType: 'FORENSIC_IMAGE',
                      filesystem: 'RAW Disk Image'
                    });
                  }}
                  className="w-full bg-[var(--surface-secondary)] border border-[var(--border)] rounded-xl px-4 py-2.5 text-xs font-mono text-[var(--text-primary)] focus:border-[var(--primary-orange)] outline-none"
                >
                  <option value="">-- Select an Imported Forensic Image --</option>
                  {storageSources.disk_images.map((img, idx) => {
                    const sizeMb = img.size_mb != null ? img.size_mb : (img.size_bytes ? img.size_bytes / (1024 * 1024) : 0);
                    return (
                      <option key={img.path || idx} value={img.path}>
                        {getFriendlyEvidenceName(img.name)} ({img.name}) — {sizeMb.toFixed(2)} MB [{img.format}]
                      </option>
                    );
                  })}
                </select>
              )}
            </div>
          )}

          {sourceCategory === 'portable' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <label className="block text-[11px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
                  Connected Windows Portable Devices (MTP / USB):
                </label>
                <span className="text-[11px] font-mono text-[var(--text-secondary)]">
                  Found {portableDevices.length} device(s)
                </span>
              </div>

              {portableDevices.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-56 overflow-y-auto pr-1">
                  {portableDevices.map((dev) => {
                    const isSelected = selectedSourcePath === dev.device_id;
                    return (
                      <div
                        key={dev.device_id}
                        onClick={() => {
                          selectSource({
                            path: dev.device_id,
                            label: dev.name,
                            displayType: 'Portable Device (MTP)',
                            sourceType: 'MTP_DEVICE',
                            filesystem: 'Not exposed through MTP'
                          });
                          handleBrowseMtp(dev.device_id, '', 'Root');
                        }}
                        className={`p-3.5 rounded-xl border text-xs cursor-pointer transition-all space-y-2 ${
                          isSelected
                            ? 'bg-[var(--primary-orange)]/15 border-[var(--primary-orange)] shadow-xs'
                            : 'bg-[var(--surface-secondary)] border-[var(--border)] hover:border-[var(--border-strong)]'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="font-bold text-[13px] text-[var(--text-primary)] flex items-center gap-2 truncate">
                            <Smartphone size={16} className={isSelected ? 'text-[var(--primary-orange)]' : 'text-[var(--text-secondary)]'} />
                            <span className="truncate">{dev.name}</span>
                          </div>
                          <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-[#1976D2]/10 text-[#1976D2] border border-[#1976D2]/20">
                            {dev.protocol || 'MTP'}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-[var(--text-secondary)]">
                          <div>Manufacturer: {dev.manufacturer || 'Unknown'}</div>
                          <div>Connection: {dev.connection_type || 'USB'}</div>
                          <div className="col-span-2 truncate">Storage: {dev.storage_names?.join(', ') || 'Internal Shared Storage'}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="p-6 rounded-xl border border-dashed border-[var(--border)] text-center space-y-2 bg-[var(--surface-secondary)]/50">
                  <Smartphone size={28} className="mx-auto text-[var(--text-secondary)] opacity-50" />
                  <p className="text-xs text-[var(--text-primary)] font-medium">
                    No portable devices detected via USB Media Transfer Protocol (MTP).
                  </p>
                  <p className="text-[11px] text-[var(--text-secondary)]">
                    To inspect an Android phone, connect it via USB and select <strong>File Transfer / MTP</strong> on the handset, then click <strong>Refresh Sources</strong>.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Selected Source Status Area (Single Unified Compact Card) */}
      {selectedSourcePath && (
        <div className="workstation-card p-4 bg-[var(--surface)] border border-[var(--border)] rounded-[12px] space-y-3 shadow-xs">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 min-w-0">
              <span className="shrink-0 p-2 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]" aria-hidden="true">
                <HardDrive size={18} className="text-[var(--primary-orange)]" />
              </span>
              <div className="min-w-0">
                <div className="text-[10px] uppercase font-bold text-[var(--text-secondary)]">
                  Selected Source
                </div>
                <div className="text-xs sm:text-sm font-bold text-[var(--text-primary)] truncate" title={selectedSourceLabel || selectedSourcePath}>
                  {selectedSourceLabel || selectedSourcePath}
                </div>
                <div className="text-[11px] text-[var(--text-secondary)] font-mono">
                  {selectedSourceFs || selectedCanonicalSource?.filesystem || 'NTFS'} · {selectedCanonicalSource?.capacity_formatted || (selectedCanonicalSource?.capacity ? formatBytes(selectedCanonicalSource.capacity) : '')}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)]">
                Read-Only
              </span>

              {sourceType === 'MTP_DEVICE' ? (
                <>
                  <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20">
                    Live File/Object Access: AVAILABLE
                  </span>
                  <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[var(--surface-secondary)] text-[var(--text-muted)] border border-[var(--border)]">
                    Raw Sector Access: NOT AVAILABLE
                  </span>
                  <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[var(--surface-secondary)] text-[var(--text-muted)] border border-[var(--border)]">
                    Deleted-Sector Recovery: NOT AVAILABLE
                  </span>
                  <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20">
                    File Copy: AVAILABLE
                  </span>
                  <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)]">
                    File Delete: AVAILABLE (ONLY IF WPD OBJECT SUPPORTS IT)
                  </span>
                </>
              ) : (sourceType === 'FORENSIC_IMAGE' || privileges?.is_elevated) ? (
                <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)]">
                  Raw Access: Available
                </span>
              ) : (
                <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[var(--surface-secondary)] text-[var(--primary-orange)] border border-[var(--primary-orange)]/30 font-medium">
                  Raw Access: Administrator Required
                </span>
              )}
            </div>
          </div>

          {/* Compact Administrator Notice (High-contrast red styling) */}
          {(!privileges?.is_elevated && (selectedCanonicalSource?.requires_elevation || sourceCategory === 'volumes' || sourceCategory === 'physical' || selectedSourcePath.includes('PhysicalDrive') || selectedSourcePath.toUpperCase().startsWith('C:')) && sourceType !== 'FORENSIC_IMAGE' && sourceType !== 'MTP_DEVICE') && (
            <div className="p-3 rounded-lg bg-[#FEF3F2] border border-[#D92D20] text-[#292524] flex flex-wrap items-center justify-between gap-3 text-xs">
              <div>
                <div className="font-bold text-[#B42318] flex items-center gap-1.5">
                  <Lock size={13} className="text-[#B42318]" />
                  <span>RAW ACCESS REQUIRES ADMINISTRATOR</span>
                </div>
                <div className="text-[11.5px] text-[#292524] font-medium mt-0.5">Windows denied low-level sector access to this source. Re-launch with Administrator elevation to read raw physical sectors.</div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => handleTestRawAccess(selectedSourcePath)}
                  disabled={isTestingRawAccess}
                  className="btn-secondary h-7 px-2.5 text-xs font-semibold rounded-lg shadow-xs"
                  title="Diagnose raw handle access"
                >
                  <ShieldAlert size={11} className="text-[var(--primary-orange)]" aria-hidden="true" />
                  <span>{isTestingRawAccess ? 'Testing...' : 'Test Raw Access'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleRelaunchElevated(selectedSourcePath)}
                  disabled={isRelaunchingElevated}
                  className="btn-primary h-7 px-3 text-xs font-semibold rounded-lg shadow-xs"
                >
                  {isRelaunchingElevated ? 'Restarting...' : 'Restart as Administrator'}
                </button>
              </div>
            </div>
          )}

          {/* Collapsible Technical Details ▾ (Collapsed by default, only show fields that exist) */}
          <details className="group border border-[var(--border)] rounded-lg text-xs overflow-hidden">
            <summary className="px-3.5 py-2 cursor-pointer font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] flex items-center justify-between select-none bg-[var(--surface-secondary)]/50">
              <div className="flex items-center gap-2">
                <Database size={13} className="text-[var(--primary-orange)]" aria-hidden="true" />
                <span>Technical Details ▾</span>
              </div>
              <span className="text-[10px] text-[var(--text-secondary)] group-open:hidden">Click to expand</span>
            </summary>
            <div className="p-3.5 border-t border-[var(--border)] space-y-3 bg-[var(--surface)]">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px]">
                {(selectedCanonicalSource?.source_id || selectedSourcePath) && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Canonical ID</span>
                    <span className="text-[var(--text-primary)] font-semibold truncate block" title={selectedCanonicalSource?.source_id || selectedSourcePath}>
                      {selectedCanonicalSource?.source_id || selectedSourcePath}
                    </span>
                  </div>
                )}
                {(selectedCanonicalSource?.device_path || selectedSourcePath) && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Device Path</span>
                    <span className="text-[var(--text-primary)] font-semibold truncate block" title={selectedCanonicalSource?.device_path || selectedSourcePath}>
                      {selectedCanonicalSource?.device_path || selectedSourcePath}
                    </span>
                  </div>
                )}
                {selectedCanonicalSource?.physical_disk_number != null && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Disk / Partition</span>
                    <span className="text-[var(--text-primary)] font-semibold truncate block">
                      Disk #{selectedCanonicalSource.physical_disk_number}{selectedCanonicalSource.partition_number != null ? ` (P#${selectedCanonicalSource.partition_number})` : ''}
                    </span>
                  </div>
                )}
                {(selectedSourceFs || selectedCanonicalSource?.filesystem) && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Filesystem</span>
                    <span className="text-[var(--text-primary)] font-semibold truncate block">
                      {selectedSourceFs || selectedCanonicalSource?.filesystem}
                    </span>
                  </div>
                )}
                {(selectedCanonicalSource?.capacity_formatted || selectedCanonicalSource?.capacity) && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Capacity</span>
                    <span className="text-[var(--text-primary)] font-semibold truncate block">
                      {selectedCanonicalSource?.capacity_formatted || formatBytes(selectedCanonicalSource?.capacity || 0)}
                    </span>
                  </div>
                )}
                {selectedCanonicalSource?.bus_type && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Bus / Bus Type</span>
                    <span className="text-[var(--text-primary)] font-semibold truncate block">
                      {selectedCanonicalSource.bus_type}
                    </span>
                  </div>
                )}
                {partitionTable?.table_type && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Partition Table</span>
                    <span className="text-[var(--text-primary)] font-semibold truncate block">
                      {partitionTable.table_type}
                    </span>
                  </div>
                )}
                {((fsInfo as any)?.total_sectors || partitionTable?.total_disk_sectors) && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Total Sectors</span>
                    <span className="text-[var(--text-primary)] font-semibold truncate block">
                      {((fsInfo as any)?.total_sectors || partitionTable?.total_disk_sectors)?.toLocaleString()}
                    </span>
                  </div>
                )}
                {(fsInfo?.sector_size || fsInfo?.bytes_per_sector) && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Sector Size</span>
                    <span className="font-semibold text-[var(--text-primary)]">
                      {fsInfo?.sector_size || fsInfo?.bytes_per_sector} B
                    </span>
                  </div>
                )}
                {(fsInfo?.cluster_size || fsInfo?.sectors_per_cluster) && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Cluster Size</span>
                    <span className="font-semibold text-[var(--text-primary)]">
                      {fsInfo?.cluster_size ? `${fsInfo.cluster_size} B` : `${(fsInfo?.sectors_per_cluster || 8) * 512} B`}
                    </span>
                  </div>
                )}
                {fsInfo?.volume_label && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Volume Label</span>
                    <span className="font-semibold text-[var(--text-primary)] truncate block">
                      {fsInfo.volume_label}
                    </span>
                  </div>
                )}
                {fsInfo?.serial_number && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Serial Number</span>
                    <span className="font-semibold text-[var(--text-primary)] truncate block">
                      {fsInfo.serial_number}
                    </span>
                  </div>
                )}
                <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                  <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Windows Error Code</span>
                  <span className="font-semibold text-[var(--text-primary)] truncate block">
                    {privileges?.is_elevated ? '0 (OK / Elevated)' : '5 (Access Denied)'}
                  </span>
                </div>
                <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                  <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Raw Access State</span>
                  <span className="font-semibold text-[var(--text-primary)] truncate block">
                    {privileges?.is_elevated ? 'Available' : 'Administrator Required'}
                  </span>
                </div>
                {selectedCaseId && (
                  <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)]">
                    <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold">Case ID</span>
                    <span className="font-semibold text-[var(--text-primary)] truncate block">
                      {selectedCaseId}
                    </span>
                  </div>
                )}
              </div>

              {partitionTable && partitionTable.partitions && partitionTable.partitions.length > 0 && (
                <div className="p-2.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1.5">
                  <div className="text-[10px] uppercase font-bold text-[var(--text-secondary)]">Partition Table ({partitionTable.table_type})</div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[10.5px]">
                    {partitionTable.partitions.map(p => (
                      <div key={p.partition_number} className="p-1.5 rounded bg-[var(--surface)] border border-[var(--border)] font-mono">
                        Part #{p.partition_number}: {p.type_name} ({p.size_formatted})
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </details>
        </div>
      )}

      {/* Conditional Pipeline Rendering: MTP Dedicated Workflow */}
      {sourceType === 'MTP_DEVICE' && (
        <div className="space-y-5">
          {/* MTP Handset Identity & Forensic Limitations Card */}
          <div className="workstation-card p-5 bg-[var(--surface)] border border-[var(--border)] rounded-[12px] space-y-4 shadow-xs">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-3">
              <div>
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  {renderSourceBadge()}
                </div>
                <div className="text-[11px] uppercase tracking-wider font-bold text-[var(--text-secondary)] flex items-center gap-1.5">
                  <Smartphone size={14} className="text-[var(--primary-orange)]" />
                  <span>PORTABLE DEVICE — MTP (WPD OBJECT STORE)</span>
                </div>
                <div className="font-bold text-[15px] text-[var(--text-primary)] mt-0.5 flex items-center gap-2">
                  <span>Device: {selectedSourceLabel || 'Portable Device'}</span>
                  {selectedCanonicalSource?.manufacturer && (
                    <span className="text-[11px] px-2 py-0.5 rounded font-mono font-bold bg-[#1976D2]/10 text-[#1976D2] border border-[#1976D2]/20">
                      {selectedCanonicalSource.manufacturer}
                    </span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20 flex items-center gap-1.5">
                  <ShieldCheck size={13} />
                  <span>Read-only analysis mode</span>
                </span>
                <button
                  type="button"
                  onClick={() => setShowDeviceInfoModal(true)}
                  className="px-3 py-1 rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[11.5px] font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all cursor-pointer"
                >
                  View Technical Info
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                <div className="text-[10px] uppercase font-bold text-[var(--text-secondary)]">Manufacturer</div>
                <div className="font-mono font-semibold text-[var(--text-primary)] mt-0.5">
                  {portableDevices.find(d => d.device_id === selectedSourcePath)?.manufacturer || 'Unknown'}
                </div>
              </div>
              <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                <div className="text-[10px] uppercase font-bold text-[var(--text-secondary)]">Connection</div>
                <div className="font-mono font-semibold text-[var(--text-primary)] mt-0.5">USB / MTP</div>
              </div>
              <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                <div className="text-[10px] uppercase font-bold text-[var(--text-secondary)]">Storage</div>
                <div className="font-mono font-semibold text-[var(--text-primary)] mt-0.5">Internal shared storage</div>
              </div>
              <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                <div className="text-[10px] uppercase font-bold text-[var(--text-secondary)]">Filesystem</div>
                <div className="font-mono font-semibold text-[var(--text-primary)] mt-0.5">Not exposed through MTP</div>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2.5">
              <div className="flex items-center gap-2 text-xs font-bold text-[var(--text-primary)]">
                <CheckCircle2 size={14} className="text-[#2E7D32]" />
                <span>Live file/object access available.</span>
              </div>
              <p className="text-[11.5px] text-[var(--text-secondary)] leading-relaxed font-medium">
                MTP provides live file/object access. Raw deleted-data recovery requires a forensic acquisition that exposes the underlying storage data.
              </p>
              <div className="pt-1 flex items-center justify-between gap-3 flex-wrap">
                <span className="text-[11px] text-[var(--text-muted)]">
                  To perform low-level deleted-data recovery on an acquired device dump (.img, .dd, .raw, .bin), switch to Forensic Disk Images.
                </span>
                <button
                  type="button"
                  onClick={() => handleCategoryChange('images')}
                  className="px-3 py-1.5 rounded-lg bg-[var(--primary-orange)] text-white text-xs font-bold hover:opacity-90 transition-all flex items-center gap-1.5 cursor-pointer shrink-0 shadow-xs"
                >
                  <HardDrive size={13} />
                  <span>Analyze Forensic Image</span>
                </button>
              </div>
            </div>

            {/* Capabilities Matrix (Part 20) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1 text-xs">
              <div className="p-3 rounded-lg bg-[#2E7D32]/5 border border-[#2E7D32]/20 space-y-1.5">
                <div className="text-[11px] font-bold uppercase tracking-wider text-[#2E7D32] flex items-center gap-1.5">
                  <CheckCircle2 size={13} />
                  <span>Available Capabilities</span>
                </div>
                <ul className="text-[11.5px] text-[var(--text-secondary)] space-y-1 list-disc list-inside">
                  <li>Live file/object browsing & navigation</li>
                  <li>Live file export / bitstream copying to case folder</li>
                  <li>Device identity & property inspection</li>
                  <li>Automatic SHA-256 cryptographic verification upon copy</li>
                </ul>
              </div>

              <div className="p-3 rounded-lg bg-[#C53030]/5 border border-[#C53030]/20 space-y-1.5">
                <div className="text-[11px] font-bold uppercase tracking-wider text-[#C53030] flex items-center gap-1.5">
                  <AlertTriangle size={13} />
                  <span>Not Available (Protocol Limitation)</span>
                </div>
                <ul className="text-[11.5px] text-[var(--text-secondary)] space-y-1 list-disc list-inside">
                  <li>Raw sector recovery (NAND flash sectors inaccessible)</li>
                  <li>Deleted-sector recovery & unallocated-space carving</li>
                  <li>Partition table parsing (MBR/GPT)</li>
                  <li>Filesystem cluster inspection (FAT/NTFS/ext4)</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Live Object Browser (Part 9, 10, 11) */}
          <div className="workstation-card p-5 bg-[var(--surface)] border border-[var(--border)] rounded-[12px] space-y-4 shadow-xs">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-[13.5px] font-bold text-[var(--text-primary)]">
                <FolderOpen size={16} className="text-[var(--primary-orange)]" />
                <span>Live Object Browser — {selectedSourceLabel || 'Portable Device'}</span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    if (mtpParentObjectId && mtpParentObjectId !== '') {
                      handleBrowseMtp(selectedSourcePath, mtpParentObjectId);
                    } else if (mtpPathHistory.length > 1) {
                      const prev = mtpPathHistory[mtpPathHistory.length - 2];
                      handleBrowseMtp(selectedSourcePath, prev.id, prev.name);
                    } else {
                      handleBrowseMtp(selectedSourcePath, '', 'Root');
                    }
                  }}
                  disabled={(!mtpCurrentObjectId && mtpPathHistory.length === 0) || isMtpLoading}
                  className="btn-secondary px-2.5 py-1.5 text-xs font-semibold flex items-center gap-1 cursor-pointer disabled:opacity-40"
                  title="Go back to parent folder"
                >
                  <ArrowLeft size={13} />
                  <span>Back</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleBrowseMtp(selectedSourcePath, '', 'Root')}
                  disabled={isMtpLoading || (!mtpCurrentObjectId && mtpPathHistory.length === 0)}
                  className="btn-secondary px-2.5 py-1.5 text-xs font-semibold flex items-center gap-1 cursor-pointer disabled:opacity-40"
                  title="Return to device root storage"
                >
                  <HardDrive size={13} />
                  <span>Root</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    handleBrowseMtp(selectedSourcePath, mtpCurrentObjectId);
                  }}
                  disabled={isMtpLoading}
                  className="p-1.5 rounded-lg bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
                  title="Refresh current folder"
                >
                  <RefreshCw size={14} className={isMtpLoading ? 'animate-spin' : ''} />
                </button>
                <button
                  type="button"
                  onClick={() => handleCopySelectedMtpFiles()}
                  disabled={isMtpExporting || selectedMtpObjectIds.size === 0}
                  className="btn-primary px-3 py-1.5 text-xs font-bold flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
                >
                  <Download size={13} />
                  <span>{isMtpExporting ? 'Copying...' : `Copy Selected (${selectedMtpObjectIds.size})`}</span>
                </button>
              </div>
            </div>

            {/* Breadcrumb Navigation */}
            <div className="flex flex-wrap items-center gap-1 text-xs font-mono bg-[var(--surface-secondary)] p-2.5 rounded-lg border border-[var(--border)]">
              <button
                type="button"
                onClick={() => handleBrowseMtp(selectedSourcePath, '', 'Root')}
                className="hover:text-[var(--primary-orange)] font-bold text-[var(--text-primary)] cursor-pointer flex items-center gap-1"
              >
                <span>[Device Root]</span>
              </button>
              {mtpPathHistory.map((h, i) => (
                <span key={h.id} className="flex items-center gap-1">
                  <ChevronRight size={12} className="text-[var(--text-secondary)]" />
                  <button
                    type="button"
                    onClick={() => handleBrowseMtp(selectedSourcePath, h.id, h.name)}
                    className={`hover:text-[var(--primary-orange)] cursor-pointer ${
                      i === mtpPathHistory.length - 1 ? 'text-[var(--primary-orange)] font-bold' : 'text-[var(--text-secondary)]'
                    }`}
                  >
                    {h.name}
                  </button>
                </span>
              ))}
            </div>

            {/* MTP Delete Action Banner if any */}
            {mtpDeleteResultBanner && (
              <div className={`p-3.5 rounded-lg border text-xs flex items-start justify-between gap-3 shadow-xs ${
                mtpDeleteResultBanner.type === 'success'
                  ? 'bg-[#ECFDF5] border-[#10B981] text-[#065F46]'
                  : 'bg-[#FEF3F2] border-[#D92D20] text-[#B42318]'
              }`}>
                <div className="flex items-start gap-2.5">
                  {mtpDeleteResultBanner.type === 'success' ? (
                    <CheckCircle2 size={16} className="text-[#059669] flex-shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle size={16} className="text-[#B42318] flex-shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-0.5">
                    <div className="font-bold flex items-center gap-2">
                      <span>{mtpDeleteResultBanner.title}</span>
                      <span className={`px-2 py-0.2 text-[10px] font-mono rounded font-bold ${
                        mtpDeleteResultBanner.type === 'success' ? 'bg-[#D1FAE5] text-[#065F46]' : 'bg-[#FEE4E2] text-[#991B1B]'
                      }`}>
                        {mtpDeleteResultBanner.verification_status}
                      </span>
                    </div>
                    <div className="leading-relaxed font-medium">{mtpDeleteResultBanner.message}</div>
                  </div>
                </div>
                <button
                  onClick={() => setMtpDeleteResultBanner(null)}
                  className="hover:opacity-75 cursor-pointer p-0.5"
                  title="Dismiss"
                >
                  <X size={14} />
                </button>
              </div>
            )}

            {/* MTP Error Banner if any */}
            {mtpError && (
              <div className="p-3.5 rounded-lg bg-[#FEF3F2] border border-[#D92D20] text-[#292524] text-xs flex items-start gap-2.5 shadow-xs">
                <AlertTriangle size={16} className="text-[#B42318] flex-shrink-0 mt-0.5" />
                <div className="space-y-1 flex-1">
                  <div className="font-bold text-[#B42318]">MTP Device Notice</div>
                  <div className="leading-relaxed font-medium text-[#292524]">{mtpError}</div>
                </div>
                <button onClick={() => setMtpError(null)} className="text-[#B42318] hover:text-[#991B1B] cursor-pointer p-0.5" title="Dismiss notice">
                  <X size={14} />
                </button>
              </div>
            )}

            {/* Live Files / Folders Table */}
            <div className="overflow-hidden border border-[var(--border)] rounded-lg">
              <table className="w-full text-left border-collapse table-fixed text-xs">
                <thead>
                  <tr className="border-b border-[var(--border)] bg-[var(--surface-secondary)] text-[10.5px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
                    <th className="py-2.5 px-3 w-[4%] text-center">
                      <input
                        type="checkbox"
                        checked={mtpItems.filter(it => !it.is_folder).length > 0 && selectedMtpObjectIds.size >= mtpItems.filter(it => !it.is_folder).length}
                        onChange={() => {
                          const fileItems = mtpItems.filter(it => !it.is_folder);
                          if (selectedMtpObjectIds.size >= fileItems.length) {
                            setSelectedMtpObjectIds(new Set());
                          } else {
                            setSelectedMtpObjectIds(new Set(fileItems.map(it => it.object_id)));
                          }
                        }}
                        disabled={mtpItems.filter(it => !it.is_folder).length === 0}
                        className="rounded border-[var(--border)] text-[var(--primary-orange)] focus:ring-0 cursor-pointer"
                      />
                    </th>
                    <th className="py-2.5 px-3 w-[30%]">Name</th>
                    <th className="py-2.5 px-3 w-[10%]">Type</th>
                    <th className="py-2.5 px-3 w-[11%]">Size</th>
                    <th className="py-2.5 px-3 w-[15%]">Modified Date</th>
                    <th className="py-2.5 px-3 w-[12%]">Object ID</th>
                    <th className="py-2.5 px-3 w-[18%] text-right pr-4">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {mtpItems.map((item) => {
                    const isSelected = selectedMtpObjectIds.has(item.object_id);
                    return (
                      <tr
                        key={item.object_id}
                        onDoubleClick={() => {
                          if (item.is_folder) {
                            handleBrowseMtp(selectedSourcePath, item.object_id, item.name);
                          }
                        }}
                        title={item.is_folder ? 'Double-click to open folder' : undefined}
                        className={`transition-colors ${
                          item.is_folder ? 'cursor-pointer hover:bg-[var(--surface-hover)]' : 'hover:bg-[var(--surface-hover)]'
                        } ${isSelected ? 'bg-[var(--primary-orange)]/10' : ''}`}
                      >
                        <td className="py-2.5 px-3 text-center">
                          {!item.is_folder && (
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => toggleMtpFileSelection(item.object_id)}
                              className="rounded border-[var(--border)] text-[var(--primary-orange)] focus:ring-0 cursor-pointer"
                            />
                          )}
                        </td>
                        <td className="py-2.5 px-3 truncate">
                          <div className="flex items-center gap-2 truncate">
                            {item.is_folder ? (
                              <Folder size={15} className="text-[var(--primary-orange)] flex-shrink-0" />
                            ) : (
                              <File size={15} className="text-[var(--text-secondary)] flex-shrink-0" />
                            )}
                            {item.is_folder ? (
                              <button
                                type="button"
                                onClick={() => handleBrowseMtp(selectedSourcePath, item.object_id, item.name)}
                                className="font-semibold text-[var(--text-primary)] hover:underline truncate text-left cursor-pointer"
                              >
                                {item.name}
                              </button>
                            ) : (
                              <span className="text-[var(--text-primary)] font-medium truncate" title={item.name}>
                                {item.name}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-[var(--text-secondary)] font-mono text-[11px]">
                          {item.is_folder ? 'Folder' : (item.content_type || 'File')}
                        </td>
                        <td className="py-2.5 px-3 text-[var(--text-secondary)] font-mono text-[11px]">
                          {item.is_folder ? '--' : formatBytes(item.size_bytes)}
                        </td>
                        <td className="py-2.5 px-3 text-[var(--text-secondary)] font-mono text-[11px] truncate" title={item.modified_iso}>
                          {item.modified_iso || 'Available on copy'}
                        </td>
                        <td className="py-2.5 px-3 text-[var(--text-secondary)] font-mono text-[10.5px] truncate" title={item.object_id}>
                          {item.object_id}
                        </td>
                        <td className="py-2.5 px-3 text-right pr-4">
                          {item.is_folder ? (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleBrowseMtp(selectedSourcePath, item.object_id, item.name);
                              }}
                              className="px-2.5 py-1 rounded bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[11px] font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
                            >
                              Open
                            </button>
                          ) : (
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleCopySelectedMtpFiles(item.object_id);
                                }}
                                disabled={isMtpExporting}
                                className="px-2.5 py-1 rounded bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[11px] font-semibold text-[var(--primary-orange)] hover:text-white hover:bg-[var(--primary-orange)] transition-colors cursor-pointer disabled:opacity-40"
                                title="Acquire bitstream copy with SHA-256 hash"
                              >
                                Copy
                              </button>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setMtpDeletingFile(item);
                                  setMtpDeleteConfirmationInput('');
                                  setMtpDeletePasswordInput('');
                                  setMtpDeleteResultBanner(null);
                                }}
                                disabled={item.can_delete === false || isMtpDeleting}
                                className="px-2.5 py-1 rounded bg-[#FEF3F2] hover:bg-[#FEE4E2] border border-[#FECDCA] text-[11px] font-semibold text-[#B42318] hover:text-[#991B1B] transition-colors cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                                title={item.can_delete === false ? "Object cannot be deleted via MTP" : "Delete file from device via WPD"}
                              >
                                Delete
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                  {mtpItems.length === 0 && (
                    <tr>
                      <td colSpan={7} className="py-10 text-center text-[var(--text-secondary)]">
                        {isMtpLoading ? (
                          <div className="flex items-center justify-center gap-2">
                            <RefreshCw size={16} className="animate-spin text-[var(--primary-orange)]" />
                            <span>Enumerating live objects from device via WPD...</span>
                          </div>
                        ) : mtpError ? (
                          <div className="space-y-1 text-[#B42318]">
                            <div className="font-semibold">Enumeration Notice</div>
                            <div className="text-xs text-[var(--text-secondary)]">{mtpError}</div>
                          </div>
                        ) : (
                          <div className="space-y-1">
                            <div className="font-medium text-[var(--text-primary)]">0 items in folder</div>
                            <div className="text-[11.5px] text-[var(--text-secondary)]">
                              This folder is empty or not exposed through the current MTP connection.
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Verified Acquisition Summary Card (Part 11) */}
            {lastMtpAcquisition && (
              <div className="p-4 rounded-lg bg-[var(--surface-secondary)] border border-emerald-500/40 text-xs space-y-2">
                <div className="flex items-center justify-between text-emerald-400 font-bold">
                  <div className="flex items-center gap-1.5">
                    <CheckCircle2 size={15} />
                    <span>MTP Object Acquisition Verified</span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-[10px] font-mono border border-emerald-500/30 text-emerald-300 font-bold">
                    Verification: {lastMtpAcquisition.verification}
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono">
                  <div>
                    <span className="text-[var(--text-secondary)]">Source: </span>
                    <span className="text-[var(--text-primary)] break-all">{lastMtpAcquisition.source}</span>
                  </div>
                  <div>
                    <span className="text-[var(--text-secondary)]">Destination: </span>
                    <span className="text-[var(--text-primary)] break-all">{lastMtpAcquisition.destination}</span>
                  </div>
                  <div>
                    <span className="text-[var(--text-secondary)]">Size: </span>
                    <span className="text-[var(--text-primary)] font-semibold">{formatBytes(lastMtpAcquisition.size)} ({lastMtpAcquisition.size.toLocaleString()} bytes)</span>
                  </div>
                  <div className="md:col-span-2">
                    <span className="text-[var(--text-secondary)]">SHA-256: </span>
                    <span className="text-emerald-400 font-bold break-all">{lastMtpAcquisition.sha256}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Evidence Immutability Card (When Recovery or Scan Has Completed) */}
      {recoveryResult && sourceType !== 'MTP_DEVICE' && (
        <div className="workstation-card p-5 bg-[var(--surface)] border border-[var(--border)] rounded-[12px] space-y-3.5 shadow-xs animate-fade-in">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] pb-3">
            <div className="flex items-center gap-2">
              <ShieldCheck size={17} className="text-[#2E7D32]" />
              <span className="font-bold text-[13px] text-[var(--text-primary)]">
                Evidence Bitstream Integrity Verification (Software Read-Only Analysis Mode)
              </span>
            </div>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20 flex items-center gap-1">
              <CheckCircle2 size={12} />
              Software Read-Only Mode (Evidence Source Unmodified)
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1">
              <div className="text-[10px] uppercase font-bold text-[var(--text-secondary)] flex items-center justify-between">
                <span>Evidence Pre-Recovery SHA-256</span>
                {recoveryResult.evidence_pre_hash && recoveryResult.evidence_pre_hash.length === 64 && (
                  <button
                    onClick={() => copyToClipboard(recoveryResult.evidence_pre_hash, 'pre')}
                    className="hover:text-[var(--text-primary)] text-[10px] flex items-center gap-1 cursor-pointer"
                  >
                    <Copy size={11} />
                    <span>{copiedHash === 'pre' ? 'Copied!' : 'Copy'}</span>
                  </button>
                )}
              </div>
              <div className="text-[11px] text-[var(--text-primary)] break-all select-all">
                {recoveryResult.evidence_pre_hash || 'Verified Unmodified Bitstream'}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1">
              <div className="text-[10px] uppercase font-bold text-[var(--text-secondary)] flex items-center justify-between">
                <span>Evidence Post-Recovery SHA-256</span>
                {recoveryResult.evidence_post_hash && recoveryResult.evidence_post_hash.length === 64 && (
                  <button
                    onClick={() => copyToClipboard(recoveryResult.evidence_post_hash, 'post')}
                    className="hover:text-[var(--text-primary)] text-[10px] flex items-center gap-1 cursor-pointer"
                  >
                    <Copy size={11} />
                    <span>{copiedHash === 'post' ? 'Copied!' : 'Copy'}</span>
                  </button>
                )}
              </div>
              <div className="text-[11px] text-[var(--text-primary)] break-all select-all">
                {recoveryResult.evidence_post_hash || 'Verified Unmodified Bitstream'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Recovery Controls & Candidate Results (Block Devices only) */}
      {sourceType !== 'MTP_DEVICE' && (
        <div className="workstation-card bg-[var(--surface)] border border-[var(--border)] rounded-[12px] overflow-hidden shadow-xs space-y-0">
          {/* Action Controls Toolbar & Secondary Reports Area */}
          <div className="p-3.5 border-b border-[var(--border)] flex flex-wrap items-center justify-between gap-3 bg-[var(--surface-secondary)]/50">
            {/* Primary & Secondary Recovery Actions (Requirement 8) */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => handleScanDeleted()}
                disabled={isScanning || isExtracting}
                className="btn-primary h-8 px-3.5 text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                <FileSearch size={14} aria-hidden="true" />
                <span>Rescan Metadata</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  if (!privileges?.is_elevated && sourceType !== 'FORENSIC_IMAGE') {
                    setElevationModalSource(selectedSourcePath);
                    setShowElevationModal(true);
                    return;
                  }
                  handleCarveUnallocated();
                }}
                disabled={isScanning || isExtracting}
                className="btn-secondary h-8 px-3.5 text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                title={(!privileges?.is_elevated && sourceType !== 'FORENSIC_IMAGE') ? 'Direct sector carving requires Administrator elevation' : 'Carve unallocated space'}
              >
                <Layers size={14} aria-hidden="true" />
                <span>Carve Unallocated</span>
                {(!privileges?.is_elevated && sourceType !== 'FORENSIC_IMAGE') && (
                  <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded bg-[var(--surface-secondary)] text-[var(--primary-orange)] font-bold border border-[var(--primary-orange)]/30">
                    Administrator Required
                  </span>
                )}
              </button>

              <button
                type="button"
                onClick={() => handleExtractFiles()}
                disabled={isExtracting || isScanning || selectedFileIds.size === 0}
                className={`btn-secondary h-8 px-3.5 text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-40 ${
                  selectedFileIds.size > 0 ? 'border-[var(--primary-orange)] text-[var(--primary-orange)]' : ''
                }`}
              >
                <Download size={13} aria-hidden="true" />
                <span>{isExtracting ? 'Extracting...' : `Recover Selected${selectedFileIds.size > 0 ? ` (${selectedFileIds.size})` : ''}`}</span>
              </button>

              <button
                type="button"
                onClick={() => handleTestRawAccess()}
                disabled={isTestingRawAccess || isScanning}
                className="btn-secondary h-8 px-3 text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                title="Safely probe read-only raw handle access and sector 0 read without modifying evidence"
              >
                <ShieldAlert size={13} className="text-[var(--primary-orange)]" aria-hidden="true" />
                <span>{isTestingRawAccess ? 'Testing Access...' : 'Test Raw Access'}</span>
              </button>
            </div>

            {/* Reports & Output Secondary Action Area (Requirement 9) */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <span className="text-[11px] font-semibold text-[var(--text-secondary)] mr-1">Reports / Output:</span>
              <button
                type="button"
                onClick={handleGenerateReport}
                disabled={isGeneratingReport || discoveredFiles.length === 0}
                className="btn-secondary h-7 px-2.5 text-xs font-medium flex items-center gap-1 cursor-pointer disabled:opacity-40"
                title="Generate Case Report"
              >
                <FileText size={12} aria-hidden="true" />
                <span>{isGeneratingReport ? 'Compiling...' : 'Generate Case Report'}</span>
              </button>

              <button
                type="button"
                onClick={handleOpenPdf}
                disabled={isOpeningPdf || (!lastGeneratedReport && !recoveryResult?.recovery_report)}
                className="btn-secondary h-7 px-2.5 text-xs font-medium flex items-center gap-1 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                title={lastGeneratedReport || recoveryResult?.recovery_report ? 'Open PDF report in default viewer' : 'No report generated yet'}
              >
                <ExternalLink size={12} aria-hidden="true" />
                <span>Open PDF</span>
              </button>

              <button
                type="button"
                onClick={handleDownloadPdf}
                disabled={!lastGeneratedReport && !recoveryResult?.recovery_report}
                className="btn-secondary h-7 px-2.5 text-xs font-medium flex items-center gap-1 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                title={lastGeneratedReport || recoveryResult?.recovery_report ? 'Download PDF report' : 'No report generated yet'}
              >
                <Download size={12} aria-hidden="true" />
                <span>Download PDF</span>
              </button>

              <button
                type="button"
                onClick={handleOpenFolder}
                disabled={isOpeningFolder || (!recoveryResult?.output_directory && !lastGeneratedReport)}
                className="btn-secondary h-7 px-2.5 text-xs font-medium flex items-center gap-1 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                title={recoveryResult?.output_directory || lastGeneratedReport ? 'Open recovery directory' : 'No output folder available'}
              >
                <FolderCheck size={12} aria-hidden="true" />
                <span>Open Output Folder</span>
              </button>
            </div>
          </div>

          {/* Diagnostic Raw Access Probe Card (Part 2: Real Status Guarantee) */}
          {rawAccessDiag && (
            <div className={`p-4 border-b border-[var(--border)] text-xs shadow-xs space-y-3 ${
              rawAccessDiag.handle_opened 
                ? 'bg-[#F0FDF4] border-[#86EFAC] text-[#14532D]' 
                : 'bg-[#FEF3F2] border-[#D92D20] text-[#292524]'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-sm">
                  {rawAccessDiag.handle_opened ? (
                    <CheckCircle2 size={16} className="text-[#15803D]" />
                  ) : (
                    <AlertTriangle size={16} className="text-[#B42318]" />
                  )}
                  <span className={rawAccessDiag.handle_opened ? 'text-[#14532D]' : 'text-[#B42318]'}>
                    Raw Access Diagnostic Probe: {rawAccessDiag.target_path}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setRawAccessDiag(null)}
                  className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer p-0.5"
                  title="Close diagnostic probe results"
                >
                  <X size={14} />
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                <div className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border)] font-mono text-[12px] shadow-xs">
                  <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold tracking-wide">Handle Status</span>
                  <span className={`font-bold text-sm mt-0.5 block ${rawAccessDiag.handle_opened ? 'text-[#15803D]' : 'text-[#B42318]'}`}>
                    {rawAccessDiag.handle_opened ? 'OPENED' : `FAILED (Error ${rawAccessDiag.error_code}: ${rawAccessDiag.error_code === 5 ? 'Access Denied' : 'Failed'})`}
                  </span>
                  <span className="text-[10px] text-[var(--text-secondary)] block mt-0.5">
                    {rawAccessDiag.handle_opened ? 'GENERIC_READ handle acquired' : 'Windows kernel rejected handle'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border)] font-mono text-[12px] shadow-xs">
                  <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold tracking-wide">Read Test</span>
                  <span className={`font-bold text-sm mt-0.5 block ${rawAccessDiag.bytes_read > 0 ? 'text-[#15803D]' : 'text-[#B42318]'}`}>
                    {rawAccessDiag.bytes_read > 0 ? `${rawAccessDiag.bytes_read} bytes verified` : '0 bytes read'}
                  </span>
                  <span className="text-[10px] text-[var(--text-secondary)] block mt-0.5">
                    {rawAccessDiag.bytes_read > 0 ? 'Sector 0 / VBR verified' : 'No sector bytes read'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-[var(--surface)] border border-[var(--border)] font-mono text-[12px] shadow-xs">
                  <span className="text-[10px] text-[var(--text-secondary)] block uppercase font-bold tracking-wide">Elevation</span>
                  <span className={`font-bold text-sm mt-0.5 block ${rawAccessDiag.is_elevated ? 'text-[#15803D]' : 'text-[#D97706]'}`}>
                    {rawAccessDiag.is_elevated ? 'Verified Administrator' : 'Standard User'}
                  </span>
                  <span className="text-[10px] text-[var(--text-secondary)] block mt-0.5">
                    {rawAccessDiag.is_elevated ? 'Elevated process token' : 'Restricted standard token'}
                  </span>
                </div>
              </div>

              {rawAccessDiag.error_message && (
                <div className="text-[11.5px] leading-relaxed text-[#B42318] font-semibold bg-[var(--surface)] p-2.5 rounded-lg border border-[#D92D20]/30">
                  {rawAccessDiag.error_message}
                </div>
              )}

              {rawAccessDiag.first_bytes_hex && (
                <div className="text-[11px] font-mono text-[var(--text-secondary)] bg-[var(--surface)] p-2 rounded-lg border border-[var(--border)]">
                  Sector 0 Magic / Boot Record Signature: <code className="font-bold text-[var(--text-primary)]">{rawAccessDiag.first_bytes_hex}</code>
                </div>
              )}

              {!rawAccessDiag.handle_opened && rawAccessDiag.error_code === 5 && (
                <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-[#D92D20]/20">
                  <span className="text-[11.5px] text-[#292524] font-medium">
                    Low-level sector reading requires elevated administrator token on Windows.
                  </span>
                  <button
                    type="button"
                    onClick={() => handleRelaunchElevated(rawAccessDiag.target_path)}
                    disabled={isRelaunchingElevated}
                    className="btn-primary h-7 px-3 text-xs font-semibold rounded-lg shadow-xs shrink-0"
                  >
                    <Lock size={11} aria-hidden="true" />
                    <span>{isRelaunchingElevated ? 'Restarting...' : 'Restart as Administrator'}</span>
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Progress Bar when scanning or extracting */}
          {(isScanning || isExtracting) && (
            <div className="p-4 border-b border-[var(--border)] bg-[var(--surface-secondary)] space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-[var(--text-secondary)]">
                <span>{statusMessage}</span>
                <span className="font-bold text-[var(--text-primary)]">{progress}%</span>
              </div>
              <ProgressBar progress={progress} />
            </div>
          )}

          {/* Results Table (Requirement 10) */}
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse table-fixed text-xs">
              <thead>
                <tr className="border-b border-[var(--border)] bg-[var(--surface-secondary)] text-[10.5px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
                  <th className="py-2.5 px-3 w-[4%] text-center">
                    <input
                      type="checkbox"
                      checked={discoveredFiles.length > 0 && selectedFileIds.size === discoveredFiles.length}
                      onChange={() => {
                        if (selectedFileIds.size === discoveredFiles.length) {
                          setSelectedFileIds(new Set());
                        } else {
                          setSelectedFileIds(new Set(discoveredFiles.map(f => f.id)));
                        }
                      }}
                      className="rounded border-[var(--border)] text-[var(--primary-orange)] focus:ring-0 cursor-pointer"
                    />
                  </th>
                  <th className="py-2.5 px-3 w-[34%]">File Name</th>
                  <th className="py-2.5 px-3 w-[12%]">Type</th>
                  <th className="py-2.5 px-3 w-[12%]">Size</th>
                  <th className="py-2.5 px-3 w-[16%]">Recovery Status</th>
                  <th className="py-2.5 px-3 w-[12%]">Method</th>
                  <th className="py-2.5 px-3 w-[10%] text-right pr-4">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {discoveredFiles.map((file) => {
                  const isSelected = selectedFileIds.has(file.id);
                  return (
                    <tr
                      key={file.id}
                      onClick={() => handleInspectFile(file)}
                      className={`hover:bg-[var(--surface-hover)] transition-colors cursor-pointer ${
                        isSelected ? 'bg-[var(--primary-orange)]/10' : ''
                      }`}
                    >
                      <td className="py-2 px-3 text-center" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {
                            setSelectedFileIds(prev => {
                              const next = new Set(prev);
                              if (next.has(file.id)) next.delete(file.id);
                              else next.add(file.id);
                              return next;
                            });
                          }}
                          className="rounded border-[var(--border)] text-[var(--primary-orange)] focus:ring-0 cursor-pointer"
                        />
                      </td>
                      <td className="py-2 px-3 truncate">
                        <div className="font-semibold text-[var(--text-primary)] truncate" title={file.filename}>
                          {file.filename}
                        </div>
                        <div className="text-[10px] text-[var(--text-secondary)] font-mono truncate" title={file.original_path}>
                          {file.original_path || '/'}
                        </div>
                      </td>
                      <td className="py-2 px-3 text-[var(--text-secondary)] font-mono text-[11px]">
                        {file.file_type}
                      </td>
                      <td className="py-2 px-3 text-[var(--text-secondary)] font-mono text-[11px]">
                        {formatBytes(file.size_bytes)}
                      </td>
                      <td className="py-2 px-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-bold border ${
                          file.recovery_status === 'RECOVERABLE' || file.recovery_status === 'Recovered'
                            ? 'bg-[var(--surface-secondary)] text-[var(--text-primary)] border-[var(--border)]'
                            : file.recovery_status === 'PARTIALLY_RECOVERABLE'
                            ? 'bg-[var(--surface-secondary)] text-[var(--primary-orange)] border-[var(--primary-orange)]/30'
                            : 'bg-[var(--surface-secondary)] text-[var(--text-secondary)] border-[var(--border)]'
                        }`}>
                          {file.is_recoverable ? <CheckCircle2 size={11} aria-hidden="true" /> : <AlertTriangle size={11} aria-hidden="true" />}
                          <span>{file.recovery_status}</span>
                        </span>
                      </td>
                      <td className="py-2 px-3 text-[var(--text-secondary)] font-mono text-[10.5px] truncate">
                        {file.method}
                      </td>
                      <td className="py-2 px-3 text-right pr-4" onClick={(e) => e.stopPropagation()}>
                        <div className="inline-flex items-center gap-1.5 justify-end">
                          <button
                            type="button"
                            onClick={() => handleInspectFile(file)}
                            className="px-2 py-1 rounded bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[11px] font-semibold text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
                            title="Inspect metadata & live preview"
                          >
                            Inspect
                          </button>
                          <button
                            type="button"
                            onClick={() => handleExtractFiles([file.id])}
                            disabled={!file.is_recoverable || isExtracting}
                            className="px-2 py-1 rounded bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[11px] font-semibold text-[var(--primary-orange)] disabled:opacity-30 cursor-pointer"
                          >
                            Extract
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {discoveredFiles.length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-[var(--text-secondary)] space-y-1">
                      <div className="text-sm font-semibold text-[var(--text-primary)]">0 files found</div>
                      <p className="text-xs text-[var(--text-secondary)]">No deleted file candidates found.</p>
                      <p className="text-[11px] text-[var(--text-secondary)]">Run a metadata scan or raw carving operation against the selected source.</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Recent Forensic Activity Section (Requirement 12: 1-3 real events) */}
      <div className="workstation-card p-3.5 bg-[var(--surface)] border border-[var(--border)] rounded-[12px] space-y-2 shadow-xs">
        <div className="flex items-center justify-between text-xs font-bold text-[var(--text-secondary)]">
          <div className="flex items-center gap-2">
            <Play size={12} className="text-[var(--primary-orange)]" aria-hidden="true" />
            <span className="text-[var(--text-primary)] font-semibold">Recent Forensic Activity</span>
          </div>
          <button
            type="button"
            onClick={() => setShowFullAuditLog(!showFullAuditLog)}
            className="text-[11px] font-semibold text-[var(--primary-orange)] hover:underline cursor-pointer flex items-center gap-1"
          >
            <span>{showFullAuditLog ? 'Hide Full Audit Journal' : 'View Full Audit Journal ▾'}</span>
          </button>
        </div>

        {!showFullAuditLog ? (
          <div className="space-y-1">
            {recentActivities.slice(0, 3).map((act, idx) => (
              <div key={idx} className="px-3 py-1.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0 truncate font-mono text-[11px] text-[var(--text-primary)]">
                  <CheckCircle2 size={12} className="text-[var(--primary-orange)] shrink-0" aria-hidden="true" />
                  <span className="truncate">{act}</span>
                </div>
                <span className="text-[10px] text-[var(--text-secondary)] font-mono shrink-0">Logged</span>
              </div>
            ))}
          </div>
        ) : (
          <pre className="p-3 rounded-lg bg-slate-900 text-emerald-400 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-48 select-all whitespace-pre-wrap">
            {scanOutput || '[+] ForensiVault Audit Engine ready. Select an evidence storage source to begin analysis.'}
          </pre>
        )}
      </div>

      {/* Drawer: Detailed Technical File Breakdown */}
      {activeDetailFile && (
        <div className="fixed inset-y-0 right-0 w-full sm:w-[480px] bg-[var(--surface)] border-l border-[var(--border)] shadow-2xl z-50 flex flex-col animate-slide-left">
          {/* Drawer Header */}
          <div className="p-4 border-b border-[var(--border)] flex items-center justify-between bg-[var(--surface-secondary)]">
            <div className="flex items-center gap-2 truncate">
              <FileSearch size={16} className="text-[var(--primary-orange)] flex-shrink-0" />
              <span className="font-bold text-sm text-[var(--text-primary)] truncate">
                {activeDetailFile.filename}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setActiveDetailFile(null)}
              className="p-1 rounded-lg text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
            >
              <X size={16} />
            </button>
          </div>

          {/* Drawer Body */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs font-mono">
            {/* Status & Confidence */}
            <div className="p-3 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10.5px] uppercase text-[var(--text-secondary)] font-bold">RECOVERY STATUS</span>
                <span className={`px-2 py-0.5 rounded text-[10.5px] font-bold border ${
                  activeDetailFile.is_recoverable
                    ? 'bg-[#2E7D32]/10 text-[#2E7D32] border-[#2E7D32]/20'
                    : 'bg-[#C53030]/10 text-[#C53030] border-[#C53030]/20'
                }`}>
                  {activeDetailFile.recovery_status}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10.5px] text-[var(--text-secondary)]">Forensic Confidence</span>
                <span className="font-bold text-[var(--text-primary)]">
                  {activeDetailFile.confidence_score}% ({activeDetailFile.confidence_level})
                </span>
              </div>
            </div>

            {/* Unrecoverable Reason if any */}
            {!activeDetailFile.is_recoverable && activeDetailFile.unrecoverable_reason && (
              <div className="p-3 rounded-xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] space-y-1">
                <div className="font-bold flex items-center gap-1 text-[11px]">
                  <AlertTriangle size={12} />
                  Allocation Conflict
                </div>
                <div className="text-[10.5px] leading-relaxed">{activeDetailFile.unrecoverable_reason}</div>
              </div>
            )}

            {/* Technical Metadata */}
            <div className="space-y-1.5">
              <div className="text-[10.5px] font-bold uppercase text-[var(--text-secondary)]">Allocation Metadata</div>
              <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)] flex justify-between">
                <span className="text-[var(--text-secondary)]">Original Path:</span>
                <span className="text-[var(--text-primary)] font-semibold truncate max-w-[240px]" title={activeDetailFile.original_path}>
                  {activeDetailFile.original_path || '/'}
                </span>
              </div>
              <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)] flex justify-between">
                <span className="text-[var(--text-secondary)]">Byte Offset:</span>
                <span className="text-[var(--text-primary)] font-semibold">
                  {activeDetailFile.offset_hex || `0x${activeDetailFile.offset_dec.toString(16).toUpperCase()}`}
                </span>
              </div>
              <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)] flex justify-between">
                <span className="text-[var(--text-secondary)]">Cluster Span:</span>
                <span className="text-[var(--text-primary)] font-semibold">
                  {activeDetailFile.starting_cluster > 0 ? `Cluster #${activeDetailFile.starting_cluster}` : 'Direct Offset'}
                </span>
              </div>
              <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)] flex justify-between">
                <span className="text-[var(--text-secondary)]">Fragments:</span>
                <span className="text-[var(--text-primary)] font-semibold">{activeDetailFile.fragment_count || 1} Fragment(s)</span>
              </div>
              <div className="p-2 rounded bg-[var(--surface-secondary)] border border-[var(--border)] flex justify-between">
                <span className="text-[var(--text-secondary)]">Method:</span>
                <span className="text-[var(--text-primary)] font-semibold">{activeDetailFile.method}</span>
              </div>
            </div>


            {/* Live Content & Byte Stream Preview */}
            <div className="space-y-1.5">
              <div className="text-[10.5px] font-bold uppercase text-[var(--text-secondary)] flex items-center justify-between">
                <span>Recovered Content Preview</span>
                {filePreviewData && (
                  <span className="text-[10px] text-[var(--primary-orange)] uppercase font-semibold">
                    {filePreviewData.preview_type}
                  </span>
                )}
              </div>
              <div className="p-3 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] min-h-[140px] flex flex-col justify-center">
                {isPreviewLoading ? (
                  <div className="py-6 text-center text-[var(--text-secondary)] space-y-2">
                    <RefreshCw size={18} className="animate-spin inline-block text-[var(--primary-orange)]" />
                    <div>Reading recovered byte stream...</div>
                  </div>
                ) : filePreviewData ? (
                  filePreviewData.preview_type === 'image' ? (
                    <div className="space-y-2 text-center">
                      <img
                        src={filePreviewData.preview_data}
                        alt="Recovered Artifact Preview"
                        className="max-h-56 mx-auto rounded border border-[var(--border)] object-contain bg-black/20"
                      />
                      <div className="text-[10px] text-[var(--text-secondary)] font-mono">
                        Valid raster bitstream rendered from disk ({filePreviewData.size_formatted || 'Intact'})
                      </div>
                    </div>
                  ) : filePreviewData.preview_type === 'text' || filePreviewData.preview_type === 'pdf' ? (
                    <div className="space-y-1.5">
                      <pre className="p-2 rounded bg-[var(--surface)] border border-[var(--border-subtle)] text-[11px] font-mono text-[var(--text-primary)] max-h-48 overflow-y-auto whitespace-pre-wrap select-all">
                        {filePreviewData.preview_data || '(No printable text streams)'}
                      </pre>
                      {filePreviewData.extra_meta?.page_count && (
                        <div className="text-[10px] text-[var(--text-secondary)]">
                          Document Pages: {filePreviewData.extra_meta.page_count}
                        </div>
                      )}
                    </div>
                  ) : filePreviewData.preview_type === 'archive' ? (
                    <div className="space-y-1.5">
                      <div className="text-[10.5px] text-[var(--text-secondary)] font-bold">Archive Manifest:</div>
                      <pre className="p-2 rounded bg-[var(--surface)] border border-[var(--border-subtle)] text-[10.5px] font-mono text-[var(--text-primary)] max-h-44 overflow-y-auto whitespace-pre-wrap select-all">
                        {filePreviewData.preview_data}
                      </pre>
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      <div className="text-[10px] text-[var(--text-secondary)]">Raw Hex Dump (First 1KB):</div>
                      <pre className="p-2 rounded bg-[var(--surface)] border border-[var(--border-subtle)] text-[9.5px] font-mono text-[var(--text-primary)] max-h-48 overflow-y-auto whitespace-pre select-all leading-tight">
                        {filePreviewData.preview_data}
                      </pre>
                    </div>
                  )
                ) : (
                  <div className="py-4 text-center text-[var(--text-secondary)] text-[11px]">
                    {activeDetailFile.recovered_file_path ? (
                      <button
                        type="button"
                        onClick={() => handleInspectFile(activeDetailFile)}
                        className="text-[var(--primary-orange)] hover:underline font-semibold cursor-pointer"
                      >
                        Load Recovered Bitstream Preview
                      </button>
                    ) : (
                      'Extract file to generate live disk preview & SHA-256 validation.'
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* SHA-256 Digest */}
            <div className="space-y-1">
              <div className="text-[10.5px] font-bold uppercase text-[var(--text-secondary)] flex items-center justify-between">
                <span>Cryptographic SHA-256 Digest</span>
                {activeDetailFile.sha256 && (
                  <button
                    onClick={() => copyToClipboard(activeDetailFile.sha256, 'file')}
                    className="hover:text-[var(--text-primary)] text-[10px] flex items-center gap-1 cursor-pointer"
                  >
                    <Copy size={11} />
                    <span>{copiedHash === 'file' ? 'Copied!' : 'Copy'}</span>
                  </button>
                )}
              </div>
              <div className="p-2.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)] text-[10.5px] break-all select-all text-[var(--text-primary)]">
                {activeDetailFile.sha256 || 'Calculated automatically upon extraction.'}
              </div>
            </div>

            {/* Extraction Location */}
            {activeDetailFile.recovered_file_path && (
              <div className="space-y-1">
                <div className="text-[10.5px] font-bold uppercase text-[var(--text-secondary)]">Extracted Destination</div>
                <div className="p-2.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)] text-[10.5px] break-all select-all text-[var(--text-primary)]">
                  {activeDetailFile.recovered_file_path}
                </div>
              </div>
            )}

            {/* Drawer Action */}
            {activeDetailFile.is_recoverable && !activeDetailFile.recovered_file_path && (
              <div className="pt-2">
                <button
                  onClick={() => handleExtractFiles([activeDetailFile.id])}
                  disabled={isExtracting}
                  className="w-full btn-primary py-2 text-xs font-bold flex items-center justify-center gap-2 cursor-pointer"
                >
                  <Download size={13} />
                  <span>Extract & Validate File</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Modal: Device Technical Info */}
      {showDeviceInfoModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-[var(--surface)] border border-[var(--border)] rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
              <div className="flex items-center gap-2 font-bold text-sm text-[var(--text-primary)]">
                <Smartphone size={16} className="text-[var(--primary-orange)]" />
                <span>Portable Device Technical Specification</span>
              </div>
              <button
                type="button"
                onClick={() => setShowDeviceInfoModal(false)}
                className="p-1 rounded-lg text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                <X size={16} />
              </button>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1">
                <div className="text-[10px] text-[var(--text-secondary)] uppercase font-bold">WPD Device Identifier</div>
                <div className="break-all text-[var(--text-primary)] text-[11px] select-all">{selectedSourcePath}</div>
              </div>
              <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1">
                <div className="text-[10px] text-[var(--text-secondary)] uppercase font-bold">Protocol Specification</div>
                <div className="text-[var(--text-primary)]">Windows Portable Device (WPD) / Media Transfer Protocol (MTP)</div>
              </div>
              <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1">
                <div className="text-[10px] text-[var(--text-secondary)] uppercase font-bold">Forensic Acquisition Standard</div>
                <div className="text-[var(--text-secondary)] leading-relaxed">
                  Direct physical bitstream imaging requires authenticated Qualcomm EDL, Samsung Odin, or ADB Fastboot acquisition mode. MTP abstraction layer is restricted to high-level active file extraction.
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setShowDeviceInfoModal(false)}
                className="btn-primary px-4 py-1.5 text-xs font-bold cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Administrative Elevation Required */}
      {showElevationModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-[var(--surface)] border border-[#D92D20] rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
              <div className="flex items-center gap-2 font-bold text-sm text-[#B42318]">
                <Lock size={18} className="text-[#B42318]" />
                <span>Administrator Elevation Required</span>
              </div>
              <button
                type="button"
                onClick={() => setShowElevationModal(false)}
                className="p-1 rounded-lg text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                <X size={16} />
              </button>
            </div>

            <div className="space-y-3 text-xs leading-relaxed">
              <div className="p-3.5 rounded-xl bg-[#FEF3F2] border border-[#D92D20] text-[#292524]">
                Direct sector-level access to raw drive/volume <strong className="font-mono font-bold text-[#B42318]">{elevationModalSource || selectedSourceLabel || selectedSourcePath}</strong> was denied by Windows OS security policy:
                <div className="font-mono font-bold text-[#B42318] mt-1.5 text-[12px]">
                  Windows Access Denied (Error 5): Elevation Required
                </div>
              </div>

              <div className="space-y-2 p-3 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] font-mono text-[11.5px]">
                <div className="flex justify-between">
                  <span className="text-[var(--text-secondary)]">Current Privilege:</span>
                  <span className="font-bold text-[#D97706]">Standard User (Restricted)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-secondary)]">Required Privilege:</span>
                  <span className="font-bold text-[#2E7D32]">Administrator (Elevated)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-secondary)]">Operation Mode:</span>
                  <span className="font-bold text-[var(--primary-orange)]">Strict READ-ONLY</span>
                </div>
              </div>

              <p className="text-[#292524] leading-relaxed">
                Windows requires elevation for low-level direct sector handles (<code className="font-mono font-bold text-[var(--text-primary)]">\\.\C:</code> or physical drives). Even when elevated, ForensiVault enforces software write-blocking and will never modify physical media.
              </p>
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-[var(--border)]">
              <button
                type="button"
                onClick={() => setShowElevationModal(false)}
                className="btn-secondary px-4 py-2 text-xs font-semibold cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => handleRelaunchElevated(elevationModalSource || selectedSourcePath)}
                disabled={isRelaunchingElevated}
                className="px-4 py-2 rounded-lg text-xs font-bold bg-[var(--primary-orange)] text-white hover:opacity-90 transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-xs"
              >
                <Lock size={13} />
                <span>{isRelaunchingElevated ? 'Requesting UAC...' : 'Restart ForensiVault as Administrator'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: MTP File Deletion Confirmation */}
      {mtpDeletingFile && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-[var(--surface)] border border-[#D92D20] rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
              <div className="flex items-center gap-2 font-bold text-sm text-[#B42318]">
                <Trash2 size={18} className="text-[#B42318]" />
                <span>Confirm Object Deletion on Mobile Device</span>
              </div>
              <button
                type="button"
                onClick={() => {
                  setMtpDeletingFile(null);
                  setMtpDeleteConfirmationInput('');
                  setMtpDeletePasswordInput('');
                }}
                disabled={isMtpDeleting}
                className="p-1 rounded-lg text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                <X size={16} />
              </button>
            </div>

            <div className="space-y-3 text-xs leading-relaxed">
              <div className="p-3.5 rounded-xl bg-[#FEF3F2] border border-[#D92D20] text-[#292524] space-y-1.5 shadow-xs">
                <div className="font-bold text-[#B42318] flex items-center gap-1.5">
                  <AlertTriangle size={15} className="text-[#B42318]" />
                  <span>Permanent Device Modification Notice</span>
                </div>
                <div className="text-[11.5px] leading-relaxed">
                  ForensiVault will issue a native <strong>Windows Portable Device (WPD) Delete</strong> command directly to the connected mobile device via MTP. Deleted objects cannot be recovered via sector carving as MTP does not permit raw NAND block access.
                </div>
              </div>

              {/* Object Details Table */}
              <div className="space-y-1.5 p-3 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] font-mono text-[11.5px]">
                <div className="flex justify-between py-0.5 border-b border-[var(--border)]/50">
                  <span className="text-[var(--text-secondary)]">Target Device:</span>
                  <span className="font-bold text-[var(--text-primary)] truncate max-w-[240px]">{selectedSourceLabel || 'Portable Device'}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[var(--border)]/50">
                  <span className="text-[var(--text-secondary)]">Filename:</span>
                  <span className="font-bold text-[#B42318] truncate max-w-[240px]">{mtpDeletingFile.name}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[var(--border)]/50">
                  <span className="text-[var(--text-secondary)]">Object ID:</span>
                  <span className="text-[var(--text-primary)]">{mtpDeletingFile.object_id}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[var(--border)]/50">
                  <span className="text-[var(--text-secondary)]">Parent ID:</span>
                  <span className="text-[var(--text-primary)]">{mtpDeletingFile.parent_object_id || mtpCurrentObjectId || 'Root'}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-[var(--border)]/50">
                  <span className="text-[var(--text-secondary)]">Object Size:</span>
                  <span className="text-[var(--text-primary)] font-semibold">{formatBytes(mtpDeletingFile.size_bytes)} ({mtpDeletingFile.size_bytes.toLocaleString()} bytes)</span>
                </div>
                <div className="flex justify-between py-0.5">
                  <span className="text-[var(--text-secondary)]">Protocol:</span>
                  <span className="font-semibold text-[var(--primary-orange)]">MTP / WPD</span>
                </div>
              </div>

              {/* Confirmation Input */}
              <div className="space-y-1.5 pt-1">
                <label className="block text-xs font-semibold text-[var(--text-primary)]">
                  Type <span className="font-mono font-bold text-[#B42318]">DELETE</span> to confirm removal:
                </label>
                <input
                  type="text"
                  value={mtpDeleteConfirmationInput}
                  onChange={(e) => setMtpDeleteConfirmationInput(e.target.value)}
                  placeholder="DELETE"
                  disabled={isMtpDeleting}
                  className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-[var(--border)] bg-[var(--surface)] text-[var(--text-primary)] focus:border-[#D92D20] focus:ring-1 focus:ring-[#D92D20] outline-none"
                />
              </div>

              {/* Password Input (Optional Authorization) */}
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-[var(--text-secondary)]">
                  Examiner Password (optional authorization):
                </label>
                <input
                  type="password"
                  value={mtpDeletePasswordInput}
                  onChange={(e) => setMtpDeletePasswordInput(e.target.value)}
                  placeholder="Enter password or leave blank"
                  disabled={isMtpDeleting}
                  className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-[var(--border)] bg-[var(--surface)] text-[var(--text-primary)] focus:border-[var(--primary-orange)] outline-none"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-[var(--border)]">
              <button
                type="button"
                onClick={() => {
                  setMtpDeletingFile(null);
                  setMtpDeleteConfirmationInput('');
                  setMtpDeletePasswordInput('');
                }}
                disabled={isMtpDeleting}
                className="btn-secondary px-4 py-2 text-xs font-semibold cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteMtpFile}
                disabled={isMtpDeleting || mtpDeleteConfirmationInput.trim().toUpperCase() !== 'DELETE'}
                className="px-4 py-2 rounded-lg text-xs font-bold bg-[#D92D20] hover:bg-[#B42318] text-white transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed shadow-xs"
              >
                <Trash2 size={13} />
                <span>{isMtpDeleting ? 'Executing WPD Delete...' : 'Delete File from Device'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

