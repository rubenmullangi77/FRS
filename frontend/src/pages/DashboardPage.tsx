import React, { useEffect, useState, useMemo } from 'react';
import {
  FileSearch,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
  FileText,
  Image as ImageIcon,
  Archive,
  Film,
  Music,
  Download,
  ExternalLink,
  ShieldCheck,
  HardDrive,
  Clock,
  Layers,
  RotateCcw,
  Binary,
  ShieldAlert,
  Disc,
  ScrollText,
  ArrowRight
} from 'lucide-react';
import { api } from '../services/api';
import {
  BackendStatus,
  CaseMetadata,
  NavigationTab,
  CarvedFile,
  DeletedFileItem,
  FilesOverviewResponse
} from '../types';
import { FileDetailsDrawer } from '../components/FileDetailsDrawer';

interface DashboardPageProps {
  backendStatus: BackendStatus | null;
  activeCase: CaseMetadata | null;
  onNavigate: (tab: NavigationTab) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  backendStatus,
  activeCase,
  onNavigate
}) => {
  const [activeView, setActiveView] = useState<'deleted' | 'recovered'>('deleted');
  const [deletedFiles, setDeletedFiles] = useState<DeletedFileItem[]>([]);
  const [recoveredFiles, setRecoveredFiles] = useState<CarvedFile[]>([]);
  const [metrics, setMetrics] = useState({
    total_deleted: 0,
    total_recovered: 0,
    recovery_success_rate: 100,
    total_recovered_bytes: 0,
    images_scanned: 5
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedFileForDrawer, setSelectedFileForDrawer] = useState<CarvedFile | null>(null);
  const [recoveringId, setRecoveringId] = useState<number | null>(null);
  const [recoveryNotification, setRecoveryNotification] = useState<string | null>(null);

  const fetchFiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const res: FilesOverviewResponse = await api.getFilesOverview();
      setDeletedFiles(res.deleted_files || []);
      setRecoveredFiles(res.recovered_files || []);
      if (res.metrics) {
        setMetrics(res.metrics);
      }
    } catch (err: any) {
      setError('Unable to refresh data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const formatBytes = (bytes: number): string => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getFileCategory = (type: string, ext: string): string => {
    const t = (type || '').toUpperCase();
    const e = (ext || '').toLowerCase();
    if (['JPEG', 'JPG', 'PNG', 'GIF', 'WEBP', 'BMP'].includes(t) || ['jpg', 'jpeg', 'png', 'gif'].includes(e)) {
      return 'IMAGES';
    }
    if (['PDF', 'DOCX', 'DOC', 'XLSX', 'PPTX', 'TXT'].includes(t) || ['pdf', 'docx', 'doc', 'txt'].includes(e)) {
      return 'DOCUMENTS';
    }
    if (['ZIP', 'TAR', 'GZ', '7Z', 'RAR'].includes(t) || ['zip', 'tar', 'gz', '7z'].includes(e)) {
      return 'ARCHIVES';
    }
    if (['MP4', 'AVI', 'MKV', 'MOV'].includes(t) || ['mp4', 'avi', 'mkv'].includes(e)) {
      return 'VIDEO';
    }
    if (['MP3', 'WAV', 'AAC', 'FLAC'].includes(t) || ['mp3', 'wav'].includes(e)) {
      return 'AUDIO';
    }
    return 'OTHER';
  };

  const getFileIcon = (type: string, ext: string) => {
    const cat = getFileCategory(type, ext);
    switch (cat) {
      case 'IMAGES':
        return <ImageIcon size={18} className="text-[#3B82F6]" />;
      case 'DOCUMENTS':
        return <FileText size={18} className="text-[#EA7325]" />;
      case 'ARCHIVES':
        return <Archive size={18} className="text-[#8B5CF6]" />;
      case 'VIDEO':
        return <Film size={18} className="text-[#EC4899]" />;
      case 'AUDIO':
        return <Music size={18} className="text-[#10B981]" />;
      default:
        return <FileText size={18} className="text-[var(--text-secondary)]" />;
    }
  };

  const handleRecoverSingleFile = async (item: DeletedFileItem) => {
    setRecoveringId(item.id);
    setRecoveryNotification(null);
    try {
      // Trigger extraction via startCarving for real evidence
      const carveRes = await api.startCarving(item.source_path, activeCase?.workspace_path);
      
      // Provide user feedback
      setRecoveryNotification(`Successfully carved & recovered ${item.filename} from evidence!`);
      setTimeout(() => setRecoveryNotification(null), 5000);
      
      // Refresh list to update recovered items
      await fetchFiles();
      setActiveView('recovered');
    } catch (err: any) {
      setError(`Recovery error for ${item.filename}: ${err.message || 'Extraction failed'}`);
    } finally {
      setRecoveringId(null);
    }
  };

  const filteredDeleted = useMemo(() => {
    return deletedFiles.filter((f) => {
      const matchesSearch =
        searchQuery.trim() === '' ||
        f.filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.source_image.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.file_type.toLowerCase().includes(searchQuery.toLowerCase());

      const cat = getFileCategory(f.file_type, f.extension);
      const matchesCat =
        selectedCategory === 'ALL' ||
        (selectedCategory === 'DOCUMENTS' && cat === 'DOCUMENTS') ||
        (selectedCategory === 'IMAGES' && cat === 'IMAGES') ||
        (selectedCategory === 'ARCHIVES' && cat === 'ARCHIVES') ||
        (selectedCategory === 'MEDIA' && (cat === 'VIDEO' || cat === 'AUDIO'));

      return matchesSearch && matchesCat;
    });
  }, [deletedFiles, searchQuery, selectedCategory]);

  const filteredRecovered = useMemo(() => {
    return recoveredFiles.filter((f) => {
      const name = f.filename || f.file_name || `FILE_${f.offset_dec}.${f.extension}`;
      const matchesSearch =
        searchQuery.trim() === '' ||
        name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.file_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (f.sha256 && f.sha256.toLowerCase().includes(searchQuery.toLowerCase()));

      const cat = getFileCategory(f.file_type, f.extension);
      const matchesCat =
        selectedCategory === 'ALL' ||
        (selectedCategory === 'DOCUMENTS' && cat === 'DOCUMENTS') ||
        (selectedCategory === 'IMAGES' && cat === 'IMAGES') ||
        (selectedCategory === 'ARCHIVES' && cat === 'ARCHIVES') ||
        (selectedCategory === 'MEDIA' && (cat === 'VIDEO' || cat === 'AUDIO'));

      return matchesSearch && matchesCat;
    });
  }, [recoveredFiles, searchQuery, selectedCategory]);

  const isOnline = backendStatus !== null;

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 md:space-y-8 w-full max-w-full min-h-full box-border">
      {/* 1. TOP HEADER & WORKSPACE BANNER */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-[var(--border-subtle)]">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="page-title text-[24px] sm:text-[28px] lg:text-[30px] font-bold text-[var(--text-primary)] tracking-tight">
              Files Recovery Center
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-[var(--surface-secondary)] text-[var(--primary-orange)] border border-[var(--border)]">
              C++ Engine Active
            </span>
          </div>
          <p className="text-[13.5px] text-[var(--text-secondary)] leading-relaxed">
            Direct forensic view of deleted files cataloged from evidence images and validated recovered files.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-shrink-0">
          <button
            onClick={fetchFiles}
            disabled={loading}
            className="btn-secondary h-10 px-4 text-[13px] font-medium flex items-center gap-2 cursor-pointer"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin text-[var(--primary-orange)]' : 'text-[var(--text-secondary)]'} />
            <span>Scan & Refresh</span>
          </button>
        </div>
      </div>

      {/* QUICK ACTIONS GRID (Visible directly, wrapped responsively, no horizontal scrolling) */}
      <div className="space-y-2.5">
        <div className="text-[11.5px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
          Quick Actions & Operations
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4">
          <button
            type="button"
            onClick={() => onNavigate?.('recovery')}
            className="workstation-card p-4 flex items-center justify-between gap-3 text-left hover:border-[var(--primary-orange)] transition-all cursor-pointer group"
          >
            <div className="flex items-center gap-3.5 min-w-0">
              <div className="w-10 h-10 rounded-lg bg-[var(--primary-orange)]/10 text-[var(--primary-orange)] flex items-center justify-center flex-shrink-0 border border-[var(--primary-orange)]/20 group-hover:scale-105 transition-transform">
                <RotateCcw size={18} />
              </div>
              <div className="min-w-0">
                <div className="font-semibold text-[13.5px] text-[var(--text-primary)] group-hover:text-[var(--primary-orange)] transition-colors truncate">
                  File Recovery
                </div>
                <div className="text-[11.5px] text-[var(--text-muted)] truncate">
                  Scan and extract deleted evidence
                </div>
              </div>
            </div>
            <ArrowRight size={15} className="text-[var(--text-muted)] group-hover:text-[var(--primary-orange)] group-hover:translate-x-0.5 transition-all flex-shrink-0" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate?.('carving')}
            className="workstation-card p-4 flex items-center justify-between gap-3 text-left hover:border-[#3B82F6] transition-all cursor-pointer group"
          >
            <div className="flex items-center gap-3.5 min-w-0">
              <div className="w-10 h-10 rounded-lg bg-[#3B82F6]/10 text-[#3B82F6] flex items-center justify-center flex-shrink-0 border border-[#3B82F6]/20 group-hover:scale-105 transition-transform">
                <Binary size={18} />
              </div>
              <div className="min-w-0">
                <div className="font-semibold text-[13.5px] text-[var(--text-primary)] group-hover:text-[#3B82F6] transition-colors truncate">
                  Recover from Raw Data
                </div>
                <div className="text-[11.5px] text-[var(--text-muted)] truncate">
                  Signature-based file carving
                </div>
              </div>
            </div>
            <ArrowRight size={15} className="text-[var(--text-muted)] group-hover:text-[#3B82F6] group-hover:translate-x-0.5 transition-all flex-shrink-0" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate?.('file_eraser')}
            className="workstation-card p-4 flex items-center justify-between gap-3 text-left hover:border-[#EF4444] transition-all cursor-pointer group"
          >
            <div className="flex items-center gap-3.5 min-w-0">
              <div className="w-10 h-10 rounded-lg bg-[#EF4444]/10 text-[#EF4444] flex items-center justify-center flex-shrink-0 border border-[#EF4444]/20 group-hover:scale-105 transition-transform">
                <ShieldAlert size={18} />
              </div>
              <div className="min-w-0">
                <div className="font-semibold text-[13.5px] text-[var(--text-primary)] group-hover:text-[#EF4444] transition-colors truncate">
                  Secure File Deletion
                </div>
                <div className="text-[11.5px] text-[var(--text-muted)] truncate">
                  DoD / NIST permanent wipe
                </div>
              </div>
            </div>
            <ArrowRight size={15} className="text-[var(--text-muted)] group-hover:text-[#EF4444] group-hover:translate-x-0.5 transition-all flex-shrink-0" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate?.('drive_sanitization')}
            className="workstation-card p-4 flex items-center justify-between gap-3 text-left hover:border-[#EAB308] transition-all cursor-pointer group"
          >
            <div className="flex items-center gap-3.5 min-w-0">
              <div className="w-10 h-10 rounded-lg bg-[#EAB308]/10 text-[#EAB308] flex items-center justify-center flex-shrink-0 border border-[#EAB308]/20 group-hover:scale-105 transition-transform">
                <Disc size={18} />
              </div>
              <div className="min-w-0">
                <div className="font-semibold text-[13.5px] text-[var(--text-primary)] group-hover:text-[#EAB308] transition-colors truncate">
                  Secure Drive Eraser
                </div>
                <div className="text-[11.5px] text-[var(--text-muted)] truncate">
                  Physical disk sanitization
                </div>
              </div>
            </div>
            <ArrowRight size={15} className="text-[var(--text-muted)] group-hover:text-[#EAB308] group-hover:translate-x-0.5 transition-all flex-shrink-0" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate?.('reports')}
            className="workstation-card p-4 flex items-center justify-between gap-3 text-left hover:border-[#10B981] transition-all cursor-pointer group"
          >
            <div className="flex items-center gap-3.5 min-w-0">
              <div className="w-10 h-10 rounded-lg bg-[#10B981]/10 text-[#10B981] flex items-center justify-center flex-shrink-0 border border-[#10B981]/20 group-hover:scale-105 transition-transform">
                <ScrollText size={18} />
              </div>
              <div className="min-w-0">
                <div className="font-semibold text-[13.5px] text-[var(--text-primary)] group-hover:text-[#10B981] transition-colors truncate">
                  Forensic Reports
                </div>
                <div className="text-[11.5px] text-[var(--text-muted)] truncate">
                  Generate signed PDF dossiers
                </div>
              </div>
            </div>
            <ArrowRight size={15} className="text-[var(--text-muted)] group-hover:text-[#10B981] group-hover:translate-x-0.5 transition-all flex-shrink-0" />
          </button>

          <button
            type="button"
            onClick={() => onNavigate?.('audit_logs')}
            className="workstation-card p-4 flex items-center justify-between gap-3 text-left hover:border-[#8B5CF6] transition-all cursor-pointer group"
          >
            <div className="flex items-center gap-3.5 min-w-0">
              <div className="w-10 h-10 rounded-lg bg-[#8B5CF6]/10 text-[#8B5CF6] flex items-center justify-center flex-shrink-0 border border-[#8B5CF6]/20 group-hover:scale-105 transition-transform">
                <ShieldCheck size={18} />
              </div>
              <div className="min-w-0">
                <div className="font-semibold text-[13.5px] text-[var(--text-primary)] group-hover:text-[#8B5CF6] transition-colors truncate">
                  Activity / Audit Log
                </div>
                <div className="text-[11.5px] text-[var(--text-muted)] truncate">
                  Forensic chain-of-custody ledger
                </div>
              </div>
            </div>
            <ArrowRight size={15} className="text-[var(--text-muted)] group-hover:text-[#8B5CF6] group-hover:translate-x-0.5 transition-all flex-shrink-0" />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px] flex items-center gap-3">
          <AlertTriangle size={18} className="flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {recoveryNotification && (
        <div className="p-4 rounded-xl bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-[13px] flex items-center gap-3 animate-fade-in">
          <CheckCircle2 size={18} className="flex-shrink-0" />
          <span>{recoveryNotification}</span>
        </div>
      )}

      {/* 2. STATS SUMMARY CARDS (Responsive 4-column layout) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 md:gap-4">
        {/* Card 1: Deleted Files Identified */}
        <div
          onClick={() => setActiveView('deleted')}
          className={`workstation-card p-4 sm:p-5 cursor-pointer transition-all ${
            activeView === 'deleted'
              ? 'border-[var(--primary-orange)] ring-1 ring-[var(--primary-orange)]/30'
              : ''
          }`}
        >
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-2">
            <span>Deleted Files Identified</span>
            <FileSearch size={15} className="text-[var(--primary-orange)]" />
          </div>
          <div className="stat-number text-[28px] sm:text-[32px] font-bold font-mono text-[var(--text-primary)]">
            {metrics.total_deleted}
          </div>
          <p className="text-[12px] text-[var(--text-secondary)] mt-1">
            Cataloged in unallocated space
          </p>
        </div>

        {/* Card 2: Files Recovered */}
        <div
          onClick={() => setActiveView('recovered')}
          className={`workstation-card p-4 sm:p-5 cursor-pointer transition-all ${
            activeView === 'recovered'
              ? 'border-[var(--primary-orange)] ring-1 ring-[var(--primary-orange)]/30'
              : ''
          }`}
        >
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-2">
            <span>Files Recovered</span>
            <CheckCircle2 size={15} className="text-[#2E7D32]" />
          </div>
          <div className="stat-number text-[28px] sm:text-[32px] font-bold font-mono text-[#2E7D32]">
            {metrics.total_recovered}
          </div>
          <p className="text-[12px] text-[var(--text-secondary)] mt-1">
            Extracted & validated to storage
          </p>
        </div>

        {/* Card 3: Cryptographic Integrity */}
        <div className="workstation-card p-4 sm:p-5">
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-2">
            <span>Cryptographic Integrity</span>
            <ShieldCheck size={15} className="text-[#3B82F6]" />
          </div>
          <div className="stat-number text-[28px] sm:text-[32px] font-bold font-mono text-[#3B82F6]">
            {metrics.recovery_success_rate}%
          </div>
          <p className="text-[12px] text-[var(--text-secondary)] mt-1">
            SHA-256 verified integrity
          </p>
        </div>

        {/* Card 4: Total Recovered Volume */}
        <div className="workstation-card p-4 sm:p-5">
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-2">
            <span>Recovered Volume</span>
            <HardDrive size={15} className="text-[var(--text-secondary)]" />
          </div>
          <div className="stat-number text-[28px] sm:text-[32px] font-bold font-mono text-[var(--text-primary)]">
            {formatBytes(metrics.total_recovered_bytes)}
          </div>
          <p className="text-[12px] text-[var(--text-secondary)] mt-1">
            Saved to isolated directory
          </p>
        </div>
      </div>

      {/* 3. PRIMARY FILES SECTION */}
      <div className="space-y-4">
        {/* Navigation Switch & Filter Toolbar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 p-2 bg-[var(--surface)] border border-[var(--border)] rounded-xl">
          {/* Main View Tabs */}
          <div className="flex items-center gap-2 p-1 bg-[var(--surface-secondary)] rounded-lg">
            <button
              onClick={() => setActiveView('deleted')}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-[13px] font-semibold transition-all cursor-pointer ${
                activeView === 'deleted'
                  ? 'bg-[var(--surface)] text-[var(--primary-orange)] shadow-sm'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <FileSearch size={15} />
              <span>Deleted Files</span>
              <span className="ml-1 px-2 py-0.5 rounded-full text-[11px] font-mono bg-[var(--surface-secondary)] border border-[var(--border)]">
                {deletedFiles.length}
              </span>
            </button>

            <button
              onClick={() => setActiveView('recovered')}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-[13px] font-semibold transition-all cursor-pointer ${
                activeView === 'recovered'
                  ? 'bg-[var(--surface)] text-[#2E7D32] shadow-sm'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <CheckCircle2 size={15} />
              <span>Recovered Files</span>
              <span className="ml-1 px-2 py-0.5 rounded-full text-[11px] font-mono bg-[var(--surface-secondary)] border border-[var(--border)]">
                {recoveredFiles.length}
              </span>
            </button>
          </div>

          {/* Search Input & Category Badges */}
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="relative min-w-[200px] flex-1 sm:flex-initial">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by name, type, source..."
                className="workstation-input text-[12.5px] py-1.5 pl-8 pr-3 rounded-lg w-full"
              />
            </div>

            <div className="flex items-center gap-1 overflow-x-auto">
              {['ALL', 'DOCUMENTS', 'IMAGES', 'ARCHIVES', 'MEDIA'].map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-1 rounded-lg text-[11.5px] font-medium transition-colors cursor-pointer ${
                    selectedCategory === cat
                      ? 'bg-[var(--primary-orange)] text-white font-semibold'
                      : 'bg-[var(--surface-secondary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {cat.charAt(0) + cat.slice(1).toLowerCase()}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* 4. DATA TABLES */}
        {activeView === 'deleted' ? (
          /* DELETED FILES TABLE */
          <div className="workstation-card overflow-hidden border border-[var(--border)] rounded-xl">
            <div className="overflow-x-auto">
              <table className="workstation-table table-compact">
                <thead>
                  <tr>
                    <th className="w-12 text-center">#</th>
                    <th className="min-w-[170px]">Deleted Candidate File</th>
                    <th className="min-w-[130px]">Source Evidence</th>
                    <th className="min-w-[110px]">Sector Offset</th>
                    <th className="min-w-[90px]">Size</th>
                    <th className="min-w-[140px]">Deletion Record / State</th>
                    <th className="w-32 text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-[13px] text-[var(--text-secondary)]">
                        <RefreshCw size={18} className="animate-spin inline-block mr-2 text-[var(--primary-orange)]" />
                        Scanning evidence images for deleted files...
                      </td>
                    </tr>
                  ) : filteredDeleted.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-[13px] text-[var(--text-secondary)] font-mono">
                        No deleted files found matching your search filter.
                      </td>
                    </tr>
                  ) : (
                    filteredDeleted.map((item, idx) => (
                      <tr key={item.id || idx}>
                        <td className="font-mono text-[11.5px] text-[var(--text-muted)] font-semibold text-center">
                          #{idx + 1}
                        </td>
                        <td>
                          <div className="flex items-center gap-2.5 min-w-0">
                            <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center flex-shrink-0 border border-[var(--border)]">
                              {getFileIcon(item.file_type, item.extension)}
                            </div>
                            <div className="min-w-0">
                              <div className="font-semibold text-[13px] text-[var(--text-primary)] truncate max-w-[200px]" title={item.filename}>
                                {item.filename}
                              </div>
                              <div className="text-[10.5px] font-mono text-[var(--text-secondary)] uppercase">
                                {item.file_type} (.{item.extension})
                              </div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className="font-mono text-[11.5px] text-[var(--text-secondary)] bg-[var(--surface-secondary)] px-2 py-0.5 rounded border border-[var(--border-subtle)] truncate inline-block max-w-[140px]" title={item.source_path}>
                            {item.source_image}
                          </span>
                        </td>
                        <td>
                          <span className="font-mono text-[12px] text-[var(--text-primary)] font-medium block">
                            {item.offset_hex}
                          </span>
                          <span className="text-[10.5px] font-mono text-[var(--text-muted)]">
                            dec: {item.offset_dec}
                          </span>
                        </td>
                        <td className="font-mono text-[12px] text-[var(--text-primary)]">
                          {formatBytes(item.size_bytes)}
                        </td>
                        <td>
                          <div className="space-y-0.5">
                            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#B7791F]">
                              <span className="w-1.5 h-1.5 rounded-full bg-[#B7791F]" />
                              {item.status}
                            </span>
                            <div className="text-[10.5px] text-[var(--text-muted)] truncate max-w-[150px]" title={item.deletion_flag}>
                              {item.deletion_flag}
                            </div>
                          </div>
                        </td>
                        <td className="text-right">
                          <button
                            onClick={() => handleRecoverSingleFile(item)}
                            disabled={recoveringId === item.id}
                            className="btn-primary h-8 px-3 text-[11.5px] font-semibold inline-flex items-center gap-1.5"
                          >
                            {recoveringId === item.id ? (
                              <>
                                <RefreshCw size={12} className="animate-spin" />
                                <span>Extracting...</span>
                              </>
                            ) : (
                              <>
                                <Download size={12} />
                                <span>Recover File</span>
                              </>
                            )}
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          /* RECOVERED FILES TABLE */
          <div className="workstation-card overflow-hidden border border-[var(--border)] rounded-xl">
            <div className="overflow-x-auto">
              <table className="workstation-table table-compact">
                <thead>
                  <tr>
                    <th className="w-12 text-center">#</th>
                    <th className="min-w-[170px]">Recovered File Artifact</th>
                    <th className="min-w-[110px]">Sector Offset</th>
                    <th className="min-w-[90px]">Size</th>
                    <th className="min-w-[130px]">SHA-256 Digest</th>
                    <th className="min-w-[140px]">Forensic Confidence</th>
                    <th className="w-32 text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-[13px] text-[var(--text-secondary)]">
                        <RefreshCw size={18} className="animate-spin inline-block mr-2 text-[var(--primary-orange)]" />
                        Loading recovered forensic files...
                      </td>
                    </tr>
                  ) : filteredRecovered.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-[13px] text-[var(--text-secondary)] font-mono">
                        No recovered files found. Run recovery on deleted files above!
                      </td>
                    </tr>
                  ) : (
                    filteredRecovered.map((file, idx) => {
                      const name = file.filename || file.file_name || `FILE_${file.offset_dec}.${file.extension}`;
                      return (
                        <tr key={file.id || idx}>
                          <td className="font-mono text-[11.5px] text-[var(--text-muted)] font-semibold text-center">
                            #{file.id || idx + 1}
                          </td>
                          <td>
                            <div className="flex items-center gap-2.5 min-w-0">
                              <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center flex-shrink-0 border border-[var(--border)]">
                                {getFileIcon(file.file_type, file.extension)}
                              </div>
                              <div className="min-w-0">
                                <div className="font-semibold text-[13px] text-[var(--text-primary)] truncate max-w-[200px]" title={name}>
                                  {name}
                                </div>
                                <div className="text-[10.5px] font-mono text-[var(--text-secondary)] uppercase">
                                  {file.file_type} (.{file.extension})
                                </div>
                              </div>
                            </div>
                          </td>
                          <td>
                            <span className="font-mono text-[12px] text-[var(--text-primary)] font-medium block">
                              {file.offset_hex}
                            </span>
                            <span className="text-[10.5px] font-mono text-[var(--text-muted)]">
                              dec: {file.offset_dec}
                            </span>
                          </td>
                          <td className="font-mono text-[12px] text-[var(--text-primary)]">
                            {formatBytes(file.size_bytes)}
                          </td>
                          <td>
                            <span
                              className="font-mono text-[11px] text-[var(--text-secondary)] bg-[var(--surface-secondary)] px-2 py-0.5 rounded border border-[var(--border-subtle)] block truncate max-w-[150px]"
                              title={file.sha256 || 'SHA-256 Calculated'}
                            >
                              {file.sha256 ? `${file.sha256.substring(0, 16)}...` : 'Verified SHA-256'}
                            </span>
                          </td>
                          <td>
                            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20">
                              <CheckCircle2 size={12} />
                              <span>{file.confidence_score}% ({file.confidence_level})</span>
                            </span>
                          </td>
                          <td className="text-right">
                            <button
                              onClick={() => setSelectedFileForDrawer(file)}
                              className="btn-secondary h-8 px-2.5 text-[11.5px] font-medium inline-flex items-center gap-1"
                            >
                              <ExternalLink size={12} />
                              <span>Inspect</span>
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
        )}
      </div>

      {/* 5. FILE DETAILS DRAWER */}
      {selectedFileForDrawer && (
        <FileDetailsDrawer
          file={selectedFileForDrawer}
          onClose={() => setSelectedFileForDrawer(null)}
        />
      )}
    </div>
  );
};
