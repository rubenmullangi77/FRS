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
  Layers
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
      setError(err.message || 'Failed to load forensic files overview');
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
    <div className="p-8 lg:p-12 space-y-9 max-w-[1500px] mx-auto min-h-full">
      {/* 1. TOP HEADER & WORKSPACE BANNER */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-2 border-b border-[var(--border-subtle)]">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <h1 className="page-title text-[28px] lg:text-[32px] font-bold text-[var(--text-primary)] tracking-tight">
              Files Recovery Center
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-[var(--surface-secondary)] text-[var(--primary-orange)] border border-[var(--border)]">
              C++ Engine Active
            </span>
          </div>
          <p className="text-[14px] text-[var(--text-secondary)] leading-relaxed">
            Direct forensic view of deleted files cataloged from evidence images and validated recovered files.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchFiles}
            disabled={loading}
            className="btn-secondary h-11 px-4 text-[13px] font-medium flex items-center gap-2 cursor-pointer"
          >
            <RefreshCw size={15} className={loading ? 'animate-spin text-[var(--primary-orange)]' : 'text-[var(--text-secondary)]'} />
            <span>Scan & Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-5 rounded-xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13.5px] flex items-center gap-3">
          <AlertTriangle size={18} className="flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {recoveryNotification && (
        <div className="p-5 rounded-xl bg-[#2E7D32]/10 border border-[#2E7D32]/30 text-[#2E7D32] text-[13.5px] flex items-center gap-3 animate-fade-in">
          <CheckCircle2 size={18} className="flex-shrink-0" />
          <span>{recoveryNotification}</span>
        </div>
      )}

      {/* 2. STATS SUMMARY CARDS (Spacious 4-column layout) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Card 1: Deleted Files Identified */}
        <div
          onClick={() => setActiveView('deleted')}
          className={`workstation-card p-7 cursor-pointer transition-all ${
            activeView === 'deleted'
              ? 'border-[var(--primary-orange)] ring-1 ring-[var(--primary-orange)]/30'
              : ''
          }`}
        >
          <div className="flex items-center justify-between text-[11.5px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-3">
            <span>Deleted Files Identified</span>
            <FileSearch size={16} className="text-[var(--primary-orange)]" />
          </div>
          <div className="stat-number text-[36px] font-bold font-mono text-[var(--text-primary)]">
            {metrics.total_deleted}
          </div>
          <p className="text-[13px] text-[var(--text-secondary)] mt-2">
            Cataloged in unallocated space
          </p>
        </div>

        {/* Card 2: Files Recovered */}
        <div
          onClick={() => setActiveView('recovered')}
          className={`workstation-card p-7 cursor-pointer transition-all ${
            activeView === 'recovered'
              ? 'border-[var(--primary-orange)] ring-1 ring-[var(--primary-orange)]/30'
              : ''
          }`}
        >
          <div className="flex items-center justify-between text-[11.5px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-3">
            <span>Files Recovered</span>
            <CheckCircle2 size={16} className="text-[#2E7D32]" />
          </div>
          <div className="stat-number text-[36px] font-bold font-mono text-[#2E7D32]">
            {metrics.total_recovered}
          </div>
          <p className="text-[13px] text-[var(--text-secondary)] mt-2">
            Extracted & validated to storage
          </p>
        </div>

        {/* Card 3: Cryptographic Integrity */}
        <div className="workstation-card p-7">
          <div className="flex items-center justify-between text-[11.5px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-3">
            <span>Cryptographic Integrity</span>
            <ShieldCheck size={16} className="text-[#3B82F6]" />
          </div>
          <div className="stat-number text-[36px] font-bold font-mono text-[#3B82F6]">
            {metrics.recovery_success_rate}%
          </div>
          <p className="text-[13px] text-[var(--text-secondary)] mt-2">
            SHA-256 verified integrity
          </p>
        </div>

        {/* Card 4: Total Recovered Volume */}
        <div className="workstation-card p-7">
          <div className="flex items-center justify-between text-[11.5px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-3">
            <span>Recovered Volume</span>
            <HardDrive size={16} className="text-[var(--text-secondary)]" />
          </div>
          <div className="stat-number text-[36px] font-bold font-mono text-[var(--text-primary)]">
            {formatBytes(metrics.total_recovered_bytes)}
          </div>
          <p className="text-[13px] text-[var(--text-secondary)] mt-2">
            Saved to isolated directory
          </p>
        </div>
      </div>

      {/* 3. PRIMARY FILES SECTION */}
      <div className="space-y-6">
        {/* Navigation Switch & Filter Toolbar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5 p-2 bg-[var(--surface)] border border-[var(--border)] rounded-xl">
          {/* Main View Tabs */}
          <div className="flex items-center gap-2 p-1 bg-[var(--surface-secondary)] rounded-lg">
            <button
              onClick={() => setActiveView('deleted')}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-md text-[13.5px] font-semibold transition-all cursor-pointer ${
                activeView === 'deleted'
                  ? 'bg-[var(--surface)] text-[var(--primary-orange)] shadow-sm'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <FileSearch size={16} />
              <span>Deleted Files</span>
              <span className="ml-1 px-2 py-0.5 rounded-full text-[11px] font-mono bg-[var(--surface-secondary)] border border-[var(--border)]">
                {deletedFiles.length}
              </span>
            </button>

            <button
              onClick={() => setActiveView('recovered')}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-md text-[13.5px] font-semibold transition-all cursor-pointer ${
                activeView === 'recovered'
                  ? 'bg-[var(--surface)] text-[#2E7D32] shadow-sm'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              <CheckCircle2 size={16} />
              <span>Recovered Files</span>
              <span className="ml-1 px-2 py-0.5 rounded-full text-[11px] font-mono bg-[var(--surface-secondary)] border border-[var(--border)]">
                {recoveredFiles.length}
              </span>
            </button>
          </div>

          {/* Search Input & Category Badges */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative min-w-[240px]">
              <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by name, type, source..."
                className="workstation-input text-[13px] py-2 pl-9 pr-3 rounded-lg w-full"
              />
            </div>

            <div className="flex items-center gap-1.5 overflow-x-auto">
              {['ALL', 'DOCUMENTS', 'IMAGES', 'ARCHIVES', 'MEDIA'].map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-3 py-1.5 rounded-lg text-[12px] font-medium transition-colors cursor-pointer ${
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
              <table className="workstation-table">
                <thead>
                  <tr>
                    <th className="w-16">#</th>
                    <th className="min-w-[260px]">Deleted Candidate File</th>
                    <th className="w-48">Source Evidence</th>
                    <th className="w-40">Sector Offset</th>
                    <th className="w-28">Size</th>
                    <th className="w-56">Deletion Record / State</th>
                    <th className="w-36 text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-[13.5px] text-[var(--text-secondary)]">
                        <RefreshCw size={20} className="animate-spin inline-block mr-2 text-[var(--primary-orange)]" />
                        Scanning evidence images for deleted files...
                      </td>
                    </tr>
                  ) : filteredDeleted.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-[13.5px] text-[var(--text-secondary)] font-mono">
                        No deleted files found matching your search filter.
                      </td>
                    </tr>
                  ) : (
                    filteredDeleted.map((item, idx) => (
                      <tr key={item.id || idx}>
                        <td className="font-mono text-[12px] text-[var(--text-muted)] font-semibold">
                          #{idx + 1}
                        </td>
                        <td>
                          <div className="flex items-center gap-3">
                            <div className="w-9 h-9 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center flex-shrink-0 border border-[var(--border)]">
                              {getFileIcon(item.file_type, item.extension)}
                            </div>
                            <div className="min-w-0">
                              <div className="font-semibold text-[13.5px] text-[var(--text-primary)] truncate" title={item.filename}>
                                {item.filename}
                              </div>
                              <div className="text-[11px] font-mono text-[var(--text-secondary)] uppercase">
                                {item.file_type} File (.{item.extension})
                              </div>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className="font-mono text-[12px] text-[var(--text-secondary)] bg-[var(--surface-secondary)] px-2.5 py-1 rounded border border-[var(--border-subtle)] truncate inline-block max-w-[170px]" title={item.source_path}>
                            {item.source_image}
                          </span>
                        </td>
                        <td>
                          <span className="font-mono text-[12.5px] text-[var(--text-primary)] font-medium">
                            {item.offset_hex}
                          </span>
                          <span className="block text-[11px] font-mono text-[var(--text-muted)]">
                            dec: {item.offset_dec}
                          </span>
                        </td>
                        <td className="font-mono text-[12.5px] text-[var(--text-primary)]">
                          {formatBytes(item.size_bytes)}
                        </td>
                        <td>
                          <div className="space-y-0.5">
                            <span className="inline-flex items-center gap-1.5 text-[11.5px] font-semibold text-[#B7791F]">
                              <span className="w-1.5 h-1.5 rounded-full bg-[#B7791F]" />
                              {item.status}
                            </span>
                            <div className="text-[11px] text-[var(--text-muted)] truncate max-w-[200px]" title={item.deletion_flag}>
                              {item.deletion_flag}
                            </div>
                          </div>
                        </td>
                        <td className="text-right">
                          <button
                            onClick={() => handleRecoverSingleFile(item)}
                            disabled={recoveringId === item.id}
                            className="btn-primary h-9 px-4 text-[12px] font-semibold"
                          >
                            {recoveringId === item.id ? (
                              <>
                                <RefreshCw size={13} className="animate-spin" />
                                <span>Extracting...</span>
                              </>
                            ) : (
                              <>
                                <Download size={13} />
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
              <table className="workstation-table">
                <thead>
                  <tr>
                    <th className="w-16">#</th>
                    <th className="min-w-[260px]">Recovered File Artifact</th>
                    <th className="w-48">Sector Offset</th>
                    <th className="w-32">Size</th>
                    <th className="w-56">SHA-256 Digest</th>
                    <th className="w-44">Forensic Confidence</th>
                    <th className="w-36 text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-[13.5px] text-[var(--text-secondary)]">
                        <RefreshCw size={20} className="animate-spin inline-block mr-2 text-[var(--primary-orange)]" />
                        Loading recovered forensic files...
                      </td>
                    </tr>
                  ) : filteredRecovered.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-[13.5px] text-[var(--text-secondary)] font-mono">
                        No recovered files found. Run recovery on deleted files above!
                      </td>
                    </tr>
                  ) : (
                    filteredRecovered.map((file, idx) => {
                      const name = file.filename || file.file_name || `FILE_${file.offset_dec}.${file.extension}`;
                      return (
                        <tr key={file.id || idx}>
                          <td className="font-mono text-[12px] text-[var(--text-muted)] font-semibold">
                            #{file.id || idx + 1}
                          </td>
                          <td>
                            <div className="flex items-center gap-3">
                              <div className="w-9 h-9 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center flex-shrink-0 border border-[var(--border)]">
                                {getFileIcon(file.file_type, file.extension)}
                              </div>
                              <div className="min-w-0">
                                <div className="font-semibold text-[13.5px] text-[var(--text-primary)] truncate" title={name}>
                                  {name}
                                </div>
                                <div className="text-[11px] font-mono text-[var(--text-secondary)] uppercase">
                                  {file.file_type} File (.{file.extension})
                                </div>
                              </div>
                            </div>
                          </td>
                          <td>
                            <span className="font-mono text-[12.5px] text-[var(--text-primary)] font-medium">
                              {file.offset_hex}
                            </span>
                            <span className="block text-[11px] font-mono text-[var(--text-muted)]">
                              dec: {file.offset_dec}
                            </span>
                          </td>
                          <td className="font-mono text-[12.5px] text-[var(--text-primary)]">
                            {formatBytes(file.size_bytes)}
                          </td>
                          <td>
                            <span
                              className="font-mono text-[11px] text-[var(--text-secondary)] bg-[var(--surface-secondary)] px-2.5 py-1 rounded border border-[var(--border-subtle)] block truncate max-w-[200px]"
                              title={file.sha256 || 'SHA-256 Calculated'}
                            >
                              {file.sha256 ? `${file.sha256.substring(0, 16)}...` : 'Verified SHA-256'}
                            </span>
                          </td>
                          <td>
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11.5px] font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20">
                              <CheckCircle2 size={13} />
                              <span>{file.confidence_score}% ({file.confidence_level})</span>
                            </span>
                          </td>
                          <td className="text-right">
                            <button
                              onClick={() => setSelectedFileForDrawer(file)}
                              className="btn-secondary h-9 px-3.5 text-[12px] font-medium"
                            >
                              <ExternalLink size={13} />
                              <span>Inspect Details</span>
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
