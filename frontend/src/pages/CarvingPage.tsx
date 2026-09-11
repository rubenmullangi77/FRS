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
  FileText
} from 'lucide-react';
import { api } from '../services/api';
import { DiskImage, CarvedFile, CarveJob, CaseMetadata } from '../types';
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

  // Recovery Options (Simplified Filters)
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [minConfidence, setMinConfidence] = useState<number>(0);
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Fragment Recovery State
  const [isReconstructing, setIsReconstructing] = useState<boolean>(false);
  const [fragmentResult, setFragmentResult] = useState<string | null>(null);

  useEffect(() => {
    api.getDrives().then((res) => {
      setDiskImages(res.disk_images || []);
      if (res.disk_images && res.disk_images.length > 0) {
        setSelectedImage(res.disk_images[0].path);
      }
    }).catch(() => {});
  }, []);

  const handleStartCarving = async () => {
    if (!selectedImage) {
      setError('Please select an evidence file first.');
      return;
    }
    setIsCarving(true);
    setError(null);
    setProgress(5);
    setStage('Scanning evidence for file signatures...');
    setCarvedFiles([]);

    try {
      const startRes = await api.startCarving(selectedImage, activeCase?.workspace_path);
      const jobId = startRes.job_id;

      let completed = false;
      while (!completed) {
        await new Promise((resolve) => setTimeout(resolve, 800));
        const job: CarveJob = await api.getJob(jobId);
        setProgress(job.progress);
        setStage(job.stage);
        if (job.discovered_files) {
          setCarvedFiles(job.discovered_files);
        }

        if (job.status === 'COMPLETED') {
          completed = true;
          setProgress(100);
          setStage(`Scan completed: ${job.files_carved} recovered files found.`);
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
      const res = await api.reconstructFragments(selectedImage);
      setFragmentResult(res.output);
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
    <div className="p-8 lg:p-10 space-y-8 max-w-[1400px] mx-auto bg-[#F7F2E8] min-h-full">
      {/* Page Title & Subtitle */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="page-title text-[30px] font-bold text-[#2B241F] tracking-tight">
            File Recovery from Raw Data
          </h1>
          <span className="text-[12px] font-mono px-2 py-0.5 rounded bg-[#F4D5BF] text-[#B9541D] font-semibold border border-[#D96B27]/25">
            Signature Carving
          </span>
        </div>
        <p className="text-[14px] text-[#756B63] mt-1.5 leading-relaxed">
          Search an evidence image for deleted or identifiable files without modifying the original evidence.
        </p>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px] flex items-center gap-3">
          <AlertTriangle size={18} className="flex-shrink-0" aria-hidden="true" focusable="false" />
          <span>{error}</span>
        </div>
      )}

      {/* SECTION 1: Choose Evidence File */}
      <div className="workstation-card p-6 lg:p-7 bg-[#FFFDF8] border border-[#E5D8C8] space-y-5">
        <div>
          <h2 className="section-title text-[18px] font-semibold text-[#2B241F]">
            Choose Evidence File
          </h2>
          <p className="text-[13px] text-[#756B63] mt-0.5">
            Select an evidence container to inspect. All analysis operates strictly in read-only mode.
          </p>
        </div>

        {/* Evidence File Cards List */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 max-h-72 overflow-y-auto pr-1">
          {diskImages.map((img, idx) => {
            const isSelected = selectedImage === img.path;
            const friendlyName = getFriendlyEvidenceName(img.name);
            return (
              <div
                key={idx}
                onClick={() => !isCarving && setSelectedImage(img.path)}
                className={`p-3.5 rounded-lg border transition-all cursor-pointer flex flex-col justify-between space-y-2 ${
                  isSelected
                    ? 'bg-[#F4D5BF]/40 border-[#D96B27] ring-1 ring-[#D96B27]'
                    : 'bg-[#FBF8F1] border-[#E5D8C8] hover:border-[#D96B27]/40'
                } ${isCarving ? 'opacity-60 cursor-not-allowed' : ''}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="text-[13.5px] font-bold text-[#2B241F] tracking-tight">
                      {friendlyName}
                    </div>
                    <div className="text-[11px] font-mono text-[#756B63] truncate mt-0.5">
                      {img.name}
                    </div>
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20 shrink-0 font-medium">
                    Read-Only
                  </span>
                </div>

                <div className="flex items-center justify-between text-[11.5px] font-mono text-[#756B63] pt-1 border-t border-[#E5D8C8]/60">
                  <span>{img.format || 'RAW IMAGE'}</span>
                  <span className="font-semibold text-[#2B241F]">
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

        {/* Primary Action Buttons */}
        <div className="flex flex-wrap items-center gap-3 pt-2">
          <button
            onClick={handleStartCarving}
            disabled={isCarving || !selectedImage}
            className="btn-primary h-[42px] px-6 text-[13.5px] font-semibold"
          >
            <Play size={15} className={isCarving ? 'animate-spin' : ''} aria-hidden="true" focusable="false" />
            <span>{isCarving ? 'Scanning Evidence...' : 'Start File Recovery'}</span>
            <span className="text-[11px] opacity-80 font-mono font-normal">| Signature Carving</span>
          </button>

          <button
            onClick={handleReconstructFragments}
            disabled={isReconstructing || isCarving || !selectedImage}
            className="btn-secondary h-[42px] px-4 text-[13px]"
          >
            <Layers size={14} className={isReconstructing ? 'animate-spin text-[#D96B27]' : 'text-[#756B63]'} aria-hidden="true" focusable="false" />
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
        <div className="workstation-card p-6 bg-[#FFFDF8] border border-[#E5D8C8] space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between text-[#D96B27] font-bold pb-2 border-b border-[#E5D8C8]">
            <span className="flex items-center gap-2">
              <Layers size={16} />
              FRAGMENT RECOVERY REPORT
            </span>
            <button
              onClick={() => setFragmentResult(null)}
              className="text-[#756B63] hover:text-[#2B241F] text-xs cursor-pointer"
            >
              Dismiss
            </button>
          </div>
          <pre className="p-4 rounded-lg bg-[#FBF8F1] border border-[#E5D8C8] text-[#2B241F] whitespace-pre-wrap leading-relaxed max-h-52 overflow-x-auto">
            {fragmentResult}
          </pre>
        </div>
      )}

      {/* SECTION 2 & 3: Recovery Options & Recovered Files */}
      <div className="workstation-card bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] overflow-hidden space-y-0">
        <div className="p-6 border-b border-[#E5D8C8] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="section-title text-[18px] font-semibold text-[#2B241F]">
              Recovered Files
            </h2>
            <p className="text-[13px] text-[#756B63] mt-0.5">
              {filteredFiles.length} {filteredFiles.length === 1 ? 'file' : 'files'} found
              {carvedFiles.length > 0 && filteredFiles.length !== carvedFiles.length && ` (filtered from ${carvedFiles.length})`}
            </p>
          </div>

          {/* Recovery Options Filters */}
          <div className="flex flex-wrap items-center gap-2.5 text-[12.5px]">
            {/* Search Input */}
            <div className="flex items-center gap-2 bg-[#FBF8F1] border border-[#E5D8C8] rounded-md px-3 py-1.5">
              <Search size={13} className="text-[#756B63]" aria-hidden="true" focusable="false" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search file, offset..."
                className="bg-transparent text-[#2B241F] text-[12.5px] focus:outline-none w-36"
              />
            </div>

            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="bg-[#FBF8F1] border border-[#E5D8C8] rounded-md px-3 py-1.5 text-[12.5px] text-[#2B241F] focus:outline-none"
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
              className="bg-[#FBF8F1] border border-[#E5D8C8] rounded-md px-3 py-1.5 text-[12.5px] text-[#2B241F] focus:outline-none"
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
                <th className="w-28">Type</th>
                <th className="w-36">Location in Image</th>
                <th className="w-28">Size</th>
                <th className="w-36">Recovery Confidence</th>
                <th>Condition</th>
                <th className="w-28 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredFiles.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[13.5px] text-[#756B63]">
                    {carvedFiles.length === 0
                      ? 'No files found yet. Choose an evidence file and click "Start File Recovery" above.'
                      : 'No recovered files match current filter criteria.'}
                  </td>
                </tr>
              ) : (
                filteredFiles.map((file) => {
                  const defaultName = `recovered_${file.id}.${file.extension}`;
                  return (
                    <tr key={file.id} className="hover:bg-[#FDF9F2]">
                      <td className="font-medium text-[13px] text-[#2B241F]">
                        <div className="flex items-center gap-2">
                          <FileText size={15} className="text-[#D96B27]" />
                          <span>{defaultName}</span>
                        </div>
                      </td>
                      <td className="text-[12px] font-mono text-[#756B63]">
                        {(file.file_type || 'FILE').toUpperCase()}
                      </td>
                      <td className="font-mono text-[12px] text-[#756B63]">
                        {file.offset_hex || `0x${(file.offset_dec || 0).toString(16).toUpperCase()}`}
                      </td>
                      <td className="font-mono text-[12px] text-[#2B241F]">
                        {file.size_bytes != null ? `${(file.size_bytes / 1024).toFixed(1)} KB` : 'N/A'}
                      </td>
                      <td>
                        {getConfidenceBadge(file.confidence_score ?? 0)}
                      </td>
                      <td>
                        <span
                          className={`inline-flex items-center gap-1.5 text-[12px] font-medium ${
                            file.is_valid ? 'text-[#2E7D32]' : 'text-[#B45309]'
                          }`}
                        >
                          <span className={`w-2 h-2 rounded-full ${file.is_valid ? 'bg-[#2E7D32]' : 'bg-[#B45309]'}`} />
                          <span>{file.is_valid ? 'Valid' : 'Corrupted / Partial'}</span>
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
    </div>
  );
};
