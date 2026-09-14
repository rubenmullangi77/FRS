import React from 'react';
import {
  X,
  FileText,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  Info
} from 'lucide-react';
import { CarvedFile } from '../types';

interface FileDetailsDrawerProps {
  file: CarvedFile | null;
  onClose: () => void;
}

export const FileDetailsDrawer: React.FC<FileDetailsDrawerProps> = ({ file, onClose }) => {
  if (!file) return null;
  const getConfidenceBadge = (score: number, level: string) => {
    if (score >= 90) {
      return (
        <span className="px-2.5 py-1 rounded text-xs font-bold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20 flex items-center gap-1">
          <CheckCircle size={13} />
          {score}% ({level})
        </span>
      );
    }
    return (
      <span className="px-2.5 py-1 rounded text-xs font-bold bg-[#B7791F]/10 text-[#B7791F] border border-[#B7791F]/20 flex items-center gap-1">
        <AlertTriangle size={13} />
        {score}% ({level})
      </span>
    );
  };

  const formatBytes = (bytes: number): string => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full sm:w-[480px] max-w-full min-w-0 bg-[var(--surface)] border-l border-[var(--border)] shadow-2xl z-50 flex flex-col select-none animate-fade-in">
      {/* Drawer Header */}
      <div className="p-5 border-b border-[var(--border)] flex items-center justify-between bg-[var(--surface-secondary)]">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[var(--surface)] border border-[var(--primary-orange)]/30 flex items-center justify-center text-[var(--primary-orange)] font-mono font-bold text-xs">
            #{file.id}
          </div>
          <div>
            <h3 className="font-bold text-[var(--text-primary)] text-sm">
              Artifact #{file.id}: {(file.file_type || 'FILE').toUpperCase()} File
            </h3>
            <p className="text-xs font-mono text-[var(--text-secondary)]">
              Offset {file.offset_hex || `0x${(file.offset_dec || 0).toString(16).toUpperCase()}`}
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface)] transition-colors cursor-pointer"
        >
          <X size={18} />
        </button>
      </div>

      {/* Drawer Content */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6 text-sm">
        {/* Confidence Card */}
        <div className="bg-[var(--surface-secondary)] rounded-xl p-5 border border-[var(--border)] space-y-3.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold uppercase text-[var(--text-secondary)]">FORENSIC CONFIDENCE</span>
            {getConfidenceBadge(file.confidence_score, file.confidence_level)}
          </div>
          <div className="flex items-center justify-between text-xs pt-2.5 border-t border-[var(--border-subtle)]">
            <span className="text-[var(--text-secondary)]">Validation State</span>
            <span
              className={`font-bold flex items-center gap-1.5 ${
                (file.validation_state === 'VALID' || (!file.validation_state && file.is_valid)) ? 'text-[#2E7D32]' : 'text-[#B45309]'
              }`}
            >
              {(file.validation_state === 'VALID' || (!file.validation_state && file.is_valid)) ? (
                <CheckCircle size={14} />
              ) : (
                <AlertTriangle size={14} />
              )}
              {file.validation_state || file.status || (file.is_valid ? 'VALID' : 'PARTIAL')}
            </span>
          </div>
          <div className="flex items-center justify-between text-xs pt-2.5 border-t border-[var(--border-subtle)]">
            <span className="text-[var(--text-secondary)]">Recovery Method</span>
            <span className="font-mono font-medium text-[var(--text-primary)]">
              {file.recovery_method || 'Raw Signature Carving'}
            </span>
          </div>
        </div>

        {/* Explainable Scoring Factors */}
        <div>
          <h4 className="text-xs font-mono uppercase tracking-wider text-[var(--text-secondary)] mb-3 flex items-center gap-1.5 font-bold">
            <ShieldCheck size={14} className="text-[var(--primary-orange)]" />
            Explainable Validation Factors
          </h4>
          <div className="space-y-2">
            {file.reasons && file.reasons.length > 0 ? (
              file.reasons.map((reason, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2.5 p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs text-[var(--text-primary)]"
                >
                  <CheckCircle size={14} className="text-[#2E7D32] mt-0.5 flex-shrink-0" />
                  <span>{reason}</span>
                </div>
              ))
            ) : (
              <div className="text-xs text-[var(--text-secondary)] italic p-2">
                Header signature matches known {(file.file_type || 'FILE').toUpperCase()} magic bytes.
              </div>
            )}
          </div>
        </div>

        {/* Metadata Details */}
        <div className="space-y-2.5 text-xs font-mono">
          <div className="flex justify-between py-2 border-b border-[var(--border-subtle)]">
            <span className="text-[var(--text-secondary)]">File Extension:</span>
            <span className="font-bold text-[var(--text-primary)]">.{file.extension}</span>
          </div>
          <div className="flex justify-between py-2 border-b border-[var(--border-subtle)]">
            <span className="text-[var(--text-secondary)]">Offset Decimal:</span>
            <span className="text-[var(--text-primary)]">{(file.offset_dec || 0).toLocaleString()} bytes</span>
          </div>
          <div className="flex justify-between py-2 border-b border-[var(--border-subtle)]">
            <span className="text-[var(--text-secondary)]">Artifact Size:</span>
            <span className="font-bold text-[var(--text-primary)]">{formatBytes(file.size_bytes)}</span>
          </div>
          {file.sha256 && (
            <div className="flex flex-col gap-1 py-2 border-b border-[var(--border-subtle)]">
              <span className="text-[var(--text-secondary)]">SHA-256 Digest:</span>
              <span className="text-[var(--text-primary)] break-all text-[11px] bg-[var(--surface-secondary)] p-2 rounded border border-[var(--border-subtle)]">
                {file.sha256}
              </span>
            </div>
          )}
          <div className="flex flex-col gap-1 py-2 border-b border-[var(--border-subtle)]">
            <span className="text-[var(--text-secondary)]">Recovered Path:</span>
            <span className="text-[var(--text-primary)] break-all text-[11px] bg-[var(--surface-secondary)] p-2 rounded border border-[var(--border-subtle)]" title={file.recovered_path}>
              {file.recovered_path || 'N/A'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
