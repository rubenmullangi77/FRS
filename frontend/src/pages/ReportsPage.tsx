import React, { useState, useEffect } from 'react';
import {
  FileText,
  Plus,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Eye,
  FileCode,
  User,
  FolderOpen
} from 'lucide-react';
import { api } from '../services/api';
import { ForensicReportItem, CaseMetadata } from '../types';
import { settingsService } from '../services/settings';

interface ReportsPageProps {
  activeCase: CaseMetadata | null;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ activeCase }) => {
  const [reports, setReports] = useState<ForensicReportItem[]>([]);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [generationOutput, setGenerationOutput] = useState<string | null>(null);
  const [includePdf, setIncludePdf] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [examinerName, setExaminerName] = useState<string>(settingsService.getExaminerName());

  useEffect(() => {
    return settingsService.subscribe((s) => {
      setExaminerName(s.examinerName.trim() || 'Examiner not set');
    });
  }, []);

  const loadReports = async () => {
    try {
      const res = await api.listReports(activeCase?.workspace_path);
      setReports(res.reports || []);
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    loadReports();
  }, [activeCase]);

  const handleGenerateReport = async () => {
    if (!activeCase?.workspace_path) {
      setError('Please select an active Case on the Evidence Files page before generating reports.');
      return;
    }
    setIsGenerating(true);
    setError(null);
    setGenerationOutput(null);

    try {
      const res = await api.generateReport(activeCase.workspace_path, includePdf);
      setGenerationOutput(res.output);
      await loadReports();
    } catch (err: any) {
      setError(err.message || 'Report generation failed');
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="p-8 lg:p-10 space-y-8 max-w-[1400px] mx-auto bg-[#F7F2E8] min-h-full">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="page-title text-[30px] font-bold text-[#2B241F] tracking-tight">
            Forensic Reports
          </h1>
          <p className="text-[14px] text-[#756B63] mt-1 leading-relaxed">
            Generate and export court-admissible forensic documentation in JSON, HTML, and vector PDF formats.
          </p>
        </div>

        <button
          onClick={handleGenerateReport}
          disabled={isGenerating || !activeCase}
          className="btn-primary h-[42px] px-5 text-[13px] font-semibold self-start sm:self-auto"
        >
          <Plus size={15} className={isGenerating ? 'animate-spin' : ''} aria-hidden="true" focusable="false" />
          <span>{isGenerating ? 'Compiling Report...' : 'Compile Report'}</span>
        </button>
      </div>

      {/* Report Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="workstation-card p-5 bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] space-y-2 text-xs">
          <div className="font-semibold text-[#D96B27] flex items-center gap-2 text-[13px]">
            <FileCode size={16} />
            Structured JSON Report
          </div>
          <p className="text-[#756B63] leading-relaxed text-[12.5px]">
            Machine-readable forensic record with evidence hashes, carved file offsets, and recovery confidence scores.
          </p>
        </div>

        <div className="workstation-card p-5 bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] space-y-2 text-xs">
          <div className="font-semibold text-[#2E7D32] flex items-center gap-2 text-[13px]">
            <Eye size={16} />
            Interactive HTML Report
          </div>
          <p className="text-[#756B63] leading-relaxed text-[12.5px]">
            Self-contained investigator report with interactive tables, hex dumps, and evidence chain of custody.
          </p>
        </div>

        <div className="workstation-card p-5 bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] space-y-2 text-xs">
          <div className="font-semibold text-[#2B241F] flex items-center gap-2 text-[13px]">
            <FileText size={16} />
            Printable PDF Report
          </div>
          <p className="text-[#756B63] leading-relaxed text-[12.5px]">
            High-resolution document formatted with investigator details and signature blocks for court submission.
          </p>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px] flex items-center gap-3">
          <AlertTriangle size={18} className="flex-shrink-0" aria-hidden="true" focusable="false" />
          <span>{error}</span>
        </div>
      )}

      {/* Target Workspace Config Bar */}
      <div className="workstation-card p-5 bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#756B63]">
              Target Case:
            </span>
            <span className="text-[14px] font-bold text-[#2B241F] font-mono">
              {activeCase ? `${activeCase.case_id} — ${activeCase.case_name}` : 'No Case Selected'}
            </span>
          </div>
          <div className="text-[12px] text-[#756B63]">
            Prepared by: <span className="font-semibold text-[#2B241F]">{examinerName}</span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-[12.5px] text-[#2B241F] font-medium cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includePdf}
              onChange={(e) => setIncludePdf(e.target.checked)}
              className="w-4 h-4 rounded text-[#D96B27] focus:ring-0"
            />
            <span>Generate Vector PDF</span>
          </label>

          <button
            onClick={loadReports}
            className="btn-secondary h-[36px] px-3 text-[12px]"
          >
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Generation Output Terminal */}
      {generationOutput && (
        <div className="workstation-card p-5 bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] space-y-2 font-mono text-xs">
          <div className="text-[#2E7D32] font-bold pb-2 border-b border-[#E5D8C8] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 size={16} />
              <span>REPORT COMPILATION LOG</span>
            </div>
            <button
              onClick={() => setGenerationOutput(null)}
              className="text-[#756B63] hover:text-[#2B241F] text-xs cursor-pointer font-sans"
            >
              Dismiss
            </button>
          </div>
          <pre className="p-3.5 rounded-lg bg-[#FBF8F1] border border-[#E5D8C8] text-[#2B241F] whitespace-pre-wrap leading-relaxed max-h-56 overflow-y-auto">
            {generationOutput}
          </pre>
        </div>
      )}

      {/* Compiled Reports Table */}
      <div className="workstation-card bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] overflow-hidden space-y-0">
        <div className="p-5 border-b border-[#E5D8C8]">
          <h2 className="section-title text-[18px] font-semibold text-[#2B241F]">
            Compiled Reports ({reports.length})
          </h2>
          <p className="text-[13px] text-[#756B63] mt-0.5">
            Archived dossiers saved in case repository.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="workstation-table">
            <thead>
              <tr>
                <th>Report File</th>
                <th className="w-28">Format</th>
                <th className="w-32">Size</th>
                <th className="w-48">Generated</th>
                <th>File Path</th>
              </tr>
            </thead>
            <tbody>
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-[13.5px] text-[#756B63]">
                    No reports generated yet. Click &quot;Compile Report&quot; above to generate dossier.
                  </td>
                </tr>
              ) : (
                reports.map((rep, idx) => (
                  <tr key={rep.filepath || idx} className="hover:bg-[#FDF9F2]">
                    <td className="font-semibold text-[13px] text-[#2B241F]">
                      <div className="flex items-center gap-2">
                        <FileText size={15} className="text-[#D96B27]" />
                        <span>{rep.filename || (rep as any).title || 'Forensic Dossier'}</span>
                      </div>
                    </td>
                    <td>
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#FBF8F1] text-[#2B241F] border border-[#E5D8C8]">
                        {rep.format || 'HTML'}
                      </span>
                    </td>
                    <td className="font-mono text-[12px] text-[#2B241F]">
                      {rep.size_bytes != null ? `${(rep.size_bytes / 1024).toFixed(1)} KB` : 'N/A'}
                    </td>
                    <td className="font-mono text-[12px] text-[#756B63]">
                      {rep.created_iso
                        ? String(rep.created_iso).replace('T', ' ').replace('Z', '')
                        : (rep as any).generated_at
                        ? String((rep as any).generated_at).replace('T', ' ').replace('Z', '')
                        : 'N/A'}
                    </td>
                    <td className="font-mono text-[11.5px] text-[#756B63] truncate max-w-xs" title={rep.filepath}>
                      {rep.filepath || 'N/A'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
