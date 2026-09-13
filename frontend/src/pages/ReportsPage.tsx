import React, { useState, useEffect } from 'react';
import {
  FileText,
  Plus,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Eye,
  FileCode,
  Download,
  ExternalLink,
  Briefcase
} from 'lucide-react';
import { api } from '../services/api';
import { ForensicReportItem, CaseMetadata } from '../types';
import { settingsService } from '../services/settings';

interface ReportsPageProps {
  activeCase: CaseMetadata | null;
  onSelectCase?: (c: CaseMetadata) => void;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ activeCase, onSelectCase }) => {
  const [cases, setCases] = useState<CaseMetadata[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(activeCase?.case_id || '');
  const [reports, setReports] = useState<ForensicReportItem[]>([]);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [generationOutput, setGenerationOutput] = useState<string | null>(null);
  const [includePdf, setIncludePdf] = useState<boolean>(true);
  const [filterByCase, setFilterByCase] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [examinerName, setExaminerName] = useState<string>(settingsService.getExaminerName());

  useEffect(() => {
    return settingsService.subscribe((s) => {
      setExaminerName(s.examinerName.trim() || 'Examiner not set');
    });
  }, []);

  const loadCases = async () => {
    try {
      const res = await api.listCases();
      const list = res.cases || [];
      setCases(list);
      if (!selectedCaseId && list.length > 0) {
        const initialCase = activeCase || list[0];
        setSelectedCaseId(initialCase.case_id);
        if (onSelectCase && !activeCase) {
          onSelectCase(initialCase);
        }
      }
    } catch (err: any) {
      console.error('Failed to fetch cases list', err);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  useEffect(() => {
    if (activeCase?.case_id) {
      setSelectedCaseId(activeCase.case_id);
    }
  }, [activeCase]);

  const loadReports = async () => {
    setIsRefreshing(true);
    try {
      const caseFilter = filterByCase && selectedCaseId ? selectedCaseId : undefined;
      const res = await api.listReports(caseFilter);
      setReports(res.reports || []);
      setError(null);
    } catch (err: any) {
      setError('Unable to refresh reports data.');
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, [selectedCaseId, filterByCase]);

  const handleCaseChange = (caseId: string) => {
    setSelectedCaseId(caseId);
    setError(null);
    const target = cases.find((c) => c.case_id === caseId);
    if (target && onSelectCase) {
      onSelectCase(target);
    }
  };

  const selectedCaseObj =
    cases.find((c) => c.case_id === selectedCaseId) ||
    (activeCase?.case_id === selectedCaseId ? activeCase : null);

  const handleGenerateReport = async () => {
    if (!selectedCaseId || !selectedCaseId.trim()) {
      setError('Please select a case before generating a report.');
      return;
    }

    setIsGenerating(true);
    setError(null);
    setGenerationOutput(null);

    try {
      const caseName = selectedCaseObj?.case_name || selectedCaseId;
      const title = `Forensic Investigation Dossier - ${caseName}`;
      const res = await api.generateReport({
        case_id: selectedCaseId,
        title,
        examiner_name: examinerName,
        format: includePdf ? 'PDF' : 'HTML'
      });
      setGenerationOutput(
        `Forensic PDF generated successfully!\nReport ID: ${res.report_id || 'N/A'}\nFile: ${res.filename || res.file_path}\nSHA-256: ${res.sha256 || 'N/A'}\nLocation: D:\\SIH\\reports`
      );
      await loadReports();
    } catch (err: any) {
      setError(err.message || 'Report generation failed');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleOpenReport = async (rep: ForensicReportItem) => {
    try {
      await api.openReport({ report_id: rep.report_id, filepath: rep.filepath });
    } catch (err: any) {
      setError(err.message || 'Unable to open report file');
    }
  };

  return (
    <div className="p-6 md:p-8 lg:p-10 space-y-6 max-w-[1400px] mx-auto bg-[var(--bg-main)] min-h-full">
      {/* Title & Top Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="page-title text-[28px] md:text-[30px] font-bold text-[var(--text-primary)] tracking-tight">
            Forensic Reports
          </h1>
          <p className="text-[13.5px] text-[var(--text-secondary)] mt-1 leading-relaxed">
            Generate and export court-admissible forensic documentation in JSON, HTML, and vector PDF formats.
          </p>
        </div>

        <button
          onClick={handleGenerateReport}
          disabled={isGenerating || !selectedCaseId}
          className="btn-primary h-[42px] px-5 text-[13px] font-semibold self-start sm:self-auto flex items-center gap-2"
          title={!selectedCaseId ? 'Please select a case before generating a report.' : 'Compile report for selected case'}
        >
          <Plus size={15} className={isGenerating ? 'animate-spin' : ''} aria-hidden="true" focusable="false" />
          <span>{isGenerating ? 'Compiling Dossier...' : 'Compile Report'}</span>
        </button>
      </div>

      {/* Case Selection & Target Workspace Card */}
      <div className="workstation-card p-5 bg-[var(--surface)] border border-[var(--border)] rounded-[10px] space-y-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
          {/* Selected Case Indicator */}
          <div className="space-y-1.5 flex-1">
            <div className="flex items-center gap-2">
              <Briefcase size={16} className="text-[#D96B27] flex-shrink-0" />
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
                Selected Case:
              </span>
              {selectedCaseObj ? (
                <span className="text-[14px] font-bold text-[var(--text-primary)]">
                  {selectedCaseObj.case_id} — {selectedCaseObj.case_name}
                </span>
              ) : (
                <span className="text-[14px] font-bold text-[#C53030]">
                  No Case Selected (Please select a case)
                </span>
              )}
            </div>
            <div className="text-[12px] text-[var(--text-secondary)] flex items-center gap-4 flex-wrap">
              <span>
                Lead Examiner: <strong className="text-[var(--text-primary)]">{examinerName}</strong>
              </span>
              {selectedCaseObj && (
                <>
                  <span>•</span>
                  <span>
                    Status: <span className="font-semibold text-[#2E7D32]">{selectedCaseObj.status || 'ACTIVE'}</span>
                  </span>
                </>
              )}
            </div>
          </div>

          {/* Case Picker Dropdown */}
          <div className="flex items-center gap-3">
            <label className="text-[12px] font-semibold text-[var(--text-secondary)] whitespace-nowrap">
              Switch Case:
            </label>
            <select
              value={selectedCaseId}
              onChange={(e) => handleCaseChange(e.target.value)}
              className="bg-[var(--surface-secondary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-[12.5px] font-medium text-[var(--text-primary)] focus:outline-none focus:border-[#D96B27] min-w-[220px]"
            >
              <option value="" disabled>
                -- Select Investigation Case --
              </option>
              {cases.map((c) => (
                <option key={c.case_id} value={c.case_id}>
                  {c.case_id} — {c.case_name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Options Row */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
          <div className="flex items-center gap-5 flex-wrap">
            <label className="flex items-center gap-2 text-[12.5px] text-[var(--text-primary)] font-medium cursor-pointer select-none">
              <input
                type="checkbox"
                checked={includePdf}
                onChange={(e) => setIncludePdf(e.target.checked)}
                className="w-4 h-4 rounded text-[#D96B27] focus:ring-0"
              />
              <span>Generate Court-Admissible Vector PDF</span>
            </label>

            <label className="flex items-center gap-2 text-[12.5px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] font-medium cursor-pointer select-none">
              <input
                type="checkbox"
                checked={filterByCase}
                onChange={(e) => setFilterByCase(e.target.checked)}
                className="w-4 h-4 rounded text-[#D96B27] focus:ring-0"
              />
              <span>Filter Report List to Selected Case Only</span>
            </label>
          </div>

          <button
            onClick={loadReports}
            disabled={isRefreshing}
            className="btn-secondary h-[34px] px-3.5 text-[12px] flex items-center gap-1.5 self-start sm:self-auto"
          >
            <RefreshCw size={13} className={isRefreshing ? 'animate-spin' : ''} />
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh List'}</span>
          </button>
        </div>
      </div>

      {/* Format Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="workstation-card p-4 bg-[var(--surface)] border border-[var(--border)] rounded-[8px] space-y-1.5">
          <div className="font-semibold text-[#D96B27] flex items-center gap-2 text-[13px]">
            <FileCode size={15} />
            Structured JSON Report
          </div>
          <p className="text-[var(--text-secondary)] leading-relaxed text-[12px]">
            Strict case-scoped evidence hashes, carved file offsets, and recovery confidence scores.
          </p>
        </div>

        <div className="workstation-card p-4 bg-[var(--surface)] border border-[var(--border)] rounded-[8px] space-y-1.5">
          <div className="font-semibold text-[#2E7D32] flex items-center gap-2 text-[13px]">
            <Eye size={15} />
            Interactive HTML Report
          </div>
          <p className="text-[var(--text-secondary)] leading-relaxed text-[12px]">
            Audited investigator report with interactive tables, hex dumps, and case chain-of-custody.
          </p>
        </div>

        <div className="workstation-card p-4 bg-[var(--surface)] border border-[var(--border)] rounded-[8px] space-y-1.5">
          <div className="font-semibold text-[var(--text-primary)] flex items-center gap-2 text-[13px]">
            <FileText size={15} />
            Printable Vector PDF
          </div>
          <p className="text-[var(--text-secondary)] leading-relaxed text-[12px]">
            High-resolution court dossier with case details, evidence verification, and examiner signatures.
          </p>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-lg bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px] flex items-center gap-3">
          <AlertTriangle size={18} className="flex-shrink-0" aria-hidden="true" focusable="false" />
          <span>{error}</span>
        </div>
      )}

      {/* Validation Hint when no case selected */}
      {!selectedCaseId && !error && (
        <div className="p-4 rounded-lg bg-[#D96B27]/10 border border-[#D96B27]/30 text-[#D96B27] text-[13px] flex items-center gap-3">
          <AlertTriangle size={18} className="flex-shrink-0" />
          <span>Please select a case before generating a report.</span>
        </div>
      )}

      {/* Generation Output Terminal */}
      {generationOutput && (
        <div className="workstation-card p-5 bg-[var(--surface)] border border-[var(--border)] rounded-[10px] space-y-2 font-mono text-xs">
          <div className="text-[#2E7D32] font-bold pb-2 border-b border-[var(--border)] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 size={16} />
              <span>REPORT COMPILATION LOG</span>
            </div>
            <button
              onClick={() => setGenerationOutput(null)}
              className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-xs cursor-pointer font-sans"
            >
              Dismiss
            </button>
          </div>
          <pre className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed max-h-56 overflow-y-auto">
            {generationOutput}
          </pre>
        </div>
      )}

      {/* Compiled Reports List - Redesigned: Responsive Compact Cards, NO Horizontal Scroll */}
      <div className="workstation-card bg-[var(--surface)] border border-[var(--border)] rounded-[10px] p-5 space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[var(--border)]">
          <div>
            <h2 className="section-title text-[17px] font-semibold text-[var(--text-primary)]">
              Compiled Forensic Reports ({reports.length})
            </h2>
            <p className="text-[12.5px] text-[var(--text-secondary)] mt-0.5">
              {filterByCase && selectedCaseId
                ? `Filtered strictly to ${selectedCaseId}`
                : 'All archived forensic dossiers saved in case repository (D:\\SIH\\reports)'}
            </p>
          </div>
        </div>

        {reports.length === 0 ? (
          <div className="py-12 text-center text-[13.5px] text-[var(--text-secondary)] space-y-2">
            <FileText size={32} className="mx-auto text-[var(--text-secondary)] opacity-50" />
            <p>No reports generated yet for this view.</p>
            <p className="text-[12px]">Click &quot;Compile Report&quot; above to generate a court-admissible dossier.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {reports.map((rep, idx) => (
              <div
                key={rep.filepath || rep.report_id || idx}
                className="p-4 bg-[var(--surface-secondary)] border border-[var(--border)] rounded-[8px] hover:border-[#D96B27]/40 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                {/* Left: Essential Report Metadata */}
                <div className="space-y-2 min-w-0 flex-1">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <FileText size={16} className="text-[#D96B27] flex-shrink-0" />
                    <span
                      className="font-bold text-[13.5px] text-[var(--text-primary)] truncate max-w-md"
                      title={rep.filename || rep.title}
                    >
                      {rep.filename || rep.title || 'Forensic Dossier'}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/30">
                      {rep.status || 'Generated'}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[var(--surface)] text-[var(--text-secondary)] border border-[var(--border)]">
                      {rep.format || 'PDF'}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 md:gap-4 text-[12px] text-[var(--text-secondary)] flex-wrap">
                    <span className="flex items-center gap-1 font-mono text-[var(--text-primary)]">
                      <span className="text-[var(--text-secondary)]">Case:</span>
                      <span className="font-semibold text-[#D96B27]">{rep.case_id || 'N/A'}</span>
                      {rep.case_name && (
                        <span className="text-[var(--text-secondary)] truncate max-w-[220px]">
                          — {rep.case_name}
                        </span>
                      )}
                    </span>
                    <span>•</span>
                    <span>
                      Generated:{' '}
                      <span className="font-mono text-[var(--text-primary)]">
                        {rep.created_iso
                          ? String(rep.created_iso).replace('T', ' ').slice(0, 19)
                          : rep.generated_at
                          ? String(rep.generated_at).replace('T', ' ').slice(0, 19)
                          : 'N/A'}
                      </span>
                    </span>
                    <span>•</span>
                    <span>
                      Recovered Files:{' '}
                      <strong className="text-[var(--text-primary)]">{rep.recovered_count ?? '—'}</strong>
                    </span>
                    <span>•</span>
                    <span>
                      Size:{' '}
                      <span className="font-mono text-[var(--text-primary)]">
                        {rep.size_bytes != null ? `${(rep.size_bytes / 1024).toFixed(1)} KB` : 'N/A'}
                      </span>
                    </span>
                  </div>
                </div>

                {/* Right: Always-Visible Action Buttons (Never Pushed Off-Screen) */}
                <div className="flex items-center gap-2 flex-shrink-0 self-start md:self-center">
                  <button
                    onClick={() => handleOpenReport(rep)}
                    className="btn-secondary h-[32px] px-3 text-[11.5px] gap-1.5 flex items-center font-medium"
                    title="Open report in default system viewer"
                  >
                    <ExternalLink size={12} />
                    <span>Open</span>
                  </button>
                  <a
                    href={api.getReportDownloadUrl(rep.report_id, rep.filepath)}
                    download={rep.filename || 'forensic_report.pdf'}
                    className="btn-primary h-[32px] px-3 text-[11.5px] gap-1.5 inline-flex items-center font-medium"
                    title="Download report file"
                  >
                    <Download size={12} />
                    <span>Download</span>
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

