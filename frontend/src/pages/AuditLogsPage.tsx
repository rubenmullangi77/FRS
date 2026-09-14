import React, { useState, useEffect, useMemo } from 'react';
import {
  ScrollText,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Search,
  RefreshCw,
  User,
  Filter,
  X,
  Copy,
  Check,
  RotateCcw,
  FileSearch,
  Disc,
  Info,
  Layers,
  HardDrive
} from 'lucide-react';
import { api } from '../services/api';
import { AuditLogEntry, CaseMetadata } from '../types';
import { settingsService } from '../services/settings';

interface AuditLogsPageProps {
  activeCase: CaseMetadata | null;
}

export const AuditLogsPage: React.FC<AuditLogsPageProps> = ({ activeCase }) => {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [totalEntries, setTotalEntries] = useState<number>(0);
  const [logPath, setLogPath] = useState<string | null>(null);
  const [chainVerified, setChainVerified] = useState<boolean>(true);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [examinerName, setExaminerName] = useState<string>(settingsService.getExaminerName());

  // Filter state
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedEventType, setSelectedEventType] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCaseFilter, setSelectedCaseFilter] = useState<string>('ALL');

  // Detail Modal state
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    return settingsService.subscribe((s) => {
      setExaminerName(s.examinerName.trim() || 'Examiner not set');
    });
  }, []);

  const loadAuditLogs = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.getAuditLogs(activeCase?.workspace_path);
      setEntries(res.entries || []);
      setTotalEntries(res.total_entries || 0);
      setLogPath(res.log_path);
      setChainVerified(res.chain_verified);
    } catch (err: any) {
      setError('Unable to refresh data.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAuditLogs();
  }, [activeCase?.case_id]);

  // Derived Summary Counts
  const counts = useMemo(() => {
    let recovery = 0;
    let sanitization = 0;
    let system = 0;

    for (const e of entries) {
      const type = (e.event_type || '').toUpperCase();
      const op = (e.operation_type || e.action || '').toUpperCase();
      const combined = `${type} ${op}`;

      if (combined.includes('RECOVERY') || combined.includes('CARVE') || combined.includes('EXTRACT') || combined.includes('RESTORE')) {
        recovery++;
      } else if (combined.includes('SANITIZ') || combined.includes('WIPE') || combined.includes('ERASE') || combined.includes('PURGE')) {
        sanitization++;
      } else {
        system++;
      }
    }

    return {
      total: entries.length,
      recovery,
      sanitization,
      system
    };
  }, [entries]);

  // Unique Cases for Filter
  const caseOptions = useMemo(() => {
    const set = new Set<string>();
    for (const e of entries) {
      if (e.case_id) set.add(e.case_id);
    }
    return Array.from(set);
  }, [entries]);

  // Filtered entries
  const filteredEntries = useMemo(() => {
    return entries.filter((e) => {
      // 1. Search filter
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const evId = (e.event_id || `EVT-${e.entry_id}`).toLowerCase();
        const op = (e.operation_type || e.action || e.event_type || '').toLowerCase();
        const src = (e.source_identifier || '').toLowerCase();
        const user = (e.operator_name || e.user || '').toLowerCase();
        const caseId = (e.case_id || '').toLowerCase();
        const hash = (e.entry_hash || e.record_hash || '').toLowerCase();
        const details = (e.details || '').toLowerCase();

        const match =
          evId.includes(term) ||
          op.includes(term) ||
          src.includes(term) ||
          user.includes(term) ||
          caseId.includes(term) ||
          hash.includes(term) ||
          details.includes(term);

        if (!match) return false;
      }

      // 2. Event Type Filter
      if (selectedEventType !== 'ALL') {
        const type = (e.event_type || '').toUpperCase();
        const op = (e.operation_type || e.action || '').toUpperCase();
        const combined = `${type} ${op}`;

        if (selectedEventType === 'RECOVERY') {
          if (!combined.includes('RECOVERY') && !combined.includes('CARVE') && !combined.includes('EXTRACT') && !combined.includes('RESTORE')) {
            return false;
          }
        } else if (selectedEventType === 'SANITIZATION') {
          if (!combined.includes('SANITIZ') && !combined.includes('WIPE') && !combined.includes('ERASE') && !combined.includes('PURGE')) {
            return false;
          }
        } else if (selectedEventType === 'SYSTEM') {
          if (combined.includes('RECOVERY') || combined.includes('CARVE') || combined.includes('SANITIZ') || combined.includes('WIPE') || combined.includes('ERASE')) {
            return false;
          }
        } else if (selectedEventType === 'EVIDENCE') {
          if (!combined.includes('EVIDENCE') && !combined.includes('IMPORT') && !combined.includes('CUSTODY')) {
            return false;
          }
        }
      }

      // 3. Severity Filter
      if (selectedSeverity !== 'ALL') {
        const sev = (e.severity || 'INFO').toUpperCase();
        if (sev !== selectedSeverity) return false;
      }

      // 4. Case ID Filter
      if (selectedCaseFilter !== 'ALL') {
        if (e.case_id !== selectedCaseFilter) return false;
      }

      return true;
    });
  }, [entries, searchTerm, selectedEventType, selectedSeverity, selectedCaseFilter]);

  const hasActiveFilters = searchTerm !== '' || selectedEventType !== 'ALL' || selectedSeverity !== 'ALL' || selectedCaseFilter !== 'ALL';

  const resetFilters = () => {
    setSearchTerm('');
    setSelectedEventType('ALL');
    setSelectedSeverity('ALL');
    setSelectedCaseFilter('ALL');
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const formatTimestamp = (ts: string | undefined): string => {
    if (!ts) return 'N/A';
    return String(ts).replace('T', ' ').substring(0, 19);
  };

  const formatEventName = (raw: string | undefined): string => {
    if (!raw) return 'System Event';
    return raw
      .replace(/_/g, ' ')
      .toLowerCase()
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  return (
    <div className="p-6 lg:p-10 space-y-6 max-w-7xl mx-auto w-full min-w-0 min-h-full pb-24 box-border">
      {/* 1. WORKSTATION HEADER */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <h1 className="page-title text-[24px] sm:text-[28px] font-bold text-[var(--text-primary)] tracking-tight">
              Activity & Audit Log
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-[var(--surface-secondary)] text-[#2E7D32] border border-[var(--border)]">
              SHA-256 Ledger
            </span>
          </div>
          <p className="text-[13.5px] text-[var(--text-secondary)] leading-relaxed">
            Tamper-evident forensic audit journal with cryptographic hash chaining ensuring strict chain-of-custody compliance.
          </p>
        </div>

        <div className="flex items-center gap-3 flex-shrink-0">
          <button
            type="button"
            onClick={loadAuditLogs}
            disabled={isLoading}
            aria-label="Refresh Journal"
            className="btn-secondary h-10 px-4 text-[13px] font-medium flex items-center gap-2 cursor-pointer"
          >
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <RefreshCw size={14} className={isLoading ? 'animate-spin text-[var(--primary-orange)]' : 'text-[var(--text-secondary)]'} aria-hidden="true" focusable="false" role="presentation" />
            </span>
            {' '}
            <span>Refresh Journal</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px] flex items-center gap-3">
          <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
            <AlertTriangle size={18} aria-hidden="true" focusable="false" role="presentation" />
          </span>
          <span>{error}</span>
        </div>
      )}

      {/* 2. SUMMARY METRICS CARDS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 md:gap-4">
        {/* Total Events */}
        <div className="workstation-card p-4.5">
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
            <span>Total Events</span>
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <ScrollText size={15} className="text-[var(--primary-orange)]" aria-hidden="true" focusable="false" role="presentation" />
            </span>
          </div>
          <div className="stat-number text-[26px] sm:text-[30px] font-bold font-mono text-[var(--text-primary)]">
            {counts.total}
          </div>
          <p className="text-[12px] text-[var(--text-secondary)] mt-0.5">
            {chainVerified ? 'Cryptographically chained' : 'Integrity check pending'}
          </p>
        </div>

        {/* Recovery Events */}
        <div className="workstation-card p-4.5">
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
            <span>Recovery Events</span>
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <RotateCcw size={15} className="text-[var(--primary-orange)]" aria-hidden="true" focusable="false" role="presentation" />
            </span>
          </div>
          <div className="stat-number text-[26px] sm:text-[30px] font-bold font-mono text-[var(--text-primary)]">
            {counts.recovery}
          </div>
          <p className="text-[12px] text-[var(--text-secondary)] mt-0.5">
            File carving & extraction operations
          </p>
        </div>

        {/* Sanitization Events */}
        <div className="workstation-card p-4.5">
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
            <span>Sanitization Events</span>
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <Disc size={15} className="text-[var(--text-secondary)]" aria-hidden="true" focusable="false" role="presentation" />
            </span>
          </div>
          <div className="stat-number text-[26px] sm:text-[30px] font-bold font-mono text-[var(--text-primary)]">
            {counts.sanitization}
          </div>
          <p className="text-[12px] text-[var(--text-secondary)] mt-0.5">
            Secure erasure & media purge records
          </p>
        </div>

        {/* System / Security Events */}
        <div className="workstation-card p-4.5">
          <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
            <span>System & Security</span>
            <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
              <ShieldCheck size={15} className="text-[var(--primary-orange)]" aria-hidden="true" focusable="false" role="presentation" />
            </span>
          </div>
          <div className="stat-number text-[26px] sm:text-[30px] font-bold font-mono text-[var(--text-primary)]">
            {counts.system}
          </div>
          <p className="text-[12px] text-[var(--text-secondary)] mt-0.5">
            Operator: <span className="font-semibold text-[var(--text-primary)]">{examinerName}</span>
          </p>
        </div>
      </div>

      {/* 3. COMPACT FILTER TOOLBAR */}
      <div className="p-3 bg-[var(--surface)] border border-[var(--border)] rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <span aria-hidden="true" className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] inline-flex items-center shrink-0 pointer-events-none select-none">
            <Search size={14} aria-hidden="true" focusable="false" role="presentation" />
          </span>
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter by event, target, operator, hash..."
            className="workstation-input text-[12.5px] py-1.5 pl-8 pr-8 rounded-lg w-full"
          />
          {searchTerm && (
            <button
              type="button"
              onClick={() => setSearchTerm('')}
              aria-label="Clear search"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            >
              <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                <X size={13} aria-hidden="true" focusable="false" role="presentation" />
              </span>
            </button>
          )}
        </div>

        {/* Dropdown Filters & Reset */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Event Type Filter */}
          <select
            value={selectedEventType}
            onChange={(e) => setSelectedEventType(e.target.value)}
            aria-label="Filter by Event Type"
            className="workstation-input text-[12px] py-1.5 px-2.5 rounded-lg bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)] cursor-pointer"
          >
            <option value="ALL">All Event Types</option>
            <option value="RECOVERY">Recovery / Carving</option>
            <option value="SANITIZATION">Data Sanitization</option>
            <option value="EVIDENCE">Evidence Custody</option>
            <option value="SYSTEM">System & Security</option>
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            aria-label="Filter by Severity"
            className="workstation-input text-[12px] py-1.5 px-2.5 rounded-lg bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)] cursor-pointer"
          >
            <option value="ALL">All Severities</option>
            <option value="INFO">Info</option>
            <option value="WARNING">Warning</option>
            <option value="ERROR">Error</option>
          </select>

          {/* Case Filter */}
          {caseOptions.length > 0 && (
            <select
              value={selectedCaseFilter}
              onChange={(e) => setSelectedCaseFilter(e.target.value)}
              aria-label="Filter by Case"
              className="workstation-input text-[12px] py-1.5 px-2.5 rounded-lg bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)] cursor-pointer max-w-[140px] truncate"
            >
              <option value="ALL">All Cases</option>
              {caseOptions.map((c) => (
                <option key={c} value={c}>
                  Case: {c}
                </option>
              ))}
            </select>
          )}

          {/* Reset Filters Button */}
          {hasActiveFilters && (
            <button
              type="button"
              onClick={resetFilters}
              aria-label="Reset Filters"
              className="btn-secondary h-8 px-2.5 text-[11.5px] font-medium flex items-center gap-1.5 cursor-pointer text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            >
              <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                <X size={12} aria-hidden="true" focusable="false" role="presentation" />
              </span>
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* 4. BALANCED FULL-WIDTH WORKSTATION TABLE */}
      <div className="workstation-card overflow-hidden border border-[var(--border)] rounded-xl">
        <div className="overflow-x-auto w-full">
          <table className="workstation-table table-fixed w-full text-left">
            <thead>
              <tr className="border-b border-[var(--border)] bg-[var(--surface-secondary)] text-[11.5px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
                <th className="w-[14%] px-4 py-3">Timestamp</th>
                <th className="w-[18%] px-4 py-3">Event / Operation</th>
                <th className="w-[12%] px-4 py-3">Type</th>
                <th className="w-[18%] px-4 py-3">Target / Source</th>
                <th className="w-[11%] px-4 py-3 text-center">Status</th>
                <th className="w-[27%] px-4 py-3">Details & Ledger</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)] text-[12.5px]">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-14 text-center text-[13px] text-[var(--text-secondary)] font-mono">
                    <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none mr-2">
                      <RefreshCw size={16} className="animate-spin text-[var(--primary-orange)]" aria-hidden="true" focusable="false" role="presentation" />
                    </span>
                    Loading tamper-evident audit ledger...
                  </td>
                </tr>
              ) : filteredEntries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-14 text-center text-[13px] text-[var(--text-secondary)] font-mono">
                    {entries.length === 0 ? (
                      'No activity recorded yet.'
                    ) : (
                      <div className="space-y-2">
                        <div>No entries match current search criteria.</div>
                        <button
                          type="button"
                          onClick={resetFilters}
                          className="btn-secondary h-7 px-3 text-[11.5px] inline-flex items-center gap-1 cursor-pointer mx-auto"
                        >
                          Clear Filters
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ) : (
                filteredEntries.map((entry, idx) => {
                  const evId = entry.event_id || `EVT-${entry.entry_id || idx + 1}`;
                  const opName = entry.operation_type || entry.action || entry.event_type || 'System Event';
                  const src = entry.source_identifier || entry.case_id || 'System Core';
                  const isOk = entry.status === 'SUCCESS' || entry.status === 'COMPLETED';

                  return (
                    <tr
                      key={entry.entry_id ?? idx}
                      onClick={() => setSelectedEntry(entry)}
                      className="hover:bg-[var(--surface-hover)] cursor-pointer transition-colors group"
                      title="Click to view complete tamper-evident audit details"
                    >
                      {/* 1. Time */}
                      <td className="px-4 py-3 font-mono text-[11px] text-[var(--text-secondary)] whitespace-nowrap">
                        {formatTimestamp(entry.timestamp)}
                      </td>

                      {/* 2. Event */}
                      <td className="px-4 py-3 font-medium text-[13px] text-[var(--text-primary)] truncate">
                        <div className="truncate font-semibold" title={opName}>
                          {formatEventName(opName)}
                        </div>
                        <div className="text-[10px] font-mono text-[var(--text-muted)] truncate">
                          {evId}
                        </div>
                      </td>

                      {/* 3. Type */}
                      <td className="px-4 py-3">
                        <span className="inline-block px-2 py-0.5 rounded text-[10.5px] font-mono font-semibold bg-[var(--surface-secondary)] text-[var(--text-secondary)] border border-[var(--border)] truncate max-w-full">
                          {entry.event_type || 'SYSTEM'}
                        </span>
                      </td>

                      {/* 4. Source */}
                      <td className="px-4 py-3 font-mono text-[11.5px] text-[var(--text-secondary)] truncate" title={src}>
                        <div className="truncate font-medium text-[var(--text-primary)]">
                          {src}
                        </div>
                        <div className="text-[10px] text-[var(--text-muted)] truncate">
                          {entry.source_type || 'STORAGE'}
                        </div>
                      </td>

                      {/* 5. Status */}
                      <td className="px-4 py-3 text-center whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold ${
                            isOk
                              ? 'bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20'
                              : 'bg-[#C53030]/10 text-[#C53030] border border-[#C53030]/20'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              isOk ? 'bg-[#2E7D32]' : 'bg-[#C53030]'
                            }`}
                          />
                          <span>{entry.status || 'SUCCESS'}</span>
                        </span>
                      </td>

                      {/* 6. Details */}
                      <td className="px-4 py-3 text-[12px] text-[var(--text-secondary)] truncate">
                        <div className="truncate text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] transition-colors" title={entry.details || entry.message || ''}>
                          {entry.details || entry.message || 'Operation recorded in immutable chain.'}
                        </div>
                        <div className="text-[10px] font-mono text-[var(--text-muted)] truncate mt-0.5">
                          Hash: {entry.entry_hash ? `${entry.entry_hash.substring(0, 16)}...` : 'Linked'}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 5. TAMPER-EVIDENT AUDIT DETAIL MODAL */}
      {selectedEntry && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="audit-detail-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-fade-in"
        >
          <div className="workstation-card bg-[var(--surface)] border border-[var(--border)] rounded-xl w-full max-w-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="p-5 border-b border-[var(--border)] flex items-center justify-between bg-[var(--surface-secondary)]">
              <div className="flex items-center gap-3">
                <span aria-hidden="true" className="w-8 h-8 rounded-lg bg-[#2E7D32]/10 border border-[#2E7D32]/20 text-[#2E7D32] flex items-center justify-center inline-flex shrink-0 pointer-events-none select-none">
                  <ShieldCheck size={18} aria-hidden="true" focusable="false" role="presentation" />
                </span>
                <div>
                  <h3 id="audit-detail-title" className="text-[16px] font-bold text-[var(--text-primary)]">
                    Audit Event Details
                  </h3>
                  <div className="text-[11.5px] font-mono text-[var(--text-muted)]">
                    {selectedEntry.event_id || `EVT-${selectedEntry.entry_id}`} • {formatTimestamp(selectedEntry.timestamp)}
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setSelectedEntry(null)}
                aria-label="Close details"
                className="w-8 h-8 rounded-lg flex items-center justify-center text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)] cursor-pointer"
              >
                <span aria-hidden="true" className="inline-flex items-center shrink-0 pointer-events-none select-none">
                  <X size={16} aria-hidden="true" focusable="false" role="presentation" />
                </span>
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 overflow-y-auto space-y-5 text-[12.5px]">
              {/* Properties Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 p-4 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                <div>
                  <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Operation</div>
                  <div className="font-semibold text-[13px] text-[var(--text-primary)] mt-0.5">
                    {formatEventName(selectedEntry.operation_type || selectedEntry.action)}
                  </div>
                </div>

                <div>
                  <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Event Type</div>
                  <div className="font-mono text-[12px] text-[var(--text-primary)] mt-0.5">
                    {selectedEntry.event_type || 'SYSTEM'}
                  </div>
                </div>

                <div>
                  <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Target / Source</div>
                  <div className="font-mono text-[12px] text-[var(--text-primary)] mt-0.5 break-all">
                    {selectedEntry.source_identifier || 'System Core'}
                  </div>
                </div>

                <div>
                  <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Source Type</div>
                  <div className="font-mono text-[12px] text-[var(--text-primary)] mt-0.5">
                    {selectedEntry.source_type || 'STORAGE'}
                  </div>
                </div>

                <div>
                  <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Investigator / Operator</div>
                  <div className="text-[12.5px] text-[var(--text-primary)] mt-0.5 font-medium">
                    {selectedEntry.operator_name || selectedEntry.user || examinerName}
                  </div>
                </div>

                <div>
                  <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Case Reference</div>
                  <div className="font-mono text-[12px] text-[var(--text-primary)] mt-0.5">
                    {selectedEntry.case_id || 'Global Lab Session'}
                  </div>
                </div>

                <div>
                  <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Status</div>
                  <div className="mt-0.5">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20">
                      <CheckCircle2 size={11} />
                      <span>{selectedEntry.status || 'SUCCESS'}</span>
                    </span>
                  </div>
                </div>

                <div>
                  <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Severity</div>
                  <div className="mt-0.5">
                    <span className="inline-block px-2 py-0.5 rounded text-[10.5px] font-mono font-semibold bg-[var(--surface)] text-[var(--text-primary)] border border-[var(--border)]">
                      {selectedEntry.severity || 'INFO'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Message / Details */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                  Event Message & Diagnostic Data
                </div>
                <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] font-mono text-[11.5px] text-[var(--text-primary)] whitespace-pre-wrap break-words">
                  {selectedEntry.details || selectedEntry.message || 'No additional details provided for this event.'}
                </div>
              </div>

              {/* Cryptographic Hashes */}
              <div className="space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                  Cryptographic Chain of Custody Hashes
                </div>

                {/* Record Hash */}
                <div className="p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10.5px] font-mono font-bold text-[var(--text-secondary)] uppercase">
                      Current Record SHA-256 Hash
                    </span>
                    {selectedEntry.entry_hash && (
                      <button
                        type="button"
                        onClick={() => copyToClipboard(selectedEntry.entry_hash || '', 'curr')}
                        className="text-[11px] font-medium text-[var(--primary-orange)] hover:underline flex items-center gap-1 cursor-pointer"
                      >
                        {copiedField === 'curr' ? (
                          <>
                            <Check size={12} />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy size={12} />
                            <span>Copy Hash</span>
                          </>
                        )}
                      </button>
                    )}
                  </div>
                  <div className="font-mono text-[11px] text-[var(--text-primary)] break-all select-all">
                    {selectedEntry.entry_hash || selectedEntry.record_hash || 'Computed on chain write'}
                  </div>
                </div>

                {/* Previous Hash */}
                <div className="p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10.5px] font-mono font-bold text-[var(--text-secondary)] uppercase">
                      Previous Chain Link Hash
                    </span>
                    {selectedEntry.previous_hash && (
                      <button
                        type="button"
                        onClick={() => copyToClipboard(selectedEntry.previous_hash || '', 'prev')}
                        className="text-[11px] font-medium text-[var(--primary-orange)] hover:underline flex items-center gap-1 cursor-pointer"
                      >
                        {copiedField === 'prev' ? (
                          <>
                            <Check size={12} />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy size={12} />
                            <span>Copy Hash</span>
                          </>
                        )}
                      </button>
                    )}
                  </div>
                  <div className="font-mono text-[11px] text-[var(--text-muted)] break-all select-all">
                    {selectedEntry.previous_hash || selectedEntry.prev_hash || '0000000000000000000000000000000000000000000000000000000000000000'}
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-[var(--border)] flex items-center justify-between bg-[var(--surface-secondary)]">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">
                ForensiVault Forensic Integrity Engine
              </span>
              <button
                type="button"
                onClick={() => setSelectedEntry(null)}
                className="btn-secondary h-8 px-4 text-[12px] font-medium cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
