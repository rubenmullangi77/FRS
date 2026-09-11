import React, { useState, useEffect } from 'react';
import {
  ScrollText,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Search,
  RefreshCw,
  User
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
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [examinerName, setExaminerName] = useState<string>(settingsService.getExaminerName());

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
      setError(err.message || 'Failed to load audit logs');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAuditLogs();
  }, [activeCase]);

  const filteredEntries = entries.filter((e) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      ((e.operation_type || (e as any).action || (e as any).event_type || '').toLowerCase().includes(term)) ||
      (e.case_id && String(e.case_id).toLowerCase().includes(term)) ||
      (e.source_identifier && String(e.source_identifier).toLowerCase().includes(term)) ||
      (e.status && String(e.status).toLowerCase().includes(term)) ||
      (e.operator_name && String(e.operator_name).toLowerCase().includes(term))
    );
  });

  return (
    <div className="p-8 lg:p-10 space-y-8 max-w-[1400px] mx-auto bg-[#F7F2E8] min-h-full">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="page-title text-[30px] font-bold text-[#2B241F] tracking-tight">
            Activity & Audit Log
          </h1>
          <p className="text-[14px] text-[#756B63] mt-1 leading-relaxed">
            Immutable JSONL audit journal with SHA-256 hash chaining for tamper-evident chain of custody.
          </p>
        </div>

        <button
          onClick={loadAuditLogs}
          disabled={isLoading}
          className="btn-secondary h-[40px] px-4 text-[13px] font-medium self-start sm:self-auto"
        >
          <RefreshCw size={13} className={isLoading ? 'animate-spin' : ''} />
          <span>Refresh Journal</span>
        </button>
      </div>

      {/* Chain Status Card */}
      <div className="workstation-card p-5 bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-[#2E7D32]/10 border border-[#2E7D32]/25 flex items-center justify-center text-[#2E7D32]">
            <ShieldCheck size={22} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[15px] font-bold text-[#2B241F]">
                {chainVerified ? 'Cryptographic Hash Chain Verified' : 'Integrity Check Pending'}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#2E7D32]/10 text-[#2E7D32] border border-[#2E7D32]/20">
                Tamper-Evident
              </span>
            </div>
            <div className="text-[12.5px] text-[#756B63] mt-0.5">
              Active Operator: <span className="font-semibold text-[#2B241F]">{examinerName}</span> • Every operation record is linked to the previous entry hash.
            </div>
          </div>
        </div>

        <div className="text-[13px] font-mono text-[#756B63]">
          Total Entries: <span className="text-[#2B241F] font-bold text-[15px]">{totalEntries}</span>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-[#C53030]/10 border border-[#C53030]/30 text-[#C53030] text-[13px] flex items-center gap-3">
          <AlertTriangle size={18} className="flex-shrink-0" aria-hidden="true" focusable="false" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="workstation-card bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] overflow-hidden">
        <div className="p-5 border-b border-[#E5D8C8] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2 bg-[#FBF8F1] border border-[#E5D8C8] rounded-md px-3 py-1.5 text-[12.5px]">
            <Search size={13} className="text-[#756B63]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search operation, target, hash..."
              className="bg-transparent text-[#2B241F] text-[12.5px] focus:outline-none w-56"
            />
          </div>

          <div className="text-[12px] font-mono text-[#756B63] truncate max-w-md" title={logPath || ''}>
            Journal: {logPath || 'System Root Journal'}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="workstation-table">
            <thead>
              <tr>
                <th className="w-14">#</th>
                <th className="w-32">Timestamp</th>
                <th className="w-56">Operation</th>
                <th>Target / Identifier</th>
                <th className="w-36">Operator</th>
                <th className="w-28">Condition</th>
                <th className="w-36">SHA-256 Digest</th>
              </tr>
            </thead>
            <tbody>
              {filteredEntries.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[13.5px] text-[#756B63]">
                    {entries.length === 0
                      ? 'No audit activity recorded yet.'
                      : 'No entries match current search criteria.'}
                  </td>
                </tr>
              ) : (
                filteredEntries.map((entry, idx) => (
                  <tr
                    key={entry?.entry_id ?? idx}
                    onClick={() => setSelectedEntry(entry)}
                    className="hover:bg-[#FDF9F2] cursor-pointer"
                  >
                    <td className="font-mono text-[12px] text-[#756B63] font-bold">
                      #{entry?.entry_id ?? (entry as any)?.id ?? idx + 1}
                    </td>
                    <td className="font-mono text-[12px] text-[#756B63]">
                      {entry?.timestamp ? String(entry.timestamp).replace('T', ' ').substring(11, 19) + ' UTC' : 'N/A'}
                    </td>
                    <td className="font-semibold text-[13px] text-[#2B241F]">
                      {(entry?.operation_type || (entry as any)?.action || (entry as any)?.event_type || 'SYSTEM_EVENT').replace(/_/g, ' ')}
                    </td>
                    <td className="font-mono text-[11.5px] text-[#756B63] truncate max-w-xs" title={entry?.source_identifier || entry?.case_id}>
                      {entry?.source_identifier || entry?.case_id || 'System Core'}
                    </td>
                    <td className="text-[12.5px] text-[#2B241F]">
                      {entry?.operator_name || (entry as any)?.user || examinerName}
                    </td>
                    <td>
                      <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-[#2E7D32]">
                        <span className="w-2 h-2 rounded-full bg-[#2E7D32]" />
                        <span>{entry?.status === 'SUCCESS' ? 'Completed' : (entry?.status || 'Completed')}</span>
                      </span>
                    </td>
                    <td className="font-mono text-[11px] text-[#756B63]">
                      {entry?.entry_hash ? `${String(entry.entry_hash).substring(0, 16)}...` : 'N/A'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Entry Detail Drawer / Modal */}
      {selectedEntry && (
        <div className="workstation-card p-6 bg-[#FFFDF8] border border-[#E5D8C8] rounded-[10px] space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-[#E5D8C8] pb-2 text-[#D96B27] font-bold">
            <span>AUDIT ENTRY #{selectedEntry.entry_id} DETAILS</span>
            <button
              onClick={() => setSelectedEntry(null)}
              className="text-[#756B63] hover:text-[#2B241F] text-xs cursor-pointer font-sans"
            >
              Dismiss
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[12px] text-[#2B241F]">
            <div><span className="text-[#756B63]">Operation:</span> {selectedEntry.operation_type}</div>
            <div><span className="text-[#756B63]">Timestamp:</span> {selectedEntry.timestamp}</div>
            <div><span className="text-[#756B63]">Operator:</span> {selectedEntry.operator_name || examinerName}</div>
            <div><span className="text-[#756B63]">Case ID:</span> {selectedEntry.case_id || 'N/A'}</div>
            <div className="col-span-full"><span className="text-[#756B63]">Target:</span> {selectedEntry.source_identifier || 'N/A'}</div>
            <div className="col-span-full"><span className="text-[#756B63]">Details:</span> {selectedEntry.details || 'N/A'}</div>
            <div className="col-span-full break-all"><span className="text-[#756B63]">Entry Hash:</span> {selectedEntry.entry_hash}</div>
            <div className="col-span-full break-all"><span className="text-[#756B63]">Previous Hash:</span> {selectedEntry.previous_hash}</div>
          </div>
        </div>
      )}
    </div>
  );
};
