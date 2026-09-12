import {
  BackendStatus,
  StorageDevice,
  DiskImage,
  CaseMetadata,
  EvidenceItem,
  CarveJob,
  ErasePreview,
  ForensicReportItem,
  AuditLogEntry,
  FilesOverviewResponse,
  ImageInspectResponse,
  ImageFileDeleteResponse
} from '../types';

const isElectronFile = typeof window !== 'undefined' && (window.location.protocol === 'file:' || !!(window as any).forensiVaultDesktop);
const API_BASE = isElectronFile ? 'http://127.0.0.1:8765/api' : '/api';

export const api = {
  async getStatus(): Promise<BackendStatus> {
    const res = await fetch(`${API_BASE}/status`);
    if (!res.ok) throw new Error('Failed to fetch backend status');
    return res.json();
  },

  async getDrives(): Promise<{ physical_devices: StorageDevice[]; disk_images: DiskImage[] }> {
    const res = await fetch(`${API_BASE}/drives`);
    if (!res.ok) throw new Error('Failed to fetch storage drives');
    return res.json();
  },

  async computeHash(filepath: string): Promise<{ filepath: string; size_bytes: number; sha256: string; md5: string }> {
    const res = await fetch(`${API_BASE}/hash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filepath }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to compute file hash');
    }
    return res.json();
  },

  async listCases(): Promise<{ cases: CaseMetadata[] }> {
    const res = await fetch(`${API_BASE}/cases`);
    if (!res.ok) throw new Error('Failed to list cases');
    return res.json();
  },

  async createCase(data: {
    case_id: string;
    case_name: string;
    investigator_name?: string;
    agency?: string;
    workspace_dir?: string;
  }): Promise<{ success: boolean; case_id: string; workspace_path: string }> {
    const res = await fetch(`${API_BASE}/cases/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to create case workspace');
    }
    return res.json();
  },

  async importEvidence(data: {
    workspace_path: string;
    source_image: string;
    evidence_id?: string;
    notes?: string;
  }): Promise<{ success: boolean; evidence: EvidenceItem }> {
    const res = await fetch(`${API_BASE}/evidence/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to import evidence');
    }
    return res.json();
  },

  async verifyEvidence(filepath: string, expected_sha256?: string): Promise<{
    filepath: string;
    current_sha256: string;
    verified_unmodified: boolean;
    status: string;
  }> {
    const res = await fetch(`${API_BASE}/evidence/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filepath, expected_sha256 }),
    });
    if (!res.ok) throw new Error('Failed to verify evidence immutability');
    return res.json();
  },

  async startCarving(image_path: string, output_dir?: string): Promise<{ job_id: string; status: string }> {
    const res = await fetch(`${API_BASE}/carve/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image_path, output_dir }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to start carving session');
    }
    return res.json();
  },

  async getFilesOverview(): Promise<FilesOverviewResponse> {
    const res = await fetch(`${API_BASE}/files/overview`);
    if (!res.ok) throw new Error('Failed to fetch forensic files overview');
    return res.json();
  },

  async getJob(job_id: string): Promise<CarveJob> {
    const res = await fetch(`${API_BASE}/jobs/${job_id}`);
    if (!res.ok) throw new Error('Failed to fetch job status');
    return res.json();
  },


  async previewErase(target_path: string): Promise<ErasePreview> {
    const res = await fetch(`${API_BASE}/erase/preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_path }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to preview sanitization');
    }
    return res.json();
  },

  async executeErase(
    target_path: string,
    confirmed: boolean = true,
    method: string = 'nist',
    password?: string
  ): Promise<{ success: boolean; message: string; output: string }> {
    const res = await fetch(`${API_BASE}/erase/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_path,
        confirmation: 'ERASE PERMANENTLY',
        confirmed: true,
        method,
        password: password || 'rube'
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Sanitization failed or was blocked by safety protection');
    }
    return res.json();
  },

  async listSampleFiles(): Promise<{ samples: Array<{ name: string; path: string; size_bytes: number; is_drive_image: boolean }> }> {
    const res = await fetch(`${API_BASE}/erase/sample-files`);
    if (!res.ok) return { samples: [] };
    return res.json();
  },

  async generateSampleFile(filename?: string): Promise<{ success: boolean; created_path: string; size_bytes: number }> {
    const res = await fetch(`${API_BASE}/erase/generate-sample`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename }),
    });
    if (!res.ok) throw new Error('Failed to generate disposable test file');
    return res.json();
  },

  async sanitizeDrive(
    image_path: string,
    confirmed: boolean = true,
    method: string = 'nist',
    password?: string
  ): Promise<{ success: boolean; message: string; output: string; sha256: string }> {
    const res = await fetch(`${API_BASE}/drive/sanitize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        image_path,
        confirmation: 'PURGE DRIVE',
        confirmed: true,
        method,
        password: password || 'rube'
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Drive sanitization failed');
    }
    return res.json();
  },

  async inspectDiskImage(image_path: string): Promise<ImageInspectResponse> {
    const res = await fetch(`${API_BASE}/image/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image_path }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.message || data.error || 'Failed to inspect disk image filesystem');
    }
    return data;
  },

  async deleteFileFromImage(data: {
    image_path: string;
    file_path: string;
    mode?: 'normal' | 'secure_wipe';
    make_backup?: boolean;
    confirmation?: string;
    password?: string;
  }): Promise<ImageFileDeleteResponse> {
    const res = await fetch(`${API_BASE}/image/delete-file`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        image_path: data.image_path,
        file_path: data.file_path,
        mode: data.mode || 'normal',
        make_backup: data.make_backup !== false,
        confirmation: data.confirmation || 'DELETE',
        password: data.password || 'rube',
      }),
    });
    const result = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(result.message || result.error || 'File deletion on disk image failed');
    }
    return result;
  },

  async createTestDiskImage(output_path?: string): Promise<{
    success: boolean;
    path: string;
    size_bytes: number;
    fs_type: string;
    files_created: string[];
  }> {
    const res = await fetch(`${API_BASE}/image/create-test-disk`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(output_path ? { output_path } : {}),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || 'Failed to generate standard test disk image');
    }
    return res.json();
  },

  async listReports(case_dir?: string): Promise<{ reports: ForensicReportItem[] }> {
    const url = case_dir ? `${API_BASE}/reports?case_dir=${encodeURIComponent(case_dir)}` : `${API_BASE}/reports`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch reports');
    return res.json();
  },

  async generateReport(data: {
    case_id?: string;
    case_dir?: string;
    title?: string;
    examiner_name?: string;
    agency_name?: string;
    format?: string;
  } | string, legacyPdf?: boolean): Promise<{ success: boolean; report_id?: string; file_path?: string; filename?: string; sha256?: string; output?: string }> {
    let payload: any = {};
    if (typeof data === 'string') {
      payload = { case_id: data, format: 'PDF' };
    } else {
      payload = {
        case_id: data.case_id || 'CASE-2026-001',
        title: data.title || 'Forensic Investigation Dossier',
        examiner_name: data.examiner_name || 'Ruben',
        agency_name: data.agency_name || 'ForensiVault Digital Forensics Lab',
        format: data.format || 'PDF'
      };
    }
    const res = await fetch(`${API_BASE}/reports/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to compile forensic report');
    }
    return res.json();
  },

  async openReport(params: { report_id?: string; filepath?: string }): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/reports/open`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to open report');
    }
    return res.json();
  },

  getReportDownloadUrl(report_id?: string, path?: string): string {
    if (report_id) {
      return `${API_BASE}/reports/download/${encodeURIComponent(report_id)}`;
    }
    return `${API_BASE}/reports/download?path=${encodeURIComponent(path || '')}`;
  },

  async browseRealFs(path?: string): Promise<{
    current_path: string;
    parent_path: string | null;
    items: Array<{
      name: string;
      path: string;
      is_directory: boolean;
      size_bytes?: number;
      modified_iso?: string;
      is_protected?: boolean;
      protection_reason?: string;
      badge?: string;
      is_quick_pick?: boolean;
    }>;
    total_items?: number;
  }> {
    const url = path ? `${API_BASE}/real-fs/browse?path=${encodeURIComponent(path)}` : `${API_BASE}/real-fs/browse`;
    const res = await fetch(url);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to browse filesystem');
    }
    return res.json();
  },

  async createRealFsTestFiles(): Promise<{
    success: boolean;
    message: string;
    directory: string;
    files: Array<{ filename: string; path: string; size_bytes: number }>;
  }> {
    const res = await fetch(`${API_BASE}/real-fs/create-test-files`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to create test files');
    }
    return res.json();
  },

  async deleteRealFile(data: {
    filepath: string;
    method?: string;
    confirmation: string;
  }): Promise<{
    success: boolean;
    is_verified: boolean;
    accessible_after_deletion: boolean;
    target_path: string;
    method: string;
    details: string;
    limitations: string[];
  }> {
    const res = await fetch(`${API_BASE}/real-fs/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to securely delete file');
    }
    return res.json();
  },

  async reconstructFragments(data: {
    image_path: string;
    file_type?: string;
    output_directory?: string;
    case_id?: string;
  }): Promise<{
    success: boolean;
    image_path: string;
    file_type: string;
    total_fragments_discovered: number;
    headers_found: number;
    reconstructed_count: number;
    segregated_count: number;
    fragments: Array<{
      id: number;
      offset: number;
      length: number;
      start_sector: number;
      role: string;
      entropy: number;
      confidence: number;
      diagnostic_notes: string;
    }>;
    reconstructions: Array<{
      is_reconstructed: boolean;
      is_partial: boolean;
      file_type: string;
      total_size: number;
      confidence_score: number;
      sha256: string;
      uncertainty_reason: string;
      fragment_offsets: number[];
    }>;
  }> {
    const res = await fetch(`${API_BASE}/reconstruct`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Fragment reconstruction failed');
    }
    return res.json();
  },

  async getAuditLogs(case_dir?: string): Promise<{
    log_path: string | null;
    total_entries: number;
    chain_verified: boolean;
    entries: AuditLogEntry[];
  }> {
    const url = case_dir ? `${API_BASE}/audit/logs?case_dir=${encodeURIComponent(case_dir)}` : `${API_BASE}/audit/logs`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch audit journal');
    return res.json();
  },

  async login(data: { username: string; password: string; remember?: boolean }): Promise<{
    success: boolean;
    token: string;
    user: { username: string; role: string };
  }> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Invalid username or password.');
    }
    return res.json();
  },

  async verifyPassword(data: {
    username: string;
    password: string;
    action?: string;
    target?: string;
  }): Promise<{ verified: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/auth/verify-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Password verification failed.');
    }
    return res.json();
  },

  async logout(username?: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username || 'Ruben' }),
    });
    if (!res.ok) {
      throw new Error('Failed to sign out');
    }
    return res.json();
  },
};

