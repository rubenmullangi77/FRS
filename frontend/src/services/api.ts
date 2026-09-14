import {
  BackendStatus,
  StorageDevice,
  DiskImage,
  CaseMetadata,
  EvidenceItem,
  CarveJob,
  CarvedFile,
  ErasePreview,
  ForensicReportItem,
  AuditLogEntry,
  FilesOverviewResponse,
  ImageInspectResponse,
  ImageFileDeleteResponse,
  PartitionTableResponse,
  FilesystemDetectResponse,
  FsRecoveryResponse,
  FsRecoveryFile,
  StorageSourcesResponse,
  PortableDevice,
  PortableBrowseResponse,
  SanitizationDriveItem,
  CanonicalSource,
  PrivilegeStatusResponse
} from '../types';

const isElectronFile = typeof window !== 'undefined' && (window.location.protocol === 'file:' || !!(window as any).forensiVaultDesktop);
const API_BASE = isElectronFile ? 'http://127.0.0.1:8766/api' : '/api';

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
    case_id?: string;
    workspace_path?: string;
    source_image?: string;
    source_path?: string;
    evidence_id?: string;
    name?: string;
    notes?: string;
  }): Promise<{ success: boolean; evidence?: EvidenceItem; [key: string]: any }> {
    const src = data.source_path || data.source_image || '';
    const payload = {
      case_id: data.case_id || 'CASE-2026-001',
      evidence_id: data.evidence_id || `EVD-${Date.now().toString(36).toUpperCase()}`,
      source_path: src,
      name: data.name || (src.split(/[\\/]/).pop() || 'evidence.img'),
      notes: data.notes || 'Imported for forensic analysis'
    };
    const res = await fetch(`${API_BASE}/evidence/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to import evidence');
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

  async startCarving(
    image_path: string,
    output_dir?: string
  ): Promise<{
    job_id: string;
    status: string;
    files_carved?: number;
    discovered_files?: CarvedFile[];
    carved_files?: CarvedFile[];
    files?: CarvedFile[];
  }> {
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

  async getFilesOverview(caseId?: string): Promise<FilesOverviewResponse> {
    const url = caseId ? `${API_BASE}/files/overview?case_id=${encodeURIComponent(caseId)}` : `${API_BASE}/files/overview`;
    const res = await fetch(url);
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

  async listReports(case_id?: string): Promise<{ reports: ForensicReportItem[] }> {
    const url = case_id ? `${API_BASE}/reports?case_id=${encodeURIComponent(case_id)}` : `${API_BASE}/reports`;
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
        case_id: data.case_id,
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
      throw new Error(err.detail || err.error || err.message || 'Failed to compile forensic report');
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

  async getRecoveryPartitions(image_path: string, source_id?: string, source_type?: string): Promise<PartitionTableResponse> {
    const res = await fetch(`${API_BASE}/recovery/partitions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image_path, source_id, source_type }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to detect partition table');
    }
    return res.json();
  },

  async detectRecoveryFilesystem(image_path: string, start_sector: number = 0, source_id?: string, source_type?: string): Promise<FilesystemDetectResponse> {
    const res = await fetch(`${API_BASE}/recovery/detect-fs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image_path, start_sector, source_id, source_type }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to probe filesystem');
    }
    return res.json();
  },

  async scanRecoveryDeleted(data: {
    image_path: string;
    start_sector?: number;
    case_id?: string;
    source_id?: string;
    source_type?: string;
  }): Promise<FsRecoveryResponse> {
    const res = await fetch(`${API_BASE}/recovery/scan-deleted`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to scan deleted file metadata');
    }
    return res.json();
  },

  async extractRecoveryFiles(data: {
    image_path: string;
    start_sector?: number;
    case_id?: string;
    file_ids?: number[];
    output_directory?: string;
    mode?: 'filesystem' | 'carving';
    source_id?: string;
    source_type?: string;
  }): Promise<FsRecoveryResponse> {
    const res = await fetch(`${API_BASE}/recovery/extract`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to extract recovered files');
    }
    return res.json();
  },

  async openRecoveryFolder(folder_path: string): Promise<{ success: boolean; message: string; folder_path: string }> {
    const res = await fetch(`${API_BASE}/recovery/open-folder`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ folder_path }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to open recovery directory');
    }
    return res.json();
  },

  async scanRecoveryUnallocated(data: {
    image_path: string;
    case_id?: string;
    output_directory?: string;
    source_id?: string;
    source_type?: string;
  }): Promise<{
    success: boolean;
    method: string;
    case_id: string;
    image_path: string;
    total_carved: number;
    files: FsRecoveryFile[];
  }> {
    const res = await fetch(`${API_BASE}/recovery/scan-unallocated`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to carve unallocated space');
    }
    return res.json();
  },

  async getRecoveryFilePreview(data: {
    file_path?: string;
    case_id?: string;
    file_id?: number;
    max_bytes?: number;
  }): Promise<{
    success: boolean;
    file_path: string;
    filename: string;
    size_bytes: number;
    size_formatted: string;
    extension: string;
    sha256: string;
    preview_type: 'image' | 'text' | 'pdf' | 'archive' | 'hex';
    preview_data: string;
    extra_meta: Record<string, any>;
  }> {
    const res = await fetch(`${API_BASE}/recovery/file-preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to retrieve recovered file preview');
    }
    return res.json();
  },

  async getStorageSources(): Promise<StorageSourcesResponse> {
    const res = await fetch(`${API_BASE}/recovery/storage-sources`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to fetch storage sources');
    }
    return res.json();
  },

  async getPortableDevices(): Promise<{ timestamp: string; devices: PortableDevice[] }> {
    const res = await fetch(`${API_BASE}/devices/portable`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to detect portable devices');
    }
    return res.json();
  },

  async browsePortableDevice(data: { device_id: string; object_id?: string }): Promise<PortableBrowseResponse> {
    const res = await fetch(`${API_BASE}/devices/portable/browse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to browse portable device');
    }
    return res.json();
  },

  async deletePortableDeviceFile(data: {
    device_id: string;
    object_id: string;
    parent_object_id?: string;
    name?: string;
    confirmation: string;
    password?: string;
  }): Promise<{
    success: boolean;
    status?: string;
    is_verified?: boolean;
    verification_status?: string;
    accessible_after_deletion?: boolean;
    device_id?: string;
    object_id?: string;
    parent_object_id?: string;
    protocol?: string;
    message?: string;
    error?: string;
  }> {
    const res = await fetch(`${API_BASE}/devices/portable/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || err.message || 'Failed to delete file on portable device');
    }
    return res.json();
  },

  async getSanitizationDrives(): Promise<{ timestamp: string; drives: SanitizationDriveItem[] }> {
    const res = await fetch(`${API_BASE}/sanitization/drives`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to fetch sanitization drives');
    }
    return res.json();
  },

  async copyPortableFiles(data: {
    device_id: string;
    object_ids: string[];
    case_id?: string;
    destination_dir?: string;
  }): Promise<{
    success: boolean;
    exported_count: number;
    total_requested: number;
    destination_directory: string;
    results: any[];
  }> {
    const res = await fetch(`${API_BASE}/devices/portable/copy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to export files from portable device');
    }
    return res.json();
  },

  async auditMtpInspection(data: {
    device_id: string;
    device_name: string;
    manufacturer?: string;
    case_id?: string;
    examiner_name?: string;
  }): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/recovery/audit-mtp-inspection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return res.json();
  },

  async getCanonicalSources(): Promise<{ timestamp: string; total_sources: number; sources: CanonicalSource[] }> {
    const res = await fetch(`${API_BASE}/recovery/canonical-sources`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to fetch canonical sources');
    }
    return res.json();
  },

  async getSystemPrivileges(): Promise<PrivilegeStatusResponse> {
    const res = await fetch(`${API_BASE}/system/privileges`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to fetch privilege status');
    }
    return res.json();
  },

  async relaunchElevated(options?: string | { targetSource?: string; caseId?: string; currentRoute?: string }): Promise<{ success: boolean; status?: string; message: string; cancelled?: boolean }> {
    const payload = typeof options === 'string'
      ? { targetSource: options }
      : (options || {});

    // If desktop electron bridge is available, use native desktop elevation with handshake
    const desktop = (window as any).forensiVaultDesktop;
    if (desktop && typeof desktop.relaunchElevated === 'function') {
      try {
        const desktopRes = await desktop.relaunchElevated(payload);
        if (desktopRes) return desktopRes;
      } catch (err: any) {
        console.warn('Desktop elevation bridge failed:', err);
      }
    }

    const res = await fetch(`${API_BASE}/system/relaunch-elevated`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_source: payload.targetSource || null })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error || 'Failed to request administrator elevation');
    }
    return res.json();
  },

  async getElevationState(): Promise<{ targetSource?: string; target_source?: string; caseId?: string; case_id?: string; currentRoute?: string; route?: string } | null> {
    const desktop = (window as any).forensiVaultDesktop;
    if (desktop && typeof desktop.getElevationState === 'function') {
      try {
        return await desktop.getElevationState();
      } catch (_) {}
    }
    return null;
  },

  async testRawAccess(targetPath: string, caseId?: string): Promise<{
    success: boolean;
    target_path: string;
    handle_opened: boolean;
    bytes_read: number;
    error_code: number;
    error_message: string | null;
    is_elevated: boolean;
    elevation_status: string;
    first_bytes_hex?: string;
  }> {
    const res = await fetch(`${API_BASE}/recovery/test-raw-access`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_path: targetPath, case_id: caseId || null })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || err.error_message || err.error || 'Raw access test failed');
    }
    return res.json();
  }
};




