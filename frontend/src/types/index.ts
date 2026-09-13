export interface BackendStatus {
  status: string;
  application: string;
  engine_version: string;
  backend: string;
  tests_total: number;
  tests_passed: number;
  tests_failed: number;
  cli_available: boolean;
  tests_available: boolean;
  platform: string;
  timestamp: string;
}

export interface StorageDevice {
  target_path: string;
  media_type?: string;
  size_str?: string;
  is_safe: boolean;
}

export interface DiskImage {
  name: string;
  path: string;
  size_bytes: number;
  size_mb: number;
  format: string;
  is_safe: boolean;
}

export interface CaseMetadata {
  case_id: string;
  case_name: string;
  investigator_name: string;
  agency: string;
  description?: string;
  status?: string;
  created_timestamp_iso?: string;
  workspace_path: string;
  evidence_count?: number;
}

export interface EvidenceItem {
  evidence_id: string;
  filename: string;
  filepath: string;
  size_bytes: number;
  sha256_hash: string;
  md5_hash?: string;
  acquired_timestamp_iso: string;
  source_device: string;
  notes: string;
}

export interface CarvedFile {
  id: number;
  filename?: string;
  file_name?: string;
  sha256?: string;
  file_type: string;
  extension: string;
  offset_hex: string;
  offset_dec: number;
  size_bytes: number;
  confidence_score: number;
  confidence_level: 'Very High' | 'High' | 'Medium' | 'Low' | 'Very Low' | string;
  is_valid: boolean;
  recovered_path: string;
  status: 'Successfully Recovered' | 'Partially Recovered' | 'Corrupted' | 'Unvalidated' | 'Not Recoverable' | string;
  reasons?: string[];
  warnings?: string[];
  errors?: string[];
}

export interface DeletedFileItem {
  id: number;
  filename: string;
  file_type: string;
  extension: string;
  source_image: string;
  source_path: string;
  offset_hex: string;
  offset_dec: number;
  size_bytes: number;
  status: string;
  deletion_flag: string;
  confidence_score: number;
  can_recover: boolean;
}

export interface FilesOverviewMetrics {
  total_deleted: number;
  total_recovered: number;
  recovery_success_rate: number;
  total_recovered_bytes: number;
  images_scanned: number;
}

export interface FilesOverviewResponse {
  deleted_files: DeletedFileItem[];
  recovered_files: CarvedFile[];
  metrics: FilesOverviewMetrics;
}

export interface CarveJob {
  job_id: string;
  status: 'STARTED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  progress: number;
  stage: string;
  discovered_files: CarvedFile[];
  files_carved: number;
  valid_files: number;
  partial_files?: number;
  output?: string;
  error?: string;
}

export interface ErasePreview {
  target: string;
  exists?: boolean;
  is_protected?: boolean;
  file_count?: number;
  total_size_bytes?: number;
  safety_passed: boolean;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  warnings: string[];
  limitations: string[];
  raw_output: string;
}

export interface ForensicReportItem {
  report_id?: string;
  case_id?: string;
  case_name?: string;
  title?: string;
  filename: string;
  filepath: string;
  format: string;
  size_bytes: number;
  created_iso: string;
  generated_at?: string;
  recovered_count?: number;
  status?: string;
  sha256?: string;
}

export interface AuditLogEntry {
  entry_id: number;
  timestamp: string;
  case_id?: string;
  evidence_id?: string;
  operation_id?: string;
  operator_name?: string;
  tool_version?: string;
  operation_type: string;
  source_identifier?: string;
  source_sha256?: string;
  method?: string;
  status: string;
  details?: string;
  verification_results?: string;
  previous_hash?: string;
  entry_hash?: string;
}

export type NavigationTab = 
  | 'dashboard'
  | 'evidence'
  | 'recovery'
  | 'carving'
  | 'file_eraser'
  | 'drive_sanitization'
  | 'reports'
  | 'audit_logs'
  | 'diagnostics'
  | 'settings';

export interface ImageFileEntry {
  filename: string;
  full_path: string;
  size_bytes: number;
  file_type: string;
  status: 'ACTIVE' | 'DELETED';
  is_directory: boolean;
  starting_cluster: number;
  byte_offset: number;
  created_time?: string;
  modified_time?: string;
}

export interface ImageInspectResponse {
  success: boolean;
  image_name: string;
  image_path: string;
  size_bytes: number;
  fs_type: string;
  can_modify: boolean;
  message?: string;
  error?: string;
  files: ImageFileEntry[];
}

export interface ImageFileDeleteResponse {
  success: boolean;
  operation_type: 'NORMAL_DELETE' | 'SECURE_WIPE';
  message: string;
  image_path: string;
  image_filename: string;
  image_size_bytes: number;
  detected_filesystem: string;
  file_path: string;
  filename: string;
  file_size: number;
  clusters_freed: number;
  pre_hash: string;
  post_hash: string;
  hash_changed: boolean;
  backup_created: boolean;
  backup_path?: string | null;
  verified_deleted: boolean;
  verification_result: string;
  start_time: string;
  end_time: string;
  error?: string;
}

export interface PartitionItem {
  partition_number: number;
  start_sector: number;
  sector_count: number;
  size_bytes: number;
  size_formatted: string;
  partition_type_id: number;
  type_name: string;
  type_guid: string;
  partition_name: string;
  is_bootable: boolean;
}

export interface PartitionTableResponse {
  table_type: string;
  total_disk_sectors: number;
  sector_size: number;
  total_bytes: number;
  partitions: PartitionItem[];
}

export interface FilesystemDetectResponse {
  success: boolean;
  is_detected: boolean;
  fs_type: string;
  detection_status: string;
  sector_size: number;
  cluster_size: number;
  sectors_per_cluster: number;
  partition_start_sector: number;
  partition_start_bytes: number;
  partition_size_bytes: number;
  partition_size_formatted: string;
  volume_label: string;
  serial_number?: number;
  total_clusters?: number;
  message: string;
}

export interface FsRecoveryFile {
  id: number;
  filename: string;
  original_path: string;
  file_type: string;
  extension: string;
  size_bytes: number;
  offset_hex: string;
  offset_dec: number;
  starting_cluster: number;
  mft_record: number;
  fragment_count: number;
  created_time?: string;
  modified_time?: string;
  method: string;
  recovery_status: 'Recovered' | 'Not Recoverable' | 'Partial / Corrupt' | string;
  is_recoverable: boolean;
  unrecoverable_reason?: string;
  confidence_score: number;
  confidence_level: string;
  sha256: string;
  recovered_file_path: string;
}

export interface FsRecoveryResponse {
  success: boolean;
  fs_type: string;
  case_id: string;
  evidence_pre_hash: string;
  evidence_post_hash: string;
  evidence_unmodified: boolean;
  deleted_entries_found: number;
  active_entries_found: number;
  recoverable_count: number;
  partial_count: number;
  not_recoverable_count: number;
  output_directory: string;
  files: FsRecoveryFile[];
  error?: string;
  message?: string;
}

export interface DevicePartitionInfo {
  partition_number: number;
  start_offset: number;
  size_bytes: number;
  size_formatted: string;
  drive_letter: string;
  filesystem: string;
  is_boot: boolean;
  is_system: boolean;
}

export interface PhysicalDiskInfo {
  disk_index: number;
  device_id: string;
  friendly_name: string;
  bus_type: string;
  media_type: string;
  size_bytes: number;
  size_formatted: string;
  partition_style: string;
  is_read_only: boolean;
  partitions: DevicePartitionInfo[];
}

export interface MountedVolumeInfo {
  drive_letter: string;
  volume_name: string;
  filesystem: string;
  drive_type: string;
  total_bytes: number;
  total_formatted: string;
  free_bytes: number;
  free_formatted: string;
  is_removable: boolean;
  is_read_only: boolean;
  is_system: boolean;
}

export interface StorageSourcesResponse {
  success: boolean;
  physical_disks: PhysicalDiskInfo[];
  mounted_volumes: MountedVolumeInfo[];
  disk_images: DiskImage[];
  total_sources: number;
  detection_source: string;
}


