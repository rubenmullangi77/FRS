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
  validation_state?: 'VALID' | 'PARTIAL' | 'INVALID' | string;
  recovery_method?: string;
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
  recovery_success_rate: number | null;
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
  id?: number;
  event_id?: string;
  timestamp: string;
  case_id?: string;
  evidence_id?: string;
  operation_id?: string;
  operator_name?: string;
  user?: string;
  tool_version?: string;
  event_type?: string;
  operation_type: string;
  action?: string;
  severity?: 'INFO' | 'WARNING' | 'ERROR' | string;
  source_identifier?: string;
  source_type?: string;
  source_sha256?: string;
  method?: string;
  status: string;
  message?: string;
  details?: string;
  details_parsed?: Record<string, any>;
  verification_results?: string;
  previous_hash?: string;
  entry_hash?: string;
  prev_hash?: string;
  record_hash?: string;
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
  is_boot?: boolean;
  drive_letter?: string;
  filesystem?: string;
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
  bytes_per_sector?: number;
  cluster_size: number;
  sectors_per_cluster: number;
  partition_start_sector: number;
  partition_start_bytes: number;
  partition_size_bytes: number;
  partition_size_formatted: string;
  volume_label: string;
  serial_number?: number | string;
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
  recovery_status: 'RECOVERABLE' | 'PARTIALLY_RECOVERABLE' | 'NOT_RECOVERABLE' | 'Recovered' | 'Not Recoverable' | 'Partial / Corrupt' | string;
  qualitative_state?: string;
  bounds_valid?: boolean;
  cluster_run_integrity?: string;
  is_recoverable: boolean;
  unrecoverable_reason?: string;
  confidence_score: number;
  confidence_level: string;
  sha256: string;
  recovered_file_path: string;
}

export interface RecoveryReportMeta {
  report_id: string;
  filename: string;
  file_path: string;
  sha256: string;
  generated_at: string;
  total_recovered: number;
  total_failed: number;
  total_bytes: number;
  total_bytes_formatted?: string;
}

export interface FsRecoveryResponse {
  success: boolean;
  fs_type: string;
  case_id: string;
  recovery_op_id?: string;
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
  report_generated?: boolean;
  report_error?: string | null;
  recovery_report?: RecoveryReportMeta | null;
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
  disk_number?: number;
  disk_index?: number;
  device_id?: string;
  device_path?: string;
  friendly_name: string;
  bus_type: string;
  manufacturer?: string;
  serial_number?: string;
  media_type?: string;
  size_bytes?: number;
  total_size_bytes?: number;
  size_formatted?: string;
  total_size_formatted?: string;
  partition_style: string;
  is_removable?: boolean;
  is_read_only?: boolean;
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

export interface PortableDeviceItem {
  object_id: string;
  parent_object_id?: string;
  name: string;
  path: string;
  is_folder: boolean;
  size_bytes: number;
  modified_iso: string;
  content_type: string;
  can_delete: boolean;
}

export interface PortableDevice {
  device_id: string;
  name: string;
  manufacturer: string;
  description: string;
  protocol: string;
  connection_type: string;
  status: string;
  is_portable: boolean;
  storage_names: string[];
}

export interface PortableBrowseResponse {
  device_id: string;
  object_id: string;
  current_object_id?: string;
  parent_object_id?: string;
  current_folder_name?: string;
  current_path?: string;
  items: PortableDeviceItem[];
  error?: string;
  opened?: boolean;
}

export interface SanitizationDriveItem {
  id: string;
  device_type: 'PHYSICAL_DISK' | 'MOUNTED_VOLUME';
  name: string;
  device_path: string;
  disk_number?: number;
  drive_letter?: string;
  filesystem?: string;
  media_type: string;
  bus_type: string;
  is_removable: boolean;
  is_system_protected: boolean;
  can_sanitize: boolean;
  sanitization_status: 'READY' | 'LOCKED';
  reason: string;
  capacity_bytes: number;
  capacity_str: string;
  free_bytes?: number;
  free_str?: string;
  used_bytes?: number;
  used_str?: string;
  partitions_count?: number;
  partitions?: any[];
}

export type RecoverySourceType =
  | 'PHYSICAL_DISK'
  | 'PARTITION'
  | 'MOUNTED_VOLUME'
  | 'USB_MASS_STORAGE'
  | 'FORENSIC_IMAGE'
  | 'MTP_DEVICE'
  | 'WPD_DEVICE'
  | 'UNKNOWN_DEVICE';

export interface PrivilegeStatusResponse {
  is_elevated: boolean;
  privilege_status: 'ELEVATED' | 'NOT_ELEVATED' | 'UNKNOWN';
  elevation_level: 'Administrator' | 'Standard User' | string;
  elevation_display?: string;
  username?: string;
  can_read_physical_disks: boolean;
  can_read_volumes_raw: boolean;
  can_read_forensic_images: boolean;
  can_access_mtp: boolean;
  message: string;
}

export interface TestRawAccessResponse {
  success: boolean;
  target_path: string;
  handle_opened: boolean;
  bytes_read: number;
  error_code: number;
  error_message: string | null;
  is_elevated: boolean;
  elevation_status: string;
  first_bytes_hex?: string;
}

export interface CanonicalSource {
  source_type: RecoverySourceType;
  source_id: string;
  device_id?: string;
  display_name: string;
  device_path: string;
  physical_disk_number?: number | null;
  partition_number?: number | null;
  protocol: string;
  manufacturer: string;
  model: string;
  serial_number?: string;
  capacity: number;
  capacity_bytes?: number;
  capacity_formatted?: string;
  bus_type?: string;
  drive_letter?: string | null;
  volume_label?: string | null;
  volume_guid?: string | null;
  filesystem: string;
  connection_type: string;
  removable?: boolean;
  is_removable?: boolean;
  access_mode?: string;
  read_only?: boolean;
  mounted?: boolean;
  detection_status?: string;
  device_detected?: boolean;
  filesystem_detected?: boolean;
  raw_access?: boolean;
  raw_access_status?: 'AVAILABLE' | 'DENIED' | 'NOT_SUPPORTED' | string;
  raw_access_error?: string | null;
  operation_mode?: string;
  requires_elevation?: boolean;
  capabilities: {
    can_browse_live: boolean;
    can_copy_files: boolean;
    can_raw_carve: boolean;
    can_carve?: boolean;
    can_read_files?: boolean;
    can_read_raw?: boolean;
    requires_elevation?: boolean;
    can_parse_filesystem: boolean;
    can_recover_deleted: boolean;
    can_inspect_partitions?: boolean;
    can_write?: boolean;
    requires_admin?: boolean;
    admin_privilege_held?: boolean;
    permission_warning?: string | null;
  };
}

